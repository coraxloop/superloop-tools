//! Declarative positive rules and separately published negative rules.
use super::*;

/// A literal reviewed command/sequence with explicit program, PATH, env and path operands.
/// No denial field exists in this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickRule {
    pub id: String,
    pub execution: Execution,
    pub path: String,
    pub programs: Vec<String>,
    pub env_additions: Vec<(String, String)>,
    /// (step, word) slots whose lexical destination must stay in W.
    pub workspace_operands: Vec<(usize, usize)>,
}
/// Published positive table; its digest is held in the grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickPolicy {
    pub revision: String,
    pub rules: Vec<QuickRule>,
}
/// Only this published entry can supply the evidence inside a Deny.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlacklistEntry {
    pub id: String,
    /// Published owner rule versus requester-controlled execution bytes; full binding.
    pub execution_digest: String,
    pub reason: String,
}
/// Published negative table; an empty table blocks no command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blacklist {
    pub revision: String,
    pub entries: Vec<BlacklistEntry>,
}
/// Non-forgeable denial evidence: fields and construction are private to the blacklist matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlacklistDenial {
    blacklist_rule: String,
    revision: String,
    reason: String,
}
impl BlacklistDenial {
    /// Exact published rule, revision and reason; no implicit negative policy.
    #[must_use]
    pub fn evidence(&self) -> Value {
        json!({"blacklist_rule":self.blacklist_rule,"revision":self.revision,"reason":self.reason})
    }
}
/// Allow evidence can be constructed only by the positive-table matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickAllowance {
    rule: String,
    revision: String,
    bindings: Value,
    context_key: Value,
}
impl QuickAllowance {
    /// Matched rule and exact bindings, for later judgement and record adapters.
    #[must_use]
    pub fn evidence(&self) -> Value {
        json!({"rule":self.rule,"revision":self.revision,"bindings":self.bindings})
    }
}
/// Neither caller nor quick table can manufacture the other's policy evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    QuickAllow(QuickAllowance),
    Miss { reasons: Vec<String> },
    Deny(BlacklistDenial),
}
fn miss(reason: &str) -> Classification {
    Classification::Miss {
        reasons: vec![reason.into()],
    }
}
fn inside(grant: &Grant, envelope: &Envelope, operand: &[u8]) -> bool {
    let Ok(operand) = std::str::from_utf8(operand) else {
        return false;
    };
    let resolved = if operand.starts_with('/') {
        operand.to_owned()
    } else {
        let mut path = grant.workspace.trim_end_matches('/').to_owned();
        for c in &envelope.cwd {
            path.push('/');
            path.push_str(c);
        }
        path.push('/');
        path.push_str(operand);
        path
    };
    absolute(&resolved)
        && (grant.workspace == "/"
            || resolved == grant.workspace
            || resolved
                .strip_prefix(&grant.workspace)
                .is_some_and(|s| s.starts_with('/')))
}
fn programs_bound(rule: &QuickRule, grant: &Grant, steps: &[&[Vec<u8>]]) -> bool {
    let path = rule
        .env_additions
        .iter()
        .chain(&grant.baseline_env)
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v);
    if path != Some(&rule.path) || rule.programs.len() != steps.len() {
        return false;
    }
    steps.iter().zip(&rule.programs).all(|(words, program)| {
        let Ok(word) = std::str::from_utf8(&words[0]) else {
            return false;
        };
        absolute(program)
            && if word.contains('/') {
                word == program
            } else {
                // Pure contract: bind a declared PATH candidate, not a filesystem lookup.
                absolute(&rule.path)
                    && !rule.path.contains(':')
                    && format!("{}/{word}", rule.path.trim_end_matches('/')) == *program
            }
    })
}

fn validate_tables(
    grant: &Grant,
    policy: &QuickPolicy,
    blacklist: &Blacklist,
) -> Result<(), Refusal> {
    if canonical_digest(policy)? != grant.quick_policy_digest
        || canonical_digest(blacklist)? != grant.blacklist_digest
    {
        return Err(context("published policy digest differs"));
    }
    if !text(&policy.revision)
        || !text(&blacklist.revision)
        || policy.rules.len() > 256
        || blacklist.entries.len() > 256
        || policy
            .rules
            .iter()
            .map(|r| &r.id)
            .collect::<BTreeSet<_>>()
            .len()
            != policy.rules.len()
        || blacklist
            .entries
            .iter()
            .map(|r| &r.id)
            .collect::<BTreeSet<_>>()
            .len()
            != blacklist.entries.len()
        || policy.rules.iter().any(|r| {
            !text(&r.id)
                || r.execution.validate().is_err()
                || !environment(&r.env_additions)
                || r.path.contains('\0')
                || !r.programs.iter().all(|p| absolute(p))
        })
        || blacklist
            .entries
            .iter()
            .any(|r| !text(&r.id) || !text(&r.reason) || !digest(&r.execution_digest))
    {
        return Err(protocol("policy identity differs"));
    }
    Ok(())
}

/// Classify only after validating the envelope, grant and both published table digests.
/// # Errors
/// Identity/protocol/context failures stay named refusals, not blacklist decisions.
pub fn classify(
    envelope: &Envelope,
    grant: &Grant,
    policy: &QuickPolicy,
    blacklist: &Blacklist,
) -> Result<Classification, Refusal> {
    admit(
        envelope,
        Some(grant),
        &grant.loop_name,
        &grant.run,
        &grant.node,
    )?;
    validate_tables(grant, policy, blacklist)?;
    let execution_digest = canonical_digest(&envelope.execution)?;
    if let Some(entry) = blacklist
        .entries
        .iter()
        .find(|e| e.execution_digest == execution_digest)
    {
        return Ok(Classification::Deny(BlacklistDenial {
            blacklist_rule: entry.id.clone(),
            revision: blacklist.revision.clone(),
            reason: entry.reason.clone(),
        }));
    }
    if envelope
        .env_additions
        .iter()
        .map(|(k, _)| k)
        .collect::<BTreeSet<_>>()
        .len()
        != envelope.env_additions.len()
        || grant
            .baseline_env
            .iter()
            .map(|(k, _)| k)
            .collect::<BTreeSet<_>>()
            .len()
            != grant.baseline_env.len()
    {
        return Ok(miss("repeated environment names require judgement"));
    }
    let Some(steps) = envelope.execution.steps() else {
        if let Execution::Shell { shell, .. } = &envelope.execution
            && !grant.shells.contains(shell)
        {
            return Ok(miss(
                "undeclared shell; syntax analysis is not authoritative",
            ));
        }
        return Ok(miss("shell text never matches a quick rule"));
    };
    for rule in policy
        .rules
        .iter()
        .filter(|r| r.execution == envelope.execution)
    {
        if !programs_bound(rule, grant, &steps) {
            continue;
        }
        if rule.env_additions != envelope.env_additions {
            continue;
        }
        if !rule.workspace_operands.iter().all(|(step, word)| {
            steps
                .get(*step)
                .and_then(|s| s.get(*word))
                .is_some_and(|p| inside(grant, envelope, p))
        }) {
            return Ok(miss(
                "known operand is outside W or cannot be resolved lexically",
            ));
        }
        return Ok(Classification::QuickAllow(QuickAllowance {
            context_key: learned_key("compute", envelope, grant, &policy.revision)?,
            rule: rule.id.clone(),
            revision: policy.revision.clone(),
            bindings: json!({"workspace":grant.workspace,"cwd":envelope.cwd,"PATH":rule.path,"programs":rule.programs,"env_additions":envelope.env_additions,"workspace_operands":rule.workspace_operands}),
        }));
    }
    Ok(miss(
        "no exact quick rule binds execution, program resolution and every environment addition",
    ))
}

/// Exact new-context learning identity. Legacy compute shapes inhabit another operation.
/// # Errors
/// Refuses an invalid or stale envelope/grant pair.
pub fn learned_key(
    class: &str,
    envelope: &Envelope,
    grant: &Grant,
    policy_revision: &str,
) -> Result<Value, Refusal> {
    admit(
        envelope,
        Some(grant),
        &grant.loop_name,
        &grant.run,
        &grant.node,
    )?;
    let shape = canonical_digest(
        &json!({"grant":grant,"policy_revision":policy_revision,"cwd":envelope.cwd,"execution":envelope.execution,"env":envelope.env_additions}),
    )?;
    Ok(json!([class, "compute-workspace", shape]))
}
/// The timing and effect of a classified workspace request under its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Immediate,
    ImmediateJudgeAlongside,
    ImmediateRecordRefusal,
    WaitForJudgement,
    Block,
}
/// A decision read from authenticated learned custody, with its exact context key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearnedDecision<'a> {
    Allow(&'a Value),
    Refuse(&'a Value),
}
/// Decide timing from the admitted request context, never a caller-supplied expected key.
///
/// A learned key must come from authenticated decision custody; this function binds
/// that evidence to this request but cannot establish its external provenance.
/// # Errors
/// Refuses invalid context or positive evidence replayed for another request.
pub fn disposition(
    mode: crate::policy::DoorMode,
    classification: &Classification,
    envelope: &Envelope,
    grant: &Grant,
    policy_revision: &str,
    learned_decision: Option<LearnedDecision<'_>>,
) -> Result<Disposition, Refusal> {
    let expected_key = learned_key("compute", envelope, grant, policy_revision)?;
    if matches!(classification, Classification::Deny(_)) {
        return Ok(Disposition::Block);
    }
    let quick = if let Classification::QuickAllow(allow) = classification {
        if allow.context_key != expected_key {
            return Err(context(
                "quick allowance belongs to another workspace context",
            ));
        }
        true
    } else {
        false
    };
    let learned = match learned_decision {
        Some(LearnedDecision::Allow(key)) if key == &expected_key => Some(true),
        Some(LearnedDecision::Refuse(key)) if key == &expected_key => Some(false),
        _ => None,
    };
    Ok(match mode {
        crate::policy::DoorMode::Audit => Disposition::WaitForJudgement,
        crate::policy::DoorMode::Allow => match learned {
            Some(false) => Disposition::ImmediateRecordRefusal,
            _ if quick || learned == Some(true) => Disposition::Immediate,
            _ => Disposition::ImmediateJudgeAlongside,
        },
        crate::policy::DoorMode::Enforce => match learned {
            Some(false) => Disposition::Block,
            _ if quick || learned == Some(true) => Disposition::Immediate,
            _ => Disposition::WaitForJudgement,
        },
    })
}
