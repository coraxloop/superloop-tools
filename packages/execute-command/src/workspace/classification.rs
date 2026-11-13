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
/// The quick table cannot manufacture blacklist evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    QuickAllow {
        rule: String,
        revision: String,
        bindings: Value,
    },
    Miss {
        reasons: Vec<String>,
    },
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
        return Ok(Classification::QuickAllow {
            rule: rule.id.clone(),
            revision: policy.revision.clone(),
            bindings: json!({"workspace":grant.workspace,"cwd":envelope.cwd,"PATH":rule.path,"programs":rule.programs,"env_additions":envelope.env_additions,"workspace_operands":rule.workspace_operands}),
        });
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
/// W3's scheduling contract; a miss is synchronous even in allow mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Immediate,
    WaitForJudgement,
    Block,
}
/// Decide timing without executing; learned allows must carry this exact new key.
#[must_use]
pub fn disposition(
    mode: crate::policy::DoorMode,
    classification: &Classification,
    expected_key: &Value,
    learned_allow_key: Option<&Value>,
) -> Disposition {
    if matches!(classification, Classification::Deny(_)) {
        return Disposition::Block;
    }
    let new_key = expected_key.as_array().is_some_and(|k| {
        k.len() == 3 && k[1] == "compute-workspace" && k[2].as_str().is_some_and(digest)
    });
    let learned = new_key && learned_allow_key == Some(expected_key);
    if mode == crate::policy::DoorMode::Allow
        && (matches!(classification, Classification::QuickAllow { .. }) || learned)
    {
        Disposition::Immediate
    } else {
        Disposition::WaitForJudgement
    }
}
