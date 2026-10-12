//! Strict owner-supplied enforce-readiness evidence, bound to reviewed deployment inputs.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::Registry;

/// Inputs independently inspected by the assembler before it accepts an audit window.
pub struct EvidenceContext<'a> {
    /// The deployment record's own UTC assembly time.
    pub assembled_at: &'a str,
    /// Version from the topology verdict's harness provenance.
    pub harness_version: &'a str,
    /// Exact harness bytes from that provenance.
    pub binary_digest: &'a str,
    /// Digest of the complete topology verdict bytes.
    pub topology_digest: &'a str,
    /// Digest of the sorted registry tuples, including state roots.
    pub registry_digest: &'a str,
    /// Exact domain-rubric byte digests keyed by registered loop.
    pub domain_digests: &'a BTreeMap<String, String>,
    /// Validated deployment registry, including main-session corroboration.
    pub registry: &'a Registry,
}

/// A complete schema-1 record whose constraints have all passed.
pub struct AuditEvidence(Value);

impl AuditEvidence {
    /// Validate the private inventory and journal summary without changing any input.
    ///
    /// # Errors
    ///
    /// Returns a named refusal for malformed, incomplete, mismatched, or over-budget evidence.
    pub fn parse(bytes: &[u8], context: &EvidenceContext<'_>) -> Result<Self, String> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("audit evidence JSON: {error}"))?;
        let object = exact_object(
            &value,
            &[
                "schema",
                "window_start",
                "window_end",
                "harness_version",
                "binary_digest",
                "topology_digest",
                "registry_digest",
                "domain_digests",
                "sessions",
                "unknown_count",
                "lost_record_count",
                "sample_count",
                "model_call_share",
                "verdict_wall_ms",
                "invocation_wall_ms",
                "would_be_denials",
                "peer_domain_denial_count",
                "limits",
            ],
            "audit evidence",
        )?;
        if count(object, "schema")? != 1 {
            return Err("audit evidence schema is not 1".to_owned());
        }
        validate_bindings(object, context)?;
        validate_window(object, context)?;
        validate_friction(object, context)?;
        Ok(Self(value))
    }

    /// The validated observations and limits, retained verbatim as JSON values for review.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }
}

fn validate_bindings(
    object: &Map<String, Value>,
    context: &EvidenceContext<'_>,
) -> Result<(), String> {
    if string(object, "harness_version")? != context.harness_version {
        return Err("harness_version mismatch with harness_provenance version".to_owned());
    }
    for (field, expected) in [
        ("binary_digest", context.binary_digest),
        ("topology_digest", context.topology_digest),
        ("registry_digest", context.registry_digest),
    ] {
        let actual = string(object, field)?;
        validate_digest(actual, field)?;
        if actual != expected {
            return Err(format!("{field} mismatch with reviewed input"));
        }
    }
    let domains = field(object, "domain_digests")?
        .as_object()
        .ok_or_else(|| "domain_digests is not an object".to_owned())?;
    for (name, digest) in domains {
        validate_digest(
            digest
                .as_str()
                .ok_or_else(|| format!("domain digest for {name} is not a string"))?,
            name,
        )?;
    }
    if domains.len() != context.domain_digests.len()
        || context.domain_digests.iter().any(|(name, digest)| {
            domains.get(name).and_then(Value::as_str) != Some(digest.as_str())
        })
    {
        return Err("domain inventory mismatch with live loops".to_owned());
    }
    Ok(())
}

fn validate_window(
    object: &Map<String, Value>,
    context: &EvidenceContext<'_>,
) -> Result<(), String> {
    let start = timestamp(string(object, "window_start")?)?;
    let end = timestamp(string(object, "window_end")?)?;
    let assembled = timestamp(context.assembled_at)?;
    if start >= end || end > assembled {
        return Err(
            "incomplete window: require window_start < window_end <= assembled_at".to_owned(),
        );
    }
    if count(object, "unknown_count")? != 0 || count(object, "lost_record_count")? != 0 {
        return Err(
            "incomplete window: unknown_count and lost_record_count must be zero".to_owned(),
        );
    }
    let samples = count(object, "sample_count")?;
    let sessions = array(object, "sessions")?;
    let mut observed = BTreeSet::new();
    let mut inventoried = BTreeSet::new();
    let mut total = 0_u64;
    for session in sessions {
        let session = exact_object(session, &["session", "loop", "role", "count"], "session")?;
        let identifier = string(session, "session")?;
        let loop_name = string(session, "loop")?;
        let role = string(session, "role")?;
        let entry = context
            .registry
            .entries()
            .iter()
            .find(|entry| entry.name() == loop_name)
            .ok_or_else(|| "unknown session: loop is not registered".to_owned())?;
        if identifier.is_empty()
            || !matches!(role, "orchestrator" | "orchestrator-subagent")
            || context
                .registry
                .entries()
                .iter()
                .any(|peer| peer.name() != loop_name && peer.identifier() == Some(identifier))
            || (role == "orchestrator"
                && entry
                    .identifier()
                    .is_some_and(|registered| registered != identifier))
        {
            return Err("unknown session: identity or role disagrees with inventory".to_owned());
        }
        if !inventoried.insert((identifier, loop_name, role)) {
            return Err("incomplete window: duplicate session inventory row".to_owned());
        }
        let observed_count = count(session, "count")?;
        if observed_count == 0 {
            return Err("incomplete window: unobserved session".to_owned());
        }
        total = total
            .checked_add(observed_count)
            .ok_or_else(|| "incomplete window: session count overflow".to_owned())?;
        observed.insert(loop_name);
    }
    if total == 0
        || samples != total
        || context.registry.entries().iter().any(|entry| {
            !observed.contains(entry.name())
                || entry.identifier().is_some_and(|identifier| {
                    !inventoried.contains(&(identifier, entry.name(), "orchestrator"))
                })
        })
    {
        return Err(
            "incomplete window: sample_count or live session/loop coverage mismatch".to_owned(),
        );
    }
    Ok(())
}

fn validate_friction(
    object: &Map<String, Value>,
    context: &EvidenceContext<'_>,
) -> Result<(), String> {
    let limits = exact_object(
        field(object, "limits")?,
        &[
            "verdict_wall_ms",
            "invocation_wall_ms",
            "model_call_share_max",
            "denial_share_max",
        ],
        "limits",
    )?;
    for wall in ["verdict_wall_ms", "invocation_wall_ms"] {
        let actual = exact_object(field(object, wall)?, &["p50", "p95", "p99", "max"], wall)?;
        let maxima = exact_object(field(limits, wall)?, &["p50", "p95", "p99", "max"], wall)?;
        for percentile in ["p50", "p95", "p99", "max"] {
            if number(actual, percentile)? > number(maxima, percentile)? {
                return Err(format!("{wall}.{percentile} exceeds limit"));
            }
        }
    }
    if share(object, "model_call_share")? > share(limits, "model_call_share_max")? {
        return Err("model_call_share exceeds limit".to_owned());
    }
    let denial_max = share(limits, "denial_share_max")?;
    let mut groups = BTreeSet::new();
    for denial in array(object, "would_be_denials")? {
        let denial = exact_object(
            denial,
            &["class", "loop", "scope", "count", "share"],
            "denial",
        )?;
        let class = string(denial, "class")?;
        if !matches!(
            class,
            "agent-error" | "suspicious" | "infrastructure-failure"
        ) {
            return Err("denial class is outside the denial vocabulary".to_owned());
        }
        let scope = string(denial, "scope")?;
        if !matches!(scope, "loop" | "estate") {
            return Err("denial scope is not loop or estate".to_owned());
        }
        let loop_name = string(denial, "loop")?;
        if !context.domain_digests.contains_key(loop_name) {
            return Err("denial loop is not inventoried".to_owned());
        }
        if !groups.insert((class, loop_name, scope)) {
            return Err("duplicate denial class/loop/scope row".to_owned());
        }
        if count(denial, "count")? > count(object, "sample_count")? {
            return Err("denial count exceeds sample_count".to_owned());
        }
        if share(denial, "share")? > denial_max {
            return Err("denial share exceeds limit".to_owned());
        }
    }
    if count(object, "peer_domain_denial_count")? != 0 {
        return Err("peer domain denial count must be zero".to_owned());
    }
    Ok(())
}

fn exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    for key in keys {
        if !object.contains_key(*key) {
            return Err(format!("{label} missing field {key}"));
        }
    }
    if let Some(key) = object.keys().find(|key| !keys.contains(&key.as_str())) {
        return Err(format!("{label} unknown field {key}"));
    }
    Ok(object)
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("missing field {key}"))
}

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    field(object, key)?
        .as_str()
        .ok_or_else(|| format!("{key} is not a string"))
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, String> {
    field(object, key)?
        .as_array()
        .ok_or_else(|| format!("{key} is not an array"))
}

fn count(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    field(object, key)?
        .as_u64()
        .ok_or_else(|| format!("{key} must be a nonnegative integer"))
}

fn number(object: &Map<String, Value>, key: &str) -> Result<f64, String> {
    field(object, key)?
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0)
        .ok_or_else(|| format!("{key} must be a finite nonnegative number"))
}

fn share(object: &Map<String, Value>, key: &str) -> Result<f64, String> {
    let share = number(object, key).map_err(|error| format!("share {error}"))?;
    if share > 1.0 {
        return Err(format!("{key} share must be in [0, 1]"));
    }
    Ok(share)
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} digest must have 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn timestamp(value: &str) -> Result<&str, String> {
    if !valid_recorded_at(value) {
        return Err("timestamp must be a valid UTC YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ".to_owned());
    }
    Ok(value)
}

/// Recognize the canonical UTC representation emitted by schema-2 journal records.
#[must_use]
pub(crate) fn valid_recorded_at(value: &str) -> bool {
    if value.len() != 30 || !value.is_ascii() {
        return false;
    }
    for (position, expected) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (29, b'Z'),
    ] {
        if value.as_bytes().get(position) != Some(&expected) {
            return false;
        }
    }
    let component = |start, end| {
        value
            .get(start..end)
            .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|text| text.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second), Some(_nanos)) = (
        component(0, 4),
        component(5, 7),
        component(8, 10),
        component(11, 13),
        component(14, 16),
        component(17, 19),
        component(20, 29),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    year != 0 && day >= 1 && day <= days && hour < 24 && minute < 60 && second < 60
}
