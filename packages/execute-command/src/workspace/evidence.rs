//! Lossless agent input and schema-seven execution evidence, without an effect writer.
use super::*;
use std::collections::BTreeMap;

const MAX_FLAG_ROWS: usize = 64;

fn flagged(c: char) -> bool {
    c.is_control() || !c.is_ascii()
}
fn readable_word(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}
fn readable_execution(execution: &Execution) -> Value {
    match execution {
        Execution::Argv { words } => {
            json!({"kind":"argv","words":words.iter().map(|word| readable_word(word)).collect::<Vec<_>>()})
        }
        Execution::Sequence { steps } => {
            json!({"kind":"sequence","steps":steps.iter().map(|words| words.iter().map(|word| readable_word(word)).collect::<Vec<_>>()).collect::<Vec<_>>()})
        }
        Execution::Shell { shell, text } => {
            json!({"kind":"shell","shell":shell.escape_debug().to_string(),"text":text.escape_debug().to_string()})
        }
    }
}
/// Agent sees exact byte arrays or exact Unicode shell text, plus flagged code points.
/// # Errors
/// Refuses a malformed or stale context before rendering.
pub fn agent_input(
    envelope: &Envelope,
    grant: &Grant,
    reasons: &[String],
) -> Result<Value, Refusal> {
    admit(
        envelope,
        Some(grant),
        &grant.loop_name,
        &grant.run,
        &grant.node,
    )?;
    let mut code_points = Vec::new();
    for (field, bytes) in all_field_bytes(envelope) {
        let mut points = scan_points(bytes)
            .into_iter()
            .filter(|(point, _)| flagged(*point))
            .collect::<Vec<_>>();
        points.sort_by_key(|(_, (offset, _))| *offset);
        for (point, (first_byte_offset, count)) in points {
            code_points.push(json!({"field":field,"first_byte_offset":first_byte_offset,"code_point":format!("U+{:04X}",u32::from(point)),"count":count}));
        }
    }
    let omitted_count = code_points.len().saturating_sub(MAX_FLAG_ROWS);
    let rows = code_points
        .into_iter()
        .take(MAX_FLAG_ROWS)
        .collect::<Vec<_>>();
    Ok(
        json!({"execution":envelope.execution,"execution_readable_display_only":readable_execution(&envelope.execution),"cwd":envelope.cwd,"env_additions":envelope.env_additions,"grant_summary":grant,"miss_reasons":reasons,"flagged_code_points":{"rows":rows,"omitted_count":omitted_count}}),
    )
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn display_valid(display: &Value, execution: &Execution) -> bool {
    let bounded = |value: &Value| value.as_str().is_some_and(|s| s.len() <= 262_144);
    match execution {
        Execution::Argv { words } => {
            exact_keys(display, &["kind", "words"])
                && display["kind"] == "argv"
                && display["words"]
                    .as_array()
                    .is_some_and(|items| items.len() == words.len() && items.iter().all(bounded))
        }
        Execution::Sequence { steps } => {
            exact_keys(display, &["kind", "steps"])
                && display["kind"] == "sequence"
                && display["steps"].as_array().is_some_and(|items| {
                    items.len() == steps.len()
                        && items.iter().zip(steps).all(|(item, words)| {
                            item.as_array().is_some_and(|shown| {
                                shown.len() == words.len() && shown.iter().all(bounded)
                            })
                        })
                })
        }
        Execution::Shell { .. } => {
            exact_keys(display, &["kind", "shell", "text"])
                && display["kind"] == "shell"
                && bounded(&display["shell"])
                && bounded(&display["text"])
        }
    }
}

fn all_field_bytes(envelope: &Envelope) -> Vec<(String, &[u8])> {
    let mut fields = Vec::new();
    match &envelope.execution {
        Execution::Argv { words } => {
            for (i, word) in words.iter().enumerate() {
                fields.push((format!("execution.words[{i}]"), word.as_slice()));
            }
        }
        Execution::Sequence { steps } => {
            for (step, words) in steps.iter().enumerate() {
                for (i, word) in words.iter().enumerate() {
                    fields.push((format!("execution.steps[{step}][{i}]"), word.as_slice()));
                }
            }
        }
        Execution::Shell { shell, text } => {
            fields.push(("execution.shell".into(), shell.as_bytes()));
            fields.push(("execution.text".into(), text.as_bytes()));
        }
    }
    for (i, component) in envelope.cwd.iter().enumerate() {
        fields.push((format!("cwd[{i}]"), component.as_bytes()));
    }
    for (i, (name, value)) in envelope.env_additions.iter().enumerate() {
        fields.push((format!("env_additions[{i}].name"), name.as_bytes()));
        fields.push((format!("env_additions[{i}].value"), value.as_bytes()));
    }
    fields
}

fn scan_points(bytes: &[u8]) -> BTreeMap<char, (usize, usize)> {
    // Invalid UTF-8 remains in execution as bytes and contributes no code point.
    let mut points = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let (valid, skip) = match std::str::from_utf8(rest) {
            Ok(s) => (s, 0),
            Err(error) => (
                std::str::from_utf8(&rest[..error.valid_up_to()]).unwrap_or_default(),
                error
                    .error_len()
                    .unwrap_or_else(|| rest.len() - error.valid_up_to()),
            ),
        };
        for (i, point) in valid.char_indices() {
            let row = points.entry(point).or_insert((offset + i, 0));
            row.1 += 1;
        }
        offset += valid.len() + skip;
    }
    points
}

const fn floor_point(point: char) -> bool {
    !point.is_ascii() || matches!(point, '\0'..='\u{001f}' | '\u{007f}')
}

/// Check stored judge input without regenerating its display or flag policy.
/// # Errors
/// Refuses a changed exact context, a malformed display, or a flag unsupported by its bytes.
pub fn validate_agent_observation(
    input: &Value,
    envelope: &Envelope,
    grant: &Grant,
) -> Result<(), Refusal> {
    if !exact_keys(
        input,
        &[
            "execution",
            "execution_readable_display_only",
            "cwd",
            "env_additions",
            "grant_summary",
            "miss_reasons",
            "flagged_code_points",
        ],
    ) || input["execution"] != json!(envelope.execution)
        || input["cwd"] != json!(envelope.cwd)
        || input["env_additions"] != json!(envelope.env_additions)
        || input["grant_summary"] != json!(grant)
        || !display_valid(
            &input["execution_readable_display_only"],
            &envelope.execution,
        )
    {
        return Err(protocol(
            "workspace judgement input shape or exact context differs",
        ));
    }
    let flags = &input["flagged_code_points"];
    if !exact_keys(flags, &["rows", "omitted_count"])
        || flags["omitted_count"].as_u64().is_none_or(|n| n > 262_144)
    {
        return Err(protocol("workspace judgement flags differ"));
    }
    let rows = flags["rows"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_FLAG_ROWS)
        .ok_or_else(|| protocol("workspace judgement flag rows differ"))?;
    let mut claims = BTreeMap::new();
    for row in rows {
        if !exact_keys(row, &["field", "first_byte_offset", "code_point", "count"]) {
            return Err(protocol("workspace judgement flag row differs"));
        }
        let field = row["field"]
            .as_str()
            .ok_or_else(|| protocol("workspace judgement flag field differs"))?;
        let offset = row["first_byte_offset"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| protocol("workspace judgement flag offset differs"))?;
        let point = row["code_point"]
            .as_str()
            .and_then(|s| s.strip_prefix("U+"))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .and_then(char::from_u32)
            .ok_or_else(|| protocol("workspace judgement flag point differs"))?;
        let count = row["count"]
            .as_u64()
            .ok_or_else(|| protocol("workspace judgement flag count differs"))?;
        if claims
            .insert((field.to_owned(), point), (offset, count))
            .is_some()
        {
            return Err(protocol("workspace judgement flag row repeats"));
        }
    }
    let mut missing_floor = 0;
    let mut available_unrowed = 0;
    for (field, bytes) in all_field_bytes(envelope) {
        for (point, (offset, count)) in scan_points(bytes) {
            match claims.remove(&(field.clone(), point)) {
                Some((claimed_offset, claimed_count))
                    if claimed_offset == offset && claimed_count == count as u64 => {}
                Some(_) => return Err(protocol("workspace judgement flag truth differs")),
                None => {
                    available_unrowed += 1;
                    if floor_point(point) {
                        missing_floor += 1;
                    }
                }
            }
        }
    }
    if !claims.is_empty() {
        return Err(protocol("workspace judgement flag field or point differs"));
    }
    let omitted = flags["omitted_count"].as_u64().unwrap_or_default();
    if omitted < missing_floor || omitted > available_unrowed {
        return Err(protocol("workspace judgement flag coverage differs"));
    }
    Ok(())
}
/// Explicit outcome; absence of a measurement never becomes a successful exit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Outcome {
    Unknown,
    Exited { code: i32 },
    Signalled { signal: u32 },
    TimedOut,
}
/// Measured wall and CPU; null is unmeasured, not zero.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub outcome: Outcome,
    #[serde(deserialize_with = "required_measurement")]
    pub wall_seconds: Option<f64>,
    #[serde(deserialize_with = "required_measurement")]
    pub user_cpu_seconds: Option<f64>,
    #[serde(deserialize_with = "required_measurement")]
    pub system_cpu_seconds: Option<f64>,
}
impl Measurement {
    fn valid(&self) -> bool {
        [
            self.wall_seconds,
            self.user_cpu_seconds,
            self.system_cpu_seconds,
        ]
        .into_iter()
        .flatten()
        .all(|v| v.is_finite() && v >= 0.0)
            && !matches!(self.outcome, Outcome::Signalled { signal: 0 })
            && (matches!(self.outcome, Outcome::Unknown) || self.wall_seconds.is_some())
    }
}
/// Schema-seven effect detail. It attests a request, not a checkout/tree or source revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceEffect {
    pub envelope: Envelope,
    pub grant: Grant,
    pub policy_revision: String,
    pub blacklist_revision: String,
    /// Exact request retained by the decision owner versus candidate execution bytes.
    pub execution_digest: String,
    /// Authenticated learned decision versus a requester substituting any context component.
    pub context_digest: String,
    pub result: Measurement,
    #[serde(deserialize_with = "required_measurement")]
    pub admission_wall_seconds: Option<f64>,
    pub steps: Vec<Measurement>,
}
impl WorkspaceEffect {
    /// Strict shared record reader. Sequence evidence is a stopped prefix, never later steps after failure.
    /// # Errors
    /// Refuses unbound context, malformed measures or impossible sequence evidence.
    pub fn decode(value: Value, class: &str, loop_name: &str, run: &str) -> Result<Self, Refusal> {
        let effect: Self = serde_json::from_value(value).map_err(|e| protocol(e.to_string()))?;
        admit(
            &effect.envelope,
            Some(&effect.grant),
            loop_name,
            run,
            &effect.grant.node,
        )?;
        let key = learned_key(
            class,
            &effect.envelope,
            &effect.grant,
            &effect.policy_revision,
        )?;
        if effect.execution_digest != canonical_digest(&effect.envelope.execution)?
            || key[2] != effect.context_digest
            || !text(&effect.policy_revision)
            || effect.policy_revision != effect.grant.quick_policy_digest
            || !text(&effect.blacklist_revision)
            || !effect.result.valid()
            || effect
                .admission_wall_seconds
                .is_some_and(|v| !v.is_finite() || v < 0.0)
            || !effect.steps.iter().all(Measurement::valid)
        {
            return Err(context("workspace effect binding or measurements differ"));
        }
        match &effect.envelope.execution {
            Execution::Sequence { steps } => {
                if effect.steps.len() > steps.len()
                    || effect
                        .steps
                        .iter()
                        .take(effect.steps.len().saturating_sub(1))
                        .any(|m| m.outcome != (Outcome::Exited { code: 0 }))
                {
                    return Err(protocol(
                        "sequence did not stop at its first unsuccessful step",
                    ));
                }
                // A deadline may expire after a successful prefix, including before
                // any completed step was observed. Do not invent a step outcome.
                let between_steps_timeout = effect.result.outcome == Outcome::TimedOut
                    && effect.steps.len() < steps.len()
                    && effect
                        .steps
                        .iter()
                        .all(|m| m.outcome == (Outcome::Exited { code: 0 }));
                if !between_steps_timeout {
                    if let Some(last) = effect.steps.last() {
                        if effect.result.outcome != last.outcome
                            || (last.outcome == (Outcome::Exited { code: 0 })
                                && effect.steps.len() != steps.len())
                        {
                            return Err(protocol("sequence aggregate outcome differs"));
                        }
                    } else if effect.result.outcome != Outcome::Unknown {
                        return Err(protocol("sequence steps are absent"));
                    }
                }
            }
            _ if !effect.steps.is_empty() => {
                return Err(protocol("non-sequence has step evidence"));
            }
            _ => {}
        }
        Ok(effect)
    }
}

fn required_measurement<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<f64>, D::Error> {
    Option::<f64>::deserialize(deserializer)
}
impl Envelope {
    /// Sequence continuation contract: fixed cwd/env, one deadline, stop on any non-success.
    /// No process is started by this decision.
    #[must_use]
    pub fn next_step(&self, completed: &[Measurement], elapsed_ms: u64) -> Option<usize> {
        if self.validate().is_err() {
            return None;
        }
        let Execution::Sequence { steps } = &self.execution else {
            return None;
        };
        (elapsed_ms < self.deadline_ms
            && completed.len() < steps.len()
            && completed
                .iter()
                .all(|m| m.valid() && m.outcome == (Outcome::Exited { code: 0 })))
        .then_some(completed.len())
    }
}
