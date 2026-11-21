//! Lossless agent input and schema-seven execution evidence, without an effect writer.
use super::*;

fn flagged(c: char) -> bool {
    c.is_control()
        || matches!(u32::from(c), 0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f | 0x08e2 | 0x0890..=0x0891 | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x13455 | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f)
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
fn flags(path: &str, bytes: &[u8], rows: &mut Vec<Value>) {
    // Decode valid spans only. Invalid UTF-8 remains explicit bytes in execution.
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let (valid, skip) = match std::str::from_utf8(rest) {
            Ok(s) => (s, 0),
            Err(e) => (
                std::str::from_utf8(&rest[..e.valid_up_to()]).unwrap_or_default(),
                e.error_len()
                    .unwrap_or_else(|| rest.len() - e.valid_up_to()),
            ),
        };
        for (i, c) in valid.char_indices().filter(|(_, c)| flagged(*c)) {
            rows.push(json!({"field":path,"byte_offset":offset+i,"code_point":format!("U+{:04X}",u32::from(c))}));
        }
        offset += valid.len() + skip;
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
    match &envelope.execution {
        Execution::Argv { words } => {
            for (i, w) in words.iter().enumerate() {
                flags(&format!("execution.words[{i}]"), w, &mut code_points);
            }
        }
        Execution::Sequence { steps } => {
            for (s, words) in steps.iter().enumerate() {
                for (i, w) in words.iter().enumerate() {
                    flags(&format!("execution.steps[{s}][{i}]"), w, &mut code_points);
                }
            }
        }
        Execution::Shell { shell, text } => {
            flags("execution.shell", shell.as_bytes(), &mut code_points);
            flags("execution.text", text.as_bytes(), &mut code_points);
        }
    }
    for (i, c) in envelope.cwd.iter().enumerate() {
        flags(&format!("cwd[{i}]"), c.as_bytes(), &mut code_points);
    }
    for (i, (k, v)) in envelope.env_additions.iter().enumerate() {
        flags(
            &format!("env_additions[{i}].name"),
            k.as_bytes(),
            &mut code_points,
        );
        flags(
            &format!("env_additions[{i}].value"),
            v.as_bytes(),
            &mut code_points,
        );
    }
    Ok(
        json!({"execution":envelope.execution,"execution_readable_display_only":readable_execution(&envelope.execution),"cwd":envelope.cwd,"env_additions":envelope.env_additions,"grant_summary":grant,"miss_reasons":reasons,"flagged_code_points":code_points}),
    )
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
