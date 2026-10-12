//! Translate authenticated gateway observations and render its unchanged protocol.
use execute_command::policy::{RunAdmission, gateway_admission};
use execute_command::request::Binding;
use serde_json::json;

use crate::gateway::timestamp_unix_ms;
use crate::{Gateway, GatewayError, Refusal, RefusalRule, Registration};

/// Bind the registered command context without adding fields to stored envelopes.
///
/// # Panics
/// Panics only if serialization of the closed registration type fails or a
/// SHA-256 hex string violates the text bound, which caller input cannot arrange.
pub fn binding(registration: &Registration, seq: u64, argv: &[String]) -> Binding {
    let registration_digest = request_core::request_id(
        &serde_json::to_vec(registration).expect("registration serialization"),
    );
    binding_fields(&registration_digest, &registration.lane, seq, argv)
}

/// Bind an existing proposal's persisted context without changing its envelope.
///
/// # Panics
/// Panics only if a SHA-256 hex string violates the text bound, which caller input cannot arrange.
pub fn binding_fields(registration_digest: &str, lane: &str, seq: u64, argv: &[String]) -> Binding {
    let source = json!({"lane":lane,"seq":seq});
    let context =
        json!({"registration_digest":registration_digest,"lane":lane,"seq":seq,"argv":argv});
    Binding {
        request_id: request_core::request_id(source.to_string().as_bytes())
            .try_into()
            .expect("SHA-256 text"),
        context_digest: request_core::request_id(context.to_string().as_bytes())
            .try_into()
            .expect("SHA-256 text"),
    }
}

impl Gateway {
    pub(crate) fn command_admission(
        &self,
        registration: &Registration,
        seq: u64,
        argv: &[String],
    ) -> Result<Option<Refusal>, GatewayError> {
        let consumption = self.audit_consumption(&registration.lane)?;
        // Budget and snapshot refusals precede a caller clock failure.
        let clock = consumption
            .last_run_timestamp_ms
            .map(|_| timestamp_unix_ms());
        let observed = RunAdmission {
            runs: consumption.runs,
            run_cap: registration.budgets.run_cap,
            has_snapshot: consumption.mirror_snapshot.is_some(),
            last_run_timestamp_ms: consumption.last_run_timestamp_ms,
            cooldown_seconds: registration.budgets.cooldown_seconds,
            now_unix_ms: clock
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .unwrap_or(0),
        };
        let Some(verdict) = gateway_admission(&binding(registration, seq, argv), &observed)
            .map_err(|_| GatewayError::CorruptState("command_verdict"))?
        else {
            let _ = clock.transpose()?;
            return Ok(None);
        };
        let correction = verdict
            .correction
            .ok_or(GatewayError::CorruptState("command_remedy"))?;
        let refusal = match correction.rule.as_str() {
            "run_budget_exhausted" => Refusal::new(RefusalRule::RunBudgetExhausted)
                .with_run_cap(observed.run_cap, observed.runs),
            "no_snapshot" => Refusal::new(RefusalRule::NoSnapshot),
            "run_cooldown_active" => {
                let _ = clock.transpose()?;
                Refusal::new(RefusalRule::RunCooldownActive)
            }
            _ => return Err(GatewayError::CorruptState("command_rule")),
        };
        Ok(Some(refusal.with_seq(seq)))
    }
}
