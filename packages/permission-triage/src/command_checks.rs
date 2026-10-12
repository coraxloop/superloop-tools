//! Harness observations and unchanged fast-lane rendering around shared checks.
use crate::request::{BashInput, PermissionRequest};
pub use execute_command::checks::{
    FastLane, HYGIENE_RULE_COUNT, HYGIENE_RULES, HygieneRule, HygieneRuleId, READ_ONLY_TABLE,
    ReadOnlyEntry, hygiene_rule, scope_words,
};
use execute_command::request::{
    Binding, Command as CommandIdentity, HygieneObservation, HygieneRequest,
};
use serde_json::json;
use std::cell::OnceCell;

/// Mechanical classification never invokes a model.
pub const HAS_MODEL_RUN_PATH: bool = false;

/// Largest watch deadline the `Monitor` tool schema accepts, in milliseconds.
pub const MAX_MONITOR_TIMEOUT_MS: u64 = 3_600_000;

#[derive(Clone, Copy)]
struct ShellInput<'a> {
    command: &'a str,
    timeout_ms: Option<u64>,
    declared_background: Option<bool>,
}

impl<'a> From<&'a BashInput> for ShellInput<'a> {
    fn from(input: &'a BashInput) -> Self {
        Self {
            command: input.command(),
            timeout_ms: input.timeout_ms(),
            declared_background: input.run_in_background(),
        }
    }
}

/// Read the shell shape of a `Bash` request or of a command-form `Monitor` request.
///
/// `Monitor` spells its deadline `timeout_ms` and its long-running declaration `persistent`, so
/// those two fields carry the shape the Bash `timeout` and `run_in_background` fields carry. A
/// `Monitor` opened on a WebSocket source runs no command and therefore has no shell shape.
fn shell_input(request: &PermissionRequest) -> Option<ShellInput<'_>> {
    if let Some(bash) = request.bash() {
        return Some(bash.into());
    }
    if request.tool_name() != "Monitor" {
        return None;
    }
    let input = request.tool_input();
    let command = input.get("command")?.as_str()?;
    let timeout_ms = match input.get("timeout_ms") {
        Some(value) => Some(
            value
                .as_u64()
                .filter(|timeout| *timeout <= MAX_MONITOR_TIMEOUT_MS)?,
        ),
        None => None,
    };
    let declared_background = match input.get("persistent") {
        Some(value) => Some(value.as_bool()?),
        None => None,
    };
    Some(ShellInput {
        command,
        timeout_ms,
        declared_background,
    })
}

struct ObservedRequest<'a> {
    request: &'a PermissionRequest,
    command: CommandIdentity,
    binding: OnceCell<Binding>,
}

impl AsRef<Binding> for ObservedRequest<'_> {
    fn as_ref(&self) -> &Binding {
        self.binding.get_or_init(|| binding(self.request, None))
    }
}

impl HygieneRequest for ObservedRequest<'_> {
    fn command(&self) -> &CommandIdentity {
        &self.command
    }

    fn cwd(&self) -> &str {
        self.request.cwd()
    }
}

fn observe<T>(
    request: &PermissionRequest,
    call: impl FnOnce(&ObservedRequest<'_>, &HygieneObservation<'_>) -> T,
) -> T {
    let shell = shell_input(request);
    let command = CommandIdentity::Bytes {
        // Native predicates use decoded fields, never a serialized command surrogate.
        bytes: shell
            .as_ref()
            .map_or_else(Vec::new, |input| input.command.as_bytes().to_vec()),
    };
    let observation = shell.map_or_else(
        || HygieneObservation::Native {
            tool: request.tool_name(),
            fields: request.tool_input(),
        },
        |input| HygieneObservation::Shell {
            timeout_ms: input.timeout_ms,
            declared_background: input.declared_background,
        },
    );
    call(
        &ObservedRequest {
            request,
            command,
            // A miss produces no verdict to bind. A hit computes once and reuses its identity.
            binding: OnceCell::new(),
        },
        &observation,
    )
}

/// Translate the common remedy into the hook's existing static rule vocabulary.
#[must_use]
pub fn classify(request: &PermissionRequest) -> FastLane {
    classify_scoped(request, "estate")
}

/// Carry the caller's computed scope into the shared verdict before rendering.
#[must_use]
pub fn classify_scoped(request: &PermissionRequest, scope: &str) -> FastLane {
    observe(request, |request, observation| {
        let Ok(Some(verdict)) = execute_command::checks::hygiene(request, observation, scope)
        else {
            return FastLane::ToModel;
        };
        if let Some(correction) = verdict.correction {
            if let Some(rule) = HYGIENE_RULES
                .iter()
                .find(|rule| rule.rule == correction.rule.as_str())
            {
                return FastLane::AgentError {
                    rule: rule.rule,
                    defect: rule.defect,
                    correction: rule.correction,
                };
            }
        } else if let Some(entry) = READ_ONLY_TABLE
            .iter()
            .find(|entry| entry.entry == verdict.reason.as_str())
        {
            return FastLane::ReadOnlyAllow { rule: entry.entry };
        }
        FastLane::ToModel
    })
}

/// Read the shared table with harness-decoded fields and exact command bytes.
#[must_use]
pub fn matching_read_only_entry(request: &PermissionRequest) -> Option<&'static ReadOnlyEntry> {
    observe(request, |request, observation| {
        execute_command::checks::matching_read_only_entry(request, observation)
    })
}

/// Bind exactly the request and rubric identities already carried by the hook journal.
///
/// # Panics
/// Panics only if SHA-256 hexadecimal digests exceed the text bound, which inputs cannot arrange.
pub(crate) fn binding(
    request: &PermissionRequest,
    rubrics: Option<&crate::rubric::Rubrics>,
) -> Binding {
    let action =
        crate::hook::reduced_action(request).unwrap_or_else(|_| request.tool_name().to_owned());
    let digest = crate::journal::request_digest(request.tool_name(), request.cwd(), &action);
    binding_from_digests(
        &digest,
        crate::rubric::GENERAL_RUBRIC_DIGEST,
        rubrics.and_then(|rubrics| rubrics.owner().map(crate::rubric::OwnerRubric::digest)),
        rubrics.and_then(|rubrics| rubrics.domain().map(crate::rubric::OwnerRubric::digest)),
    )
}

/// Hash caller-validated existing journal identities without adding persisted fields.
///
/// # Panics
/// Panics only if a validated request digest is not bounded nonblank text, which the journal reader and request digest generator cannot arrange.
pub(crate) fn binding_from_digests(
    digest: &str,
    general: &str,
    owner: Option<&str>,
    domain: Option<&str>,
) -> Binding {
    let context = json!({"request_digest":digest,"general_rubric_digest":general,"owner_rubric_digest":owner,"domain_rubric_digest":domain});
    Binding {
        request_id: digest
            .to_owned()
            .try_into()
            .expect("validated request digest"),
        context_digest: request_core::request_id(context.to_string().as_bytes())
            .try_into()
            .expect("SHA-256 text"),
    }
}

#[cfg(test)]
mod binding_tests {
    use super::binding_from_digests;

    /// ´test:unit:hook-context-binds-request-and-all-rubric-digests´
    #[test]
    fn hook_context_binds_request_and_all_rubric_digests() {
        let initial = binding_from_digests("request", "general", Some("owner"), Some("domain"));
        for changed in [
            binding_from_digests("request", "changed", Some("owner"), Some("domain")),
            binding_from_digests("request", "general", Some("changed"), Some("domain")),
            binding_from_digests("request", "general", Some("owner"), Some("changed")),
            binding_from_digests("request", "general", None, Some("domain")),
        ] {
            assert_eq!(changed.request_id, initial.request_id);
            assert_ne!(changed.context_digest, initial.context_digest);
        }
        let changed = binding_from_digests("other", "general", Some("owner"), Some("domain"));
        assert_ne!(changed.request_id, initial.request_id);
        assert_ne!(changed.context_digest, initial.context_digest);
    }
}
