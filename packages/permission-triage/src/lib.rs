#![doc = include_str!("../README.md")]

pub mod command_checks;
pub mod evidence;
#[cfg(target_os = "linux")]
pub mod hook;
#[cfg(target_os = "linux")]
pub mod hook_entry;
#[cfg(target_os = "linux")]
pub mod journal;
#[cfg(target_os = "linux")]
pub mod model;
mod proc;
pub mod request;
pub mod requests;
#[cfg(target_os = "linux")]
pub mod review;
#[cfg(target_os = "linux")]
pub mod role;
#[cfg(target_os = "linux")]
pub mod rubric;
#[cfg(target_os = "linux")]
pub mod topology;

#[cfg(not(target_os = "linux"))]
compile_error!("permission-triage rubric loading requires Linux O_NOFOLLOW semantics");

pub use command_checks::{
    FastLane, HAS_MODEL_RUN_PATH, HYGIENE_RULES, HygieneRule, READ_ONLY_TABLE, ReadOnlyEntry,
    classify, matching_read_only_entry,
};
pub use request::{BashInput, DecodeResult, PermissionRequest, decode_request};
#[cfg(target_os = "linux")]
pub use {
    hook::{
        EscalationRecord, EscalationSink, HookInputError, HookOutcome, HookResponse,
        HookResponseBoundary, HookTiming, InvocationOutput, MAX_HOOK_INPUT_BYTES, MAX_REASON_BYTES,
        MODE_VARIABLE, Mode, ModelStage, PermissionDecision, ReductionError, adapt_hook,
        execute_invocation, execute_non_hook_invocation, last_resort_deny, nested_hook_response,
        reduced_action,
    },
    journal::{
        DispositionDetail, DispositionOutcome, Journal, JournalError, MAX_JOURNAL_RECORD_BYTES,
        read_journal_bytes, request_digest,
    },
    model::{Classification, ModelError, ModelResult, run_model},
    review::{
        COMMAND_CREDENTIAL_WARNING, Review, ReviewError, ReviewEscalation, ReviewGroup,
        load_review, review_from_bytes,
    },
    role::{
        CallerRole, Registry, RegistryEntry, RegistryError, ResolvedLoop, load_registry,
        parse_registry, resolve_role,
    },
    rubric::{Prompt, RubricError, Rubrics, load_rubrics},
    topology::{
        MAX_TOPOLOGY_CEILING_MS, ProbeReport, ProbeStatus, SUPPORTED_HARNESS_VERSION,
        TOPOLOGY_COMMAND, TOPOLOGY_INSTRUCTION, TopologyError, run_topology_probe,
    },
};

#[cfg(test)]
mod tests;
