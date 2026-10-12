pub mod entry_listing;
pub mod letters;
pub mod letters_context;
pub mod machine;
pub mod pre_tool;
pub mod project_root;

pub use machine::{Effect, Guard, HookResult, State, Transition, heartbeat_graph};
use session_core::heartbeat::Timing;
use std::path::Path;

/// Evaluate a fixture with controlled wall-clock samples and no real sleep.
///
/// This is public so integration fixtures can prove time boundaries without
/// consulting the wall clock. Production execution always uses the system
/// clock and the one-second retry.
#[doc(hidden)]
#[must_use]
pub fn fixture_evaluate(
    input: &[u8],
    state_dir: &Path,
    initial_now: &str,
    retry_now: &str,
) -> HookResult {
    machine::run(input, state_dir, Timing::fixed(initial_now, retry_now))
}

/// Evaluate the complete composed graph with a controlled listing and clock.
#[doc(hidden)]
#[must_use]
pub fn fixture_evaluate_with_letters(
    input: &[u8],
    state_dir: &Path,
    now: &str,
    listing: &[u8],
) -> HookResult {
    machine::run_with_listing(
        input,
        state_dir,
        Timing::fixed(now, now),
        letters::listing("alpha", listing),
    )
}

/// Evaluate a fixture while replacing the transcript at the retry boundary.
#[doc(hidden)]
#[must_use]
pub fn fixture_evaluate_with_reload(
    input: &[u8],
    state_dir: &Path,
    initial_now: &str,
    retry_now: &str,
    replacement_transcript: &[u8],
) -> HookResult {
    machine::run(
        input,
        state_dir,
        Timing::fixed_with_reload(initial_now, retry_now, replacement_transcript),
    )
}
