//! Stateless inbox history, independent of heartbeat state and delivery receipts.

use super::letters::{self, Listing};
use super::machine;
use serde_json::{Value, json};
use std::env;
use std::path::Path;

#[must_use]
pub fn run(input: &[u8], state_dir: &Path) -> Option<Vec<u8>> {
    let payload: Value = serde_json::from_slice(input).ok()?;
    let event = payload["hook_event_name"].as_str()?;
    let cwd = payload["cwd"].as_str()?;
    let home = env::var_os("HOME")?;
    let (_, listing) = letters::inspect(cwd, Path::new(&home));
    if matches!(listing, Listing::Failed(_)) {
        machine::record_letters_listing_failure(state_dir);
        return None;
    }
    let feedback = listing.feedback(20);
    if feedback.is_empty() {
        return None;
    }
    serde_json::to_vec(&json!({"hookSpecificOutput": {
        "hookEventName": event, "additionalContext": feedback
    }}))
    .ok()
}
