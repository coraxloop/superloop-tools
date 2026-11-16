//! Shared custody, records and result envelope for the observation and fixture artifacts.
mod fixture;
mod identity;
mod observe;
mod process;
mod receipt;
mod record;

#[derive(serde::Serialize)]
pub(crate) struct Envelope<T> {
    pub(crate) schema: u32,
    pub(crate) command: &'static str,
    pub(crate) case: String,
    pub(crate) outcome: &'static str,
    pub(crate) wall_us: u128,
    pub(crate) evidence: T,
}

mod fixture_cli;
mod observation_cli;

/// Run the observation command's shared control plane and redacted error boundary.
pub fn run_observer() -> std::process::ExitCode {
    observation_cli::main()
}

/// Run the rehearsal fixture's shared control plane and redacted error boundary.
pub fn run_fixture() -> std::process::ExitCode {
    fixture_cli::main()
}

// Retained isolated core interfaces also support the unprivileged controls.
#[allow(
    dead_code,
    reason = "isolated core and control interfaces remain available beside installed adapters"
)]
mod launch;
