//! Rehearsal-only executable entry; not installed by the ordinary build.
fn main() -> std::process::ExitCode {
    superloop_credential_custody::run_fixture()
}
