//! Compile source observations into the linter; never consult Git at runtime.

use std::io::Write;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "cargo:rerun-if-env-changed=SUPERLOOP_TOOLS_PUBLIC_COMMIT"
    )?;
    writeln!(
        output,
        "cargo:rerun-if-env-changed=SUPERLOOP_TOOLS_RELEASE_TAG"
    )?;
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or("Cargo manifest directory unavailable")?,
    );
    let root = manifest
        .parent()
        .and_then(|path| path.parent())
        .ok_or("linter source identity requires the workspace package layout")?;
    // Observe Git metadata explicitly, including worktree indirection, so a
    // commit, staging change or release-tag change invalidates a warm build.
    for path in superloop_cli_common::source_identity::watch_paths(root) {
        writeln!(output, "cargo:rerun-if-changed={}", path.display())?;
    }
    let public = std::env::var("SUPERLOOP_TOOLS_PUBLIC_COMMIT")
        .ok()
        .filter(|value| !value.is_empty());
    let tag = std::env::var("SUPERLOOP_TOOLS_RELEASE_TAG")
        .ok()
        .filter(|value| !value.is_empty());
    let identity =
        superloop_cli_common::source_identity::observe(root, public.as_deref(), tag.as_deref())
            .map_err(|reason| format!("linter source identity refused: {reason}"))?;
    // Compile only the checked public source digest, never a guessed merge parent.
    writeln!(
        output,
        "cargo:rustc-env=SUPERLOOP_LINT_SOURCE_COMMIT={}",
        identity.commit.as_deref().unwrap_or("")
    )?;
    writeln!(
        output,
        "cargo:rustc-env=SUPERLOOP_LINT_SOURCE_STATE={}",
        identity.state
    )?;
    writeln!(
        output,
        "cargo:rustc-env=SUPERLOOP_LINT_RELEASE_TAG={}",
        identity.release_tag.as_deref().unwrap_or("")
    )?;
    drop(output);
    Ok(())
}
