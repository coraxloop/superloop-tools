//! Receive the separate helper from the test suite's declared executable binding.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// # Panics
/// Panics if the declared test executable binding is missing or does not name an accessible absolute executable file.
pub fn binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let path = PathBuf::from(std::env::var_os("SUPERLOOP_TEST_REQUESTS_HELPER")
                .expect(concat!(
                    "SUPERLOOP_TEST_REQUESTS_HELPER must name the registered requests-helper executable; ",
                    "the cargo-test test in root meson.build supplies this binding; requests-helper is declared in packages/permission-triage/meson.build; ",
                    "lane route: on the assigned worker node run cargo build --locked --workspace --bins, then ",
                    "export SUPERLOOP_TEST_REQUESTS_HELPER=\"$CARGO_TARGET_DIR/debug/requests-helper\" ",
                    "before cargo test --locked with --no-fail-fast"
                )));
            let metadata = std::fs::metadata(&path).expect("registered requests-helper metadata");
            assert!(
                path.is_absolute() && metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
                "SUPERLOOP_TEST_REQUESTS_HELPER must name an absolute executable file"
            );
            path
        })
        .as_path()
}

pub fn registry(root: &Path, loop_name: &str) -> PathBuf {
    let directory = root.join("permission-registry");
    let state = root.join("permission-state");
    for path in [&directory, &state] {
        std::fs::create_dir(path).expect("permission fixture directory");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("private fixture");
    }
    let row = directory.join(format!("{loop_name}.env"));
    std::fs::write(
        &row,
        format!(
            "LOOP_NAME={loop_name}\nLOOP_SID=fixture\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            root.display(),
            state.display()
        ),
    )
    .expect("permission fixture row");
    std::fs::set_permissions(row, std::fs::Permissions::from_mode(0o600)).expect("private row");
    directory
}
