use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

pub fn settings(state: &Path) -> (PathBuf, PathBuf, String) {
    let root = state.with_extension("requests");
    let registry = root.join("registry");
    let journal = root.join("journal");
    for path in [&root, &registry, &journal] {
        fs::create_dir_all(path).expect("private journal fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
    }
    let row = registry.join("fixture.env");
    fs::write(
        &row,
        format!(
            "LOOP_NAME=fixture\nLOOP_SID=fixture\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            root.display(),
            journal.display()
        ),
    )
    .expect("registry");
    fs::set_permissions(row, fs::Permissions::from_mode(0o600)).expect("registry mode");
    (
        std::env::var_os("SUPERLOOP_TEST_REQUESTS_HELPER")
            .map(PathBuf::from)
            .expect("SUPERLOOP_TEST_REQUESTS_HELPER"),
        registry,
        "fixture".into(),
    )
}
