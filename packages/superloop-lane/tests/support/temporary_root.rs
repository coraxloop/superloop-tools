use std::path::PathBuf;

/// Resolve the explicitly assigned fixture storage before allocating any files.
///
/// # Panics
/// Panics if TMPDIR is unset, inaccessible or resolves under /tmp.
pub fn temporary_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("TMPDIR").expect("fixture TMPDIR must be set; /tmp fallback is forbidden"),
    )
    .canonicalize()
    .expect("fixture TMPDIR must resolve to an accessible directory");
    assert!(
        !root.starts_with("/tmp"),
        "fixture TMPDIR must not resolve under /tmp: {}",
        root.display()
    );
    root
}
