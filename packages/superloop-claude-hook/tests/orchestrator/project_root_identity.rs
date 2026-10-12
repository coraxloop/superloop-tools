use std::path::Path;

/// ´test:integration:project-root-resolver-matches-heartbeat-guard-byte-for-byte´
#[test]
fn project_root_resolver_matches_heartbeat_guard_byte_for_byte() {
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let orchestrator = std::fs::read_to_string(package.join("../session-core/src/orchestrator.rs"))
        .expect("read orchestrator resolver");
    let heartbeat = std::fs::read_to_string(package.join("src/heartbeat/project_root.rs"))
        .expect("read heartbeat resolver");

    assert!(orchestrator.contains("use crate::project_root;"));
    assert_eq!(
        heartbeat.trim(),
        "pub use session_core::project_root::project_root;"
    );
    assert!(!package.join("src/project_root.rs").exists());
}
