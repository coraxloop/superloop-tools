use std::process::Command;

fn fixture(case: &str) {
    let output = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixture.py"))
        .arg(env!("CARGO_BIN_EXE_superloop-claude-desktop"))
        .arg(case)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// ´test:integration:groups-dry-run-wal-table-and-migration´
#[test]
fn groups_dry_run_wal_table_and_migration() {
    fixture("groups");
}

/// ´test:integration:groups-keep-first-seen-order-and-stable-scope-priority´
#[test]
fn groups_keep_first_seen_order_and_stable_scope_priority() {
    fixture("group-order");
}

/// ´test:integration:sessions-dry-run-roots-live-forks-and-merge´
#[test]
fn sessions_dry_run_roots_live_forks_and_merge() {
    fixture("sessions");
}

/// ´test:integration:desktop-locks-corruption-and-options´
#[test]
fn desktop_locks_corruption_and_options() {
    fixture("refusals");
}
