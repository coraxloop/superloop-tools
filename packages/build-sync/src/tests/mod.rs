use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::time::{Duration, UNIX_EPOCH};

use super::{
    BuildRecord, Change, decide, probe, select_executable, should_rewrite_record, utc_timestamp,
};

/// ´test:crate:artifact-selection-requires-matching-executable-target´
#[test]
fn artifact_selection_requires_matching_executable_target() {
    let unrelated =
        r#"{"reason":"compiler-artifact","target":{"name":"other"},"executable":"/tmp/other"}"#;
    let library = r#"{"reason":"compiler-artifact","target":{"name":"wanted"},"executable":null}"#;
    let wanted =
        r#"{"reason":"compiler-artifact","target":{"name":"wanted"},"executable":"/tmp/wanted"}"#;
    assert_eq!(select_executable(unrelated, "wanted").expect("JSON"), None);
    assert_eq!(select_executable(library, "wanted").expect("JSON"), None);
    assert_eq!(
        select_executable(wanted, "wanted").expect("JSON"),
        Some("/tmp/wanted".into())
    );
}

/// ´test:crate:byte-and-mode-decision-has-three-outcomes´
#[test]
fn byte_and_mode_decision_has_three_outcomes() {
    assert_eq!(decide(None, b"new"), Change::Copy);
    assert_eq!(decide(Some((b"old", 0o755)), b"new"), Change::Copy);
    assert_eq!(decide(Some((b"new", 0o644)), b"new"), Change::RepairMode);
    assert_eq!(decide(Some((b"new", 0o755)), b"new"), Change::Keep);
}

/// ´test:crate:record-is-sorted-compact-and-rewritten-only-for-copy-or-absence´
#[test]
fn record_is_sorted_compact_and_rewritten_only_for_copy_or_absence() {
    let identity = crate::identity::Identity {
        package: "demo".into(),
        installed_name: "demo".into(),
        release_group: "demo".into(),
        repository: "fixture".into(),
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        version: "0.1.1".into(),
    };
    let record = BuildRecord {
        identity: &identity,
        bin: "demo",
        build_wall_ms: 12,
        cargo_version: "cargo 1",
        domain: "server",
        package: "demo",
        profile: "release",
        rustc_version: "rustc 1",
        sha256: "abc",
        written: "2026-09-27T00:00:00Z",
    };
    let text = serde_json::to_string(&serde_json::to_value(&record).expect("record value"))
        .expect("serialize record");
    assert_eq!(
        text,
        r#"{"bin":"demo","build_wall_ms":12,"cargo_version":"cargo 1","domain":"server","installed_name":"demo","package":"demo","profile":"release","release_group":"demo","repository":"fixture","rustc_version":"rustc 1","sha256":"abc","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"0.1.1","written":"2026-09-27T00:00:00Z"}"#
    );
    let generated = BuildRecord {
        identity: &identity,
        bin: "labels.toml",
        build_wall_ms: 7,
        cargo_version: "producer 2",
        domain: "unset",
        package: "producer",
        profile: "generated",
        rustc_version: "producer 2",
        sha256: "def",
        written: "2026-09-28T00:00:00Z",
    };
    assert_eq!(
        serde_json::to_string(&serde_json::to_value(&generated).expect("generated value"))
            .expect("serialize generated record"),
        r#"{"bin":"labels.toml","build_wall_ms":7,"cargo_version":"producer 2","domain":"unset","installed_name":"demo","package":"producer","profile":"generated","release_group":"demo","repository":"fixture","rustc_version":"producer 2","sha256":"def","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"0.1.1","written":"2026-09-28T00:00:00Z"}"#
    );
    assert!(should_rewrite_record(Change::Copy, false));
    assert!(should_rewrite_record(Change::Keep, true));
    assert!(should_rewrite_record(Change::RepairMode, true));
    assert!(!should_rewrite_record(Change::Keep, false));
    assert!(!should_rewrite_record(Change::RepairMode, false));
}

/// ´test:crate:probe-rejects-nonempty-missing-directory-and-symlink´
#[test]
fn probe_rejects_nonempty_missing_directory_and_symlink() {
    let root = tempfile::tempdir().expect("temporary directory");
    let empty = root.path().join("empty");
    let filled = root.path().join("filled");
    let link = root.path().join("link");
    fs::write(&empty, []).expect("empty stamp");
    fs::write(&filled, b"x").expect("filled stamp");
    symlink(&empty, &link).expect("stamp symlink");
    assert!(probe(&empty));
    assert!(!probe(&filled));
    assert!(!probe(&root.path().join("missing")));
    assert!(!probe(root.path()));
    assert!(!probe(&link));
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o000)).expect("chmod stamp");
    assert!(probe(&empty));
}

/// ´test:crate:utc-timestamp-has-rfc3339-calendar-boundaries´
#[test]
fn utc_timestamp_has_rfc3339_calendar_boundaries() {
    assert_eq!(
        utc_timestamp(UNIX_EPOCH).expect("epoch time"),
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(
        utc_timestamp(UNIX_EPOCH + Duration::from_secs(951_782_400)).expect("leap day"),
        "2000-02-29T00:00:00Z"
    );
}
