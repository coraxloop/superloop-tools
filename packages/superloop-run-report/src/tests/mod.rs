use std::ffi::OsString;
use std::time::Duration;

use super::{Mounts, format_wall, normalize_exit, parse_available};

/// ´test:crate:mount-defaults-preserve-deployed-paths´
#[test]
fn mount_defaults_preserve_deployed_paths() {
    assert_eq!(
        Mounts::from_lookup(|_| None),
        Mounts {
            rootfs_tmp: OsString::from("/tmp"),
            workspace: OsString::from("/workspace"),
        }
    );
}

/// ´test:crate:mount-environment-overrides-are-independent´
#[test]
fn mount_environment_overrides_are_independent() {
    let mounts = Mounts::from_lookup(|name| match name {
        "RUN_REPORT_ROOTFS_TMP_MOUNT" => Some(OsString::from("/rootfs")),
        "RUN_REPORT_WORKSPACE_MOUNT" => Some(OsString::from("/work")),
        _ => None,
    });
    assert_eq!(mounts.rootfs_tmp, OsString::from("/rootfs"));
    assert_eq!(mounts.workspace, OsString::from("/work"));
}

/// ´test:crate:wall-format-has-one-decimal-place´
#[test]
fn wall_format_has_one_decimal_place() {
    assert_eq!(format_wall(Duration::from_millis(1_249)), "1.2");
    assert_eq!(format_wall(Duration::from_millis(1_250)), "1.2");
    assert_eq!(format_wall(Duration::ZERO), "0.0");
}

/// ´test:crate:df-parser-uses-last-availability-value´
#[test]
fn df_parser_uses_last_availability_value() {
    assert_eq!(
        parse_available(b"Avail\n  20G\n"),
        Some(String::from("20G"))
    );
    assert_eq!(parse_available(b"Avail\n"), None);
    assert_eq!(parse_available(b"not UTF-8: \xff\n"), None);
}

/// ´test:crate:out-of-range-execwrap-status-is-wrapper-failure´
#[test]
fn out_of_range_execwrap_status_is_wrapper_failure() {
    assert_eq!(normalize_exit(0), 0);
    assert_eq!(normalize_exit(255), 255);
    assert_eq!(normalize_exit(-1), 125);
    assert_eq!(normalize_exit(256), 125);
}
