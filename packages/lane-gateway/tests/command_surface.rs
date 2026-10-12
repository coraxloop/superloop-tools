//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`private_gateway_rejects_retired_verdict_commands_before_settings`] |  | — |
//! | [`private_gateway_version_and_readonly_status_use_installed_identity`] |  | — |

mod support;
use std::process::Command;

/// ´test:integration:private-gateway-rejects-retired-verdict-commands-before-settings´
#[test]
fn private_gateway_rejects_retired_verdict_commands_before_settings() {
    for words in [
        vec!["proposals"],
        vec!["approve", "lane", "1"],
        vec!["deny", "lane", "1", "reason"],
        vec!["abandon", "lane", "1", "reason"],
        vec!["validate-request", "lane", "request"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_gateway-service"))
            .args(words)
            .env_clear()
            .output()
            .expect("private CLI");
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_eq!(output.stdout, [] as [u8; 0]);
        let record: serde_json::Value = serde_json::from_slice(&output.stderr).expect("usage JSON");
        assert_eq!(record["command"], "gateway-service");
    }
}

/// ´test:integration:private-gateway-version-and-readonly-status-use-installed-identity´
#[test]
fn private_gateway_version_and_readonly_status_use_installed_identity() {
    let root = std::env::temp_dir().join(format!("gateway-surface-{}", std::process::id()));
    std::fs::create_dir(&root).expect("fixture root");
    let state = root.join("absent");
    let (helper, registry, loop_name) = support::settings(&state);
    let output = Command::new(env!("CARGO_BIN_EXE_gateway-service"))
        .arg("status")
        .env_clear()
        .env("LANE_GATEWAY_STATE", &state)
        .env("SUPERLOOP_GATEWAY_REQUESTS_HELPER", helper)
        .env("PERMISSION_TRIAGE_LOOP_REGISTRY", registry)
        .env("SUPERLOOP_GATEWAY_LOOP", loop_name)
        .output()
        .expect("readonly CLI");
    assert!(output.status.success(), "{output:?}");
    assert!(!state.exists());
    let version = Command::new(env!("CARGO_BIN_EXE_gateway-service"))
        .arg("--version")
        .env_clear()
        .output()
        .expect("version");
    assert!(version.status.success());
    assert_eq!(version.stdout, [] as [u8; 0]);
    let record: serde_json::Value = serde_json::from_slice(&version.stderr).expect("version JSON");
    assert_eq!(
        record["fields"]["version"],
        format!("gateway-service {}", env!("CARGO_PKG_VERSION"))
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}
