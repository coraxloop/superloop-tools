//! Vendor image fixtures enter through the production lane executable.

#[path = "support/vendor_fixture.rs"]
mod vendor_fixture;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use vendor_fixture::{Fixture, file, successful};

/// ´test:integration:vendor-build-entry-preserves-rendered-codex-program´
#[test]
fn vendor_build_entry_preserves_rendered_codex_program() {
    let mut fixture = Fixture::new(true, false);
    let template = fixture.root.path().join("template");
    std::fs::create_dir(&template).expect("fixture template directory");
    file(
        &template.join("Containerfile"),
        include_str!("../data/Containerfile")
            .replace(
                "/usr/libexec/superloop/codex\n",
                "/usr/libexec/superloop/codex-@CODEX_VERSION@\n",
            )
            .replace(
                "/usr/libexec/superloop/codex ",
                "/usr/libexec/superloop/codex-@CODEX_VERSION@ ",
            )
            .as_bytes(),
        0o600,
    );
    file(
        &template.join("box-init"),
        include_bytes!("../data/box-init"),
        0o600,
    );
    fixture.template = template;
    let report = successful(&fixture.call());
    assert_eq!(
        report["codex_image_program"],
        "/usr/libexec/superloop/codex-0.1.0"
    );
    let repeated = successful(&fixture.call());
    assert_eq!(repeated["action"], "reuse");
    assert_eq!(
        repeated["codex_image_program"],
        report["codex_image_program"]
    );
}

/// ´test:integration:vendor-build-entry-codex-claude-and-both´
#[test]
fn vendor_build_entry_codex_claude_and_both() {
    for (codex, claude) in [(true, false), (false, true), (true, true)] {
        let fixture = Fixture::new(codex, claude);
        let report = successful(&fixture.call());
        let calls =
            std::fs::read_to_string(fixture.root.path().join("calls")).expect("container calls");
        let calls: Vec<Value> = calls
            .lines()
            .map(|line| serde_json::from_str(line).expect("call JSON"))
            .collect();
        let build = calls
            .iter()
            .find(|call| call[0] == "build")
            .expect("image build")
            .as_array()
            .expect("argv");
        let tag = build
            .windows(2)
            .find(|pair| pair[0] == "--tag")
            .expect("tag argument")[1]
            .as_str()
            .expect("tag");
        let vendor = if codex { "codex" } else { "claude" };
        assert!(
            tag.starts_with(&format!("localhost/superloop-lane-{vendor}:0.1.0-")),
            "{tag}"
        );
        assert_eq!(report.get("codex_sha256").is_some(), codex);
        assert_eq!(report.get("claude_sha256").is_some(), claude);
        assert_eq!(report["action"], "build");
        if claude {
            assert_eq!(
                report["claude_runtime"]["image_digest"],
                report["image_digest"]
            );
            superloop_lane::build::payload::check_claude_report(&report, true)
                .expect("complete image evidence");
        }
        let repeat = successful(&fixture.call());
        assert_eq!(repeat["action"], "reuse");
        assert_eq!(repeat["changed"], false);
    }
}

/// ´test:integration:vendor-build-entry-refuses-incomplete-image-evidence´
#[test]
fn vendor_build_entry_refuses_incomplete_image_evidence() {
    for field in ["sha256", "version", "help", "libraries", "interpreter"] {
        let fixture = Fixture::new(false, true);
        fixture.mutate_probe(|probe| probe[field] = Value::Null);
        let output = fixture.call();
        assert!(!output.status.success(), "accepted missing {field}");
        assert!(
            !fixture
                .root
                .path()
                .join(".config/loops/alpha/image-build.json")
                .exists()
        );
    }
    for option in superloop_lane::build::payload::CLAUDE_EXEC_OPTIONS {
        let fixture = Fixture::new(false, true);
        fixture.mutate_probe(|probe| {
            probe["help"] = json!(
                probe["help"]
                    .as_str()
                    .expect("help")
                    .replace(option, "--other")
            );
        });
        assert!(
            !fixture.call().status.success(),
            "accepted missing option {option}"
        );
    }
    let fixture = Fixture::new(false, true);
    fixture.mutate_probe(|probe| probe["version"] = json!("9.9.9 (Claude Code)\n"));
    assert!(
        !fixture.call().status.success(),
        "accepted another image version"
    );
}

/// ´test:integration:vendor-build-entry-refuses-wrapper-and-pin-mismatch´
#[test]
fn vendor_build_entry_refuses_wrapper_and_pin_mismatch() {
    let mut fixture = Fixture::new(false, true);
    fixture.claude_hash = "e".repeat(64);
    assert!(!fixture.call().status.success());
    file(
        &fixture.root.path().join("claude"),
        b"#!/bin/sh\nexit 0\n",
        0o700,
    );
    fixture.claude_hash =
        superloop_lane::build::sha256(&fixture.root.path().join("claude")).expect("wrapper hash");
    let output = fixture.call();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a script or wrapper"));
}

/// ´test:integration:vendor-build-entry-enforces-help-bound-and-image-binding´
#[test]
fn vendor_build_entry_enforces_help_bound_and_image_binding() {
    let fixture = Fixture::new(false, true);
    fixture.mutate_probe(|probe| probe["help"] = json!("x".repeat(65_537)));
    assert!(!fixture.call().status.success());
    let fixture = Fixture::new(false, true);
    let mut report = successful(&fixture.call());
    report["claude_image_program"] = json!("/usr/bin/another-program");
    assert!(superloop_lane::build::payload::check_claude_report(&report, true).is_err());
    report["claude_image_program"] = json!(superloop_lane::build::payload::CLAUDE_IMAGE_PROGRAM);
    report["claude_runtime"]["image_digest"] = json!(format!("sha256:{}", "e".repeat(64)));
    assert!(superloop_lane::build::payload::check_claude_report(&report, true).is_err());
    report
        .as_object_mut()
        .expect("object")
        .remove("claude_runtime");
    assert!(superloop_lane::build::payload::check_claude_report(&report, false).is_err());
}

/// ´test:integration:vendor-build-entry-reports-executed-claude-probe´
#[test]
fn vendor_build_entry_reports_executed_claude_probe() {
    let fixture = Fixture::new(false, true);
    let report = successful(&fixture.call());
    let home = fixture.root.path();
    for installed in [false, true] {
        if installed {
            let settings_path = home.join(".config/loops/alpha/workers.toml");
            let source = fs::read_to_string(&settings_path).expect("settings");
            let mut settings: toml::Value = toml::from_str(&source).expect("settings TOML");
            for (key, value) in [
                ("template_dir", "/fixture/template"),
                ("socket_dir", "/fixture/sockets"),
            ] {
                settings
                    .as_table_mut()
                    .expect("table")
                    .insert(key.into(), toml::Value::String(value.into()));
            }
            file(
                &settings_path,
                toml::to_string(&settings).expect("settings").as_bytes(),
                0o600,
            );
            file(
                &home.join(".config/loops/alpha/install-generation.json"),
                &serde_json::to_vec(&json!({
                    "schema":1,"phase":"complete","image_digest":report["image_digest"],
                    "claude_sha256":report["claude_sha256"],"tools_commit":report["tools_commit"],
                    "claude_image_program":report["claude_image_program"],
                    "claude_template_dir":home.join(".var/loops/alpha/runner-templates/claude").join("b".repeat(64)),
                    "template_dir":"/fixture/template","socket_dir":"/fixture/sockets"
                }))
                .expect("generation"),
                0o600,
            );
        }
        file(&home.join("calls"), b"", 0o600);
        let preview = successful(&fixture.call_with(&["--dry-run"]));
        assert_eq!(
            preview["action"],
            if installed { "seed-settings" } else { "reuse" }
        );
        let calls: Vec<Value> = fs::read_to_string(home.join("calls"))
            .expect("calls")
            .lines()
            .map(|line| serde_json::from_str(line).expect("call JSON"))
            .collect();
        let reported: Vec<Value> = preview["probes_executed"]
            .as_array()
            .expect("executed probes")
            .iter()
            .map(|probe| probe["argv"].clone())
            .collect();
        assert_eq!(
            reported, calls,
            "every executed container argv is reported exactly"
        );
        assert_eq!(calls.len(), 3);
        assert!(
            calls[2]
                .as_array()
                .expect("probe argv")
                .contains(&json!("--entrypoint=/usr/bin/python3"))
        );
    }
}

/// ´test:integration:vendor-build-entry-reuses-complete-base-record´
#[test]
fn vendor_build_entry_reuses_complete_base_record() {
    let fixture = Fixture::new(true, false);
    let home = fixture.root.path();
    // Captured from cd2ae5220cd49f2579cdc0df854f803ccf3fbff6's production
    // executable with this static fixture; only temporary paths are rebound.
    let record = include_str!("fixtures/base-image-build.json")
        .replace("@HOME@", home.to_str().expect("home"))
        .replace(
            "@DATA@",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .to_str()
                .expect("data"),
        );
    let report_path = home.join(".config/loops/alpha/image-build.json");
    file(&report_path, record.as_bytes(), 0o600);
    file(&home.join(".config/loops/alpha/workers.toml"), format!(
        "vendor_hosts = {{codex = []}}\nimage_digest = 'sha256:{}'\nbackend_argv = {{codex = ['/usr/libexec/superloop/codex']}}\n", "b".repeat(64)
    ).as_bytes(), 0o600);
    let preview = successful(&fixture.call_with(&["--dry-run"]));
    assert_eq!(preview["action"], "reuse");
    assert_eq!(preview["would_backfill_exec_probe"], false);
    assert_eq!(
        fs::read(&report_path).expect("retained record"),
        record.as_bytes()
    );
}
