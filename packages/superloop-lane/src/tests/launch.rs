use crate::runtime_admission::RuntimeAdmission::Gate;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use serde_json::json;
use tempfile::TempDir;

use crate::build::sha256;
use crate::fixture_exec::ENTRY_INTERFACE_PROBE;
use crate::launch::{
    LaunchRequest, RecordHostsRequest, record_hosts_with_lane_bin_from, run_with_host_root,
    run_with_host_root_and_proxy, select_free_uid,
};
use crate::settings::BoxBackend;

pub(super) fn fixture_work_route(home: &Path) {
    let config = home.join(".config/loops/alpha");
    let node = home.join("node");
    fs::create_dir_all(&node).expect("fixture node root");
    fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).expect("node root mode");
    let files = [
        ("door-compute-registration.json", json!({"schema":1,"loop":"alpha",
            "alias":"fixture","mirror_root":"~/mirrors","node_root":node,
            "key_path":config.join("door-key")}).to_string()),
        ("door-node-registration.json", json!({"schema":1,"loop":"alpha",
            "alias":"fixture","node":"fixture-node","address":"fixture.invalid","port":22,
            "user":"fixture","host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string()),
        ("door-known_hosts", "fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".to_owned()),
        ("door-ssh_config", format!("# Registered host key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nHost fixture\n  HostName fixture.invalid\n  Port 22\n  User fixture\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  BatchMode yes\n  ServerAliveInterval 30\n  ServerAliveCountMax 4\n", config.join("door-known_hosts").display())),
    ];
    for (name, bytes) in files {
        let path = config.join(name);
        fs::write(&path, bytes).expect("fixture route");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("route mode");
    }
}

// These fixtures install mode-0550 template directories; close must restore write access.
struct ProtectedRoot(Option<TempDir>);

impl ProtectedRoot {
    fn short_socket_root() -> Self {
        // No full-path socket bind is shown here; a TMPDIR run decides whether this root can move.
        Self(Some(
            TempDir::new_in("/tmp").expect("short socket fixture root"),
        ))
    }

    fn declared_root() -> Self {
        Self(Some(tempfile::tempdir().expect("declared temporary root")))
    }

    fn path(&self) -> &Path {
        self.0.as_ref().expect("fixture root").path()
    }
}

impl Drop for ProtectedRoot {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let path = root.path().to_path_buf();
            for vendor in ["codex", "claude"] {
                let template = path
                    .join("home/.var/loops/alpha/runner-templates")
                    .join(vendor)
                    .join("a".repeat(64));
                for directory in [template.join("bin"), template.join("libexec"), template] {
                    if fs::symlink_metadata(&directory)
                        .is_ok_and(|entry| entry.file_type().is_dir())
                    {
                        drop(fs::set_permissions(
                            &directory,
                            fs::Permissions::from_mode(0o700),
                        ));
                    }
                }
            }
            if let Err(error) = root.close() {
                drop(writeln!(
                    std::io::stderr(),
                    "cannot remove fixture home {}: {error}",
                    path.display()
                ));
                assert!(std::thread::panicking(), "fixture home cleanup failed");
            }
        }
    }
}

fn backend_settings(vendors: &[&str]) -> crate::settings::Settings {
    let mut settings = super::fixture_settings(std::path::Path::new("/fixture/entry"));
    settings.backend_argv = vendors
        .iter()
        .map(|vendor| ((*vendor).to_owned(), vec![format!("/fixture/{vendor}")]))
        .collect();
    settings
}

/// ´test:crate:boxed-backend-resume-vector-binds-protected-selection´
#[test]
fn boxed_backend_resume_vector_binds_protected_selection() {
    for backend in [BoxBackend::Codex, BoxBackend::Claude] {
        let settings = backend_settings(&["codex", "claude"]);
        let plan = crate::plan::Plan::build_with_door(
            std::path::Path::new("/fixture/owner"),
            "alpha",
            "R",
            &settings,
            &super::fixture_row(),
            super::fixture_block(),
            (1000, 1000),
            false,
            Some(backend),
        )
        .expect("selected plan");
        let vector: Vec<String> = plan.document["runtime_argv"]
            .as_array()
            .expect("vector")
            .iter()
            .map(|word| word.as_str().expect("word").to_owned())
            .collect();
        let session = "22222222-2222-4222-8222-222222222222";
        let mut record = json!({"plan":plan.document,"active_round":"dispatch"});
        assert_eq!(
            crate::container_helper::command_for_request(&vector, &record, None).expect("fresh"),
            vector
        );
        record["active_round"] = json!("work-1");
        record["thread_id"] = json!(session);
        let resumed = crate::container_helper::command_for_request(&vector, &record, Some(session))
            .expect("resume");
        match backend {
            BoxBackend::Codex => {
                assert!(resumed.ends_with(&["resume".into(), session.into(), "-".into()]));
            }
            BoxBackend::Claude => {
                assert_eq!(&resumed[..vector.len()], vector);
                let foreign: Vec<_> = vector
                    .iter()
                    .map(|word| {
                        if word == "/home/worker/.local/bin/claude" {
                            "/home/worker/.local/bin/codex".to_owned()
                        } else {
                            word.clone()
                        }
                    })
                    .collect();
                assert_eq!(
                    crate::container_helper::command_for_request(&foreign, &record, Some(session))
                        .expect_err("foreign program")
                        .kind,
                    "round-thread"
                );
                assert!(resumed.ends_with(&["--resume".into(), session.into()]));
                assert!(
                    crate::container_helper::resume_box_vector(backend, &resumed, session).is_err()
                );
            }
        }
        assert_eq!(
            crate::container_helper::command_for_request(&vector, &record, Some("other"))
                .expect_err("foreign session")
                .kind,
            "round-thread"
        );
        record["plan"]["backend"] = serde_json::Value::Null;
        assert_eq!(
            crate::container_helper::command_for_request(&vector, &record, Some(session))
                .expect_err("no inferred backend")
                .kind,
            "backend-selection"
        );
    }
}

/// ´test:crate:boxed-backend-claude-runtime-transformations-retain-confinement´
#[test]
fn boxed_backend_claude_runtime_transformations_retain_confinement() {
    for vendors in [&["claude"][..], &["codex", "claude"][..]] {
        let mut settings = backend_settings(vendors);
        settings.driver_argv = vec!["/fixture/driver".into()];
        settings.driver_bin = Some("/fixture/driver".into());
        let mut plan = crate::plan::Plan::build_with_door(
            std::path::Path::new("/fixture/owner"),
            "alpha",
            "R",
            &settings,
            &super::fixture_row(),
            super::fixture_block(),
            (1000, 1000),
            false,
            Some(BoxBackend::Claude),
        )
        .expect("Claude candidate vector");
        plan.select_worker_uid(3200).expect("reserved identity");
        plan.select_mail_group(3300).expect("mail group");
        plan.select_launch_model(&json!({"model":"fixture-claude", "effort":"high"}))
            .expect("selected model");
        plan.observe_vendor().expect("observing route");
        crate::plan::box_gate(&plan.document).expect("structural confinement");
        let words = plan.document["runtime_argv"]
            .as_array()
            .expect("runtime vector");
        for required in [
            "/home/worker/.local/bin/claude",
            "--user=3200:3200",
            "--group-add=3300",
            "--network=none",
            "CLAUDE_CONFIG_DIR=/home/worker/.claude",
        ] {
            assert!(
                words.iter().any(|word| word == required),
                "{required}: {words:?}"
            );
        }
        assert!(words.ends_with(&[
            json!("--model"),
            json!("fixture-claude"),
            json!("--effort"),
            json!("high")
        ]));
        assert!(plan.document["environment"]["CODEX_HOME"].is_null());
        assert_eq!(plan.document["owner_refresh_hosts"], json!([]));
        assert_eq!(
            crate::plan::verify_box_attestation(&plan.document)
                .expect_err("structural vectors do not admit unmeasured credentials")
                .kind,
            "backend-unavailable"
        );
        plan.document["model_selection"]["model"] = json!("changed");
        assert_eq!(
            crate::plan::box_gate(&plan.document)
                .expect_err("selected model must match the vector")
                .kind,
            "box-gate"
        );
    }
}

/// ´test:crate:boxed-backend-claude-runtime-refuses-cross-vendor-and-expanded-authority´
#[test]
fn boxed_backend_claude_runtime_refuses_cross_vendor_and_expanded_authority() {
    let mut settings = backend_settings(&["codex", "claude"]);
    settings.driver_argv = vec!["/fixture/driver".into()];
    settings.driver_bin = Some("/fixture/driver".into());
    let plan = crate::plan::Plan::build_with_door(
        std::path::Path::new("/fixture/owner"),
        "alpha",
        "R",
        &settings,
        &super::fixture_row(),
        super::fixture_block(),
        (1000, 1000),
        false,
        Some(BoxBackend::Claude),
    )
    .expect("Claude candidate vector");
    for (original, replacement) in [
        (
            "/home/worker/.local/bin/claude",
            "/home/worker/.local/bin/codex",
        ),
        ("--network=none", "--network=host"),
        ("--cap-drop=ALL", "--privileged"),
        ("bypassPermissions", "acceptEdits"),
        ("stream-json", "json"),
        (
            "--dangerously-skip-permissions",
            "--allow-dangerously-skip-permissions",
        ),
    ] {
        let mut changed = plan.document.clone();
        let words = changed["runtime_argv"].as_array_mut().expect("vector");
        let index = words
            .iter()
            .position(|word| word == original)
            .expect("original word");
        words[index] = json!(replacement);
        assert_eq!(
            crate::plan::box_gate(&changed)
                .expect_err("expanded or cross-vendor vector refuses")
                .kind,
            "box-gate",
            "{original} => {replacement}"
        );
    }
    let mut changed = plan.document.clone();
    let mounts = changed["mounts"].as_array_mut().expect("mounts");
    let configuration = mounts
        .iter_mut()
        .find(|row| row["target"] == "/home/worker/.claude/settings.json")
        .expect("immutable configuration");
    configuration["access"] = json!("rw");
    assert_eq!(
        crate::plan::box_gate(&changed)
            .expect_err("configuration cannot become worker writable")
            .kind,
        "box-gate"
    );
    let mut changed = plan.document;
    changed["backend"] = json!("codex");
    assert_eq!(
        crate::plan::box_gate(&changed)
            .expect_err("binding cannot select a different vector")
            .kind,
        "box-gate"
    );
}

/// ´test:crate:boxed-backend-runtime-probe-requires-selected-program-evidence´
#[test]
fn boxed_backend_runtime_probe_requires_selected_program_evidence() {
    let report = json!({"codex_exec_probe":{}, "image_digest":"sha256:fixture"});
    let error = crate::build::check_backend_exec_probe(BoxBackend::Claude, &report, &json!([]))
        .expect_err("Codex evidence cannot satisfy the Claude probe");
    assert_eq!(error.kind, "build-report");
    assert_eq!(error.detail, "build_environment.claude_bin is absent");
    let error = crate::build::check_backend_exec_probe(
        BoxBackend::Codex,
        &json!({"claude_exec_probe":{}}),
        &json!([]),
    )
    .expect_err("Claude evidence cannot satisfy the Codex probe");
    assert_eq!(error.kind, "codex-exec-help");
}

/// ´test:crate:boxed-backend-claude-options-require-selected-capture´
#[test]
fn boxed_backend_claude_options_require_selected_capture() {
    let image = format!("sha256:{}", "a".repeat(64));
    let program = "b".repeat(64);
    let help = [
        "  -p, --print",
        "  --output-format <format>  text, json or stream-json",
        "  --verbose",
        "  --permission-mode <mode>  acceptEdits, bypassPermissions, default or plan",
        "  --dangerously-skip-permissions",
        "  --model <model>",
        "  --effort <level>",
        "  -r, --resume [value]",
        "  -h, --help",
    ]
    .join("\n");
    let report = json!({"image_digest":image, "claude_version":"0.1.0", "claude_sha256":program,
        "claude_source":"https://fixture.example/claude",
        "claude_image_program":crate::build::payload::CLAUDE_IMAGE_PROGRAM,
        "build_environment":{"claude_bin":"/fixture/claude"},
        "claude_exec_probe":{"argv":["--help"], "stdout":help,
            "required_options":crate::build::payload::CLAUDE_EXEC_OPTIONS,
            "claude_sha256":program, "image_digest":image, "companions":[]},
        "claude_runtime":{"image_digest":image,
            "interpreter":{"path":"/lib64/ld-linux-x86-64.so.2", "sha256":"c".repeat(64)},
            "libraries":[{"path":"/lib64/libc.so.6", "sha256":"d".repeat(64)}]},
        "codex_exec_probe":{"stdout":"  --add-dir\n"}});
    let planned = json!([
        "/usr/bin/podman",
        "run",
        "--network=none",
        image,
        "/home/worker/.local/bin/claude",
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-mode",
        "bypassPermissions",
        "--dangerously-skip-permissions",
        "--model",
        "fixture-claude",
        "--effort",
        "high"
    ]);
    crate::build::check_backend_exec_probe(BoxBackend::Claude, &report, &planned)
        .expect("captured Claude options");
    let session = "22222222-2222-4222-8222-222222222222";
    let words: Vec<String> = planned
        .as_array()
        .expect("vector")
        .iter()
        .map(|word| word.as_str().expect("word").to_owned())
        .collect();
    let resumed = crate::container_helper::resume_box_vector(BoxBackend::Claude, &words, session)
        .expect("resumed Claude vector");
    let resumed = json!(resumed);
    crate::build::check_backend_exec_probe(BoxBackend::Claude, &report, &resumed)
        .expect("captured help lists the resume option");
    let mut stale = report.clone();
    stale["claude_exec_probe"]["stdout"] = json!(help.replace("  -r, --resume [value]\n", ""));
    let error = crate::build::check_backend_exec_probe(BoxBackend::Claude, &stale, &resumed)
        .expect_err("a capture without the resume option refuses");
    assert_eq!(error.kind, "claude-exec-help");
    let mut unlisted = planned.clone();
    unlisted
        .as_array_mut()
        .expect("vector")
        .insert(5, json!("--add-dir"));
    let error = crate::build::check_backend_exec_probe(BoxBackend::Claude, &report, &unlisted)
        .expect_err("an option only the Codex capture lists refuses");
    assert_eq!(error.kind, "claude-exec-help");
    assert_eq!(
        error.detail,
        "planned Claude option --add-dir is absent from the pinned help"
    );
    let mut foreign = planned;
    foreign[4] = json!("/home/worker/.local/bin/codex");
    let error = crate::build::check_backend_exec_probe(BoxBackend::Claude, &report, &foreign)
        .expect_err("another vendor's program refuses");
    assert_eq!(error.kind, "claude-exec-help");
    assert_eq!(error.detail, "planned Claude program differs");
}

/// ´test:crate:boxed-backend-image-program-uses-only-selected-generation´
#[test]
fn boxed_backend_image_program_uses_only_selected_generation() {
    for backend in [BoxBackend::Codex, BoxBackend::Claude] {
        let name = backend.name();
        let key = backend.vendor().program_key;
        for vendors in [
            &["codex"][..],
            &["claude"][..],
            &["codex", "claude"][..],
            &[][..],
        ] {
            let settings = backend_settings(vendors);
            let generation = json!({"codex_image_program":"/fixture/codex", "claude_image_program":"/fixture/claude"});
            let result =
                crate::launch::check_backend_image_program(&settings, &generation, backend);
            if !vendors.contains(&name) {
                let error = result.expect_err("selected program required");
                assert_eq!(error.kind, "missing-setting");
                assert_eq!(error.detail, format!("backend_argv.{name} is absent"));
                continue;
            }
            result.expect("selected image program");
            let mut changed = generation;
            changed.as_object_mut().expect("object").remove(key);
            let error = crate::launch::check_backend_image_program(&settings, &changed, backend)
                .expect_err("no other-vendor generation fallback");
            assert_eq!(error.kind, "install-generation");
            assert_eq!(
                error.detail,
                format!("{key} is absent; repeat install --pilot")
            );
            changed[key] = json!("/fixture/wrong");
            assert_eq!(
                crate::launch::check_backend_image_program(&settings, &changed, backend)
                    .expect_err("different measured program")
                    .kind,
                "backend-program"
            );
        }
    }
}

/// ´test:crate:boxed-backend-image-pin-records-bind-selected-evidence´
#[test]
fn boxed_backend_image_pin_records_bind_selected_evidence() {
    let template = std::path::Path::new("/fixture/template");
    for backend in [BoxBackend::Codex, BoxBackend::Claude] {
        let vendor = backend.vendor();
        let record = json!({"image_digest":"sha256:fixture", "codex_sha256":"codex-fixture-hash",
            "claude_sha256":"claude-fixture-hash", "codex_host_sha256":"host-fixture-hash",
            "codex_image_program":"/fixture/codex", "claude_image_program":"/fixture/claude",
            "claude_template_dir":template});
        crate::launch::check_backend_pin_records(backend, &record, &record, &record, template)
            .expect("selected records agree");
        for key in ["image_digest", vendor.hash_key, vendor.program_key] {
            let mut changed = record.clone();
            changed[key] = json!("changed");
            assert_eq!(
                crate::launch::check_backend_pin_records(
                    backend, &record, &record, &changed, template
                )
                .expect_err("changed generation refuses")
                .kind,
                "template-pin"
            );
        }
        let mut changed = record.clone();
        changed[vendor.hash_key] = json!("changed");
        assert_eq!(
            crate::launch::check_backend_pin_records(backend, &record, &changed, &record, template)
                .expect_err("changed build hash refuses")
                .kind,
            "template-pin"
        );
        let other = if backend == BoxBackend::Codex {
            BoxBackend::Claude
        } else {
            BoxBackend::Codex
        };
        let mut unrelated = record.clone();
        unrelated[other.vendor().hash_key] = json!("unrelated");
        unrelated[other.vendor().program_key] = json!("/unrelated");
        crate::launch::check_backend_pin_records(backend, &record, &record, &unrelated, template)
            .expect("unselected evidence cannot substitute for selected pins");
        if backend == BoxBackend::Claude {
            unrelated["claude_template_dir"] = json!("/another-loop/template");
            assert_eq!(
                crate::launch::check_backend_pin_records(
                    backend, &record, &record, &unrelated, template
                )
                .expect_err("generation template must be this selected root")
                .kind,
                "template-pin"
            );
        }
    }
}

/// ´test:crate:boxed-backend-mixed-templates-use-selected-vendor-root´
#[test]
fn boxed_backend_mixed_templates_use_selected_vendor_root() {
    let home = std::path::Path::new("/fixture/owner");
    let root = home.join(".var/loops/alpha");
    let hash = "a".repeat(64);
    let mut settings = backend_settings(&["codex", "claude"]);
    settings.driver_argv = vec!["/fixture/driver".into()];
    settings.driver_bin = Some("/fixture/driver".into());
    settings.image_digest = Some(format!("sha256:{hash}"));
    settings.template_dir = Some(root.join("runner-templates/codex").join(&hash));
    settings.socket_dir = Some(root.join("sockets"));
    for backend in [BoxBackend::Codex, BoxBackend::Claude] {
        let mut plan = crate::plan::Plan::build_with_door(
            home,
            "alpha",
            "R",
            &settings,
            &super::fixture_row(),
            super::fixture_block(),
            (1000, 1000),
            false,
            Some(backend),
        )
        .expect("selected layout");
        crate::launch::check_mount_roots(&plan, &settings, home).expect("selected installed roots");
        let template = root
            .join("runner-templates")
            .join(backend.name())
            .join(&hash);
        let config = backend.template_files()[0];
        assert!(
            plan.document["mounts"]
                .as_array()
                .expect("mounts")
                .iter()
                .any(
                    |row| row["source"] == template.join(config).to_str().expect("path")
                        && row["target"] == format!("{}/{config}", backend.state_home())
                )
        );
        let other = if backend == BoxBackend::Codex {
            "claude"
        } else {
            "codex"
        };
        plan.document["mounts"].as_array_mut().expect("mounts").push(json!({
            "kind":"bind", "source":root.join("runner-templates").join(other).join(&hash).join("foreign"),
            "target":"/foreign", "access":"ro"}));
        assert_eq!(
            crate::launch::check_mount_roots(&plan, &settings, home)
                .expect_err("other vendor template refuses")
                .kind,
            "mount-source"
        );
    }
}

/// ´test:crate:boxed-backend-claude-pin-check-reads-selected-template´
#[test]
fn boxed_backend_claude_pin_check_reads_selected_template() {
    let fixture = TempDir::new().expect("fixture");
    let home = fixture.path();
    let root = home.join(".var/loops/alpha");
    let hash = "a".repeat(64);
    let image = format!("sha256:{hash}");
    let template = root.join("runner-templates/claude").join(&hash);
    fs::create_dir_all(template.join("bin")).expect("template");
    for (name, bytes, mode) in [
        ("bin/claude", "fictional payload", 0o550),
        ("settings.json", "{}", 0o440),
        ("CLAUDE.md", "fictional charter", 0o440),
    ] {
        fs::write(template.join(name), bytes).expect("fixture file");
        fs::set_permissions(template.join(name), fs::Permissions::from_mode(mode)).expect("mode");
    }
    let manifest = json!({"image_digest":image,
        "claude_sha256":sha256(&template.join("bin/claude")).expect("hash"),
        "config_sha256":"b".repeat(64),
        "charter_sha256":sha256(&template.join("CLAUDE.md")).expect("hash")});
    fs::write(
        template.join("manifest"),
        serde_json::to_vec(&manifest).expect("manifest"),
    )
    .expect("manifest file");
    fs::set_permissions(template.join("manifest"), fs::Permissions::from_mode(0o440))
        .expect("mode");
    let mut settings = backend_settings(&["codex", "claude"]);
    settings.image_digest = Some(image);
    settings.template_dir = Some(root.join("runner-templates/codex").join(&hash));
    let plan = crate::plan::Plan {
        home: home.join("worker"),
        driver_dir: root.join("runs/R"),
        letter: home.join("letter"),
        document: json!({"loop":"alpha", "backend":"claude"}),
    };
    let error = crate::launch::check_pins(&plan, &settings, home, false, false)
        .expect_err("selected config digest differs");
    assert_eq!(error.kind, "template-pin");
    assert_eq!(
        error.detail,
        format!(
            "{} differs from manifest config_sha256",
            template.join("settings.json").display()
        )
    );
    assert!(
        !settings
            .template_dir
            .as_ref()
            .expect("primary template")
            .exists()
    );
}

/// ´test:crate:boxed-backend-protected-plan-refuses-missing-or-changed-vendor´
#[test]
fn boxed_backend_protected_plan_refuses_missing_or_changed_vendor() {
    let plan = super::gate_fixture();
    assert_eq!(plan["backend"], "codex");
    crate::plan::box_gate(&plan).expect("Codex control");
    for value in [json!(null), json!(4), json!("other"), json!("claude")] {
        let mut changed = plan.clone();
        changed["backend"] = value.clone();
        let error = crate::plan::box_gate(&changed).expect_err("backend must be bound");
        assert_eq!(
            error.kind,
            if value == "claude" {
                "box-gate"
            } else {
                "backend-selection"
            }
        );
        let record = json!({"plan": changed});
        let error = crate::launch::pinned_plan_from_record(
            std::path::Path::new("/absent-owner"),
            "alpha",
            "R",
            std::path::Path::new("/absent-container"),
            &record,
        )
        .expect_err("never silently select Codex");
        assert_eq!(
            error.kind,
            if value == "claude" {
                "backend-unavailable"
            } else {
                "backend-selection"
            }
        );
    }
    let mut absent = plan;
    absent
        .as_object_mut()
        .expect("plan object")
        .remove("backend");
    assert_eq!(
        crate::plan::box_gate(&absent)
            .expect_err("old plans need retirement")
            .kind,
        "backend-selection"
    );
}

/// ´test:crate:boxed-backend-home-refuses-before-writing-any-path´
#[test]
fn boxed_backend_home_refuses_before_writing_any_path() {
    let fixture = TempDir::new().expect("fixture");
    let parent: std::os::fd::OwnedFd = fs::File::open(fixture.path())
        .expect("fixture parent")
        .into();
    let caller = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    for value in [json!(null), json!("claude"), json!("other")] {
        let mut document = super::gate_fixture();
        document["backend"] = value.clone();
        let plan = crate::plan::Plan {
            home: fixture.path().join("home"),
            driver_dir: fixture.path().join("run"),
            letter: fixture.path().join("letter"),
            document,
        };
        let error = crate::home::make_home_pinned(
            &plan,
            &backend_settings(&["codex", "claude"]),
            b"",
            caller,
            &parent,
            &parent,
        )
        .expect_err("unsupported or unbound backend");
        assert_eq!(
            error.kind,
            if value == "claude" {
                "backend-layout"
            } else {
                "backend-selection"
            }
        );
        assert_eq!(
            fs::read_dir(fixture.path()).expect("empty fixture").count(),
            0
        );
    }
}

/// ´test:crate:boxed-backend-credential-refusal-precedes-custody-access´
#[test]
fn boxed_backend_credential_refusal_precedes_custody_access() {
    let fixture = TempDir::new().expect("fixture");
    let missing = fixture.path().join("absent-owner");
    let run = fixture.path().join("absent-run");
    assert_eq!(
        crate::credential::preflight(&missing, "alpha", BoxBackend::Claude)
            .expect_err("no Claude credential adapter")
            .kind,
        "backend-unavailable"
    );
    let error = crate::credential::prepare_run(&missing, "alpha", &run, 3000, BoxBackend::Claude)
        .expect_err("Claude has no adapter");
    assert_eq!(error.kind, "backend-unavailable");
    let mut record = json!({"plan":{"backend":"claude","home":run},"worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch"}]});
    let error = crate::container_helper::publish_round_credential_admitted(
        &missing,
        "alpha",
        &mut record,
        &Gate,
    )
    .expect_err("wrong credential adapter");
    assert_eq!(error.kind, "backend-unavailable");
    assert!(record["rounds"][0]["credential_publication"].is_null());
    assert!(!missing.exists());
    assert!(!run.exists());
}

/// ´test:crate:boxed-backend-codex-only-selects-its-own-program´
#[test]
fn boxed_backend_codex_only_selects_its_own_program() {
    let settings = backend_settings(&["codex"]);
    for requested in [None, Some(BoxBackend::Codex)] {
        let backend = settings.launch_backend(requested).expect("Codex selection");
        assert_eq!(backend, BoxBackend::Codex);
        backend.require_runtime().expect("implemented runtime");
    }
    let error = settings
        .launch_backend(Some(BoxBackend::Claude))
        .expect_err("no fallback");
    assert_eq!(error.kind, "missing-setting");
    assert!(error.detail.contains("backend_argv.claude"));
}

/// ´test:crate:boxed-backend-claude-only-refuses-unimplemented-runtime´
#[test]
fn boxed_backend_claude_only_refuses_unimplemented_runtime() {
    let settings = backend_settings(&["claude"]);
    for requested in [None, Some(BoxBackend::Claude)] {
        let backend = settings
            .launch_backend(requested)
            .expect("Claude selection");
        assert_eq!(backend, BoxBackend::Claude);
        let error = backend
            .require_runtime()
            .expect_err("Claude runtime remains incomplete");
        assert_eq!(error.kind, "backend-unavailable");
        assert!(error.detail.contains("claude"));
    }
    assert!(settings.launch_backend(Some(BoxBackend::Codex)).is_err());
}

/// ´test:crate:boxed-backend-mixed-configuration-keeps-explicit-selection´
#[test]
fn boxed_backend_mixed_configuration_keeps_explicit_selection() {
    let settings = backend_settings(&["claude", "codex"]);
    assert_eq!(
        settings.launch_backend(None).expect("default"),
        BoxBackend::Codex
    );
    for backend in [BoxBackend::Claude, BoxBackend::Codex] {
        assert_eq!(
            settings
                .launch_backend(Some(backend))
                .expect("explicit vendor"),
            backend
        );
    }
    assert_eq!(
        settings
            .launch_backend(Some(BoxBackend::Claude))
            .expect("Claude selected")
            .require_runtime()
            .expect_err("must not run Codex instead")
            .kind,
        "backend-unavailable"
    );
}

/// ´test:crate:boxed-backend-absent-program-never-uses-endpoints-as-a-selector´
#[test]
fn boxed_backend_absent_program_never_uses_endpoints_as_a_selector() {
    let mut settings = backend_settings(&[]);
    settings
        .vendor_hosts
        .insert("claude".into(), vec!["api.example.com".into()]);
    let unselected = settings.launch_backend(None).expect_err("no program");
    assert_eq!(unselected.kind, "missing-setting");
    assert_eq!(unselected.detail, "backend_argv has no configured program");
    for backend in [BoxBackend::Codex, BoxBackend::Claude] {
        let error = settings
            .launch_backend(Some(backend))
            .expect_err("no program");
        assert_eq!(error.kind, "missing-setting");
        assert_eq!(
            error.detail,
            format!("backend_argv.{} is absent or empty", backend.name())
        );
    }
    for argv in [Vec::new(), vec!["relative-program".into()]] {
        settings.backend_argv.insert("claude".into(), argv);
        assert_eq!(
            settings
                .launch_backend(Some(BoxBackend::Claude))
                .expect_err("invalid program")
                .kind,
            "missing-setting"
        );
    }
}

/// ´test:crate:boxed-backend-parser-refuses-unknown-repeated-and-resume-selectors´
#[test]
fn boxed_backend_parser_refuses_unknown_repeated_and_resume_selectors() {
    for (name, backend) in [("codex", BoxBackend::Codex), ("claude", BoxBackend::Claude)] {
        let args = [
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--backend",
            name,
        ]
        .map(String::from);
        assert_eq!(
            LaunchRequest::parse(&args).expect("vendor flag").backend,
            Some(backend)
        );
        let mut repeated = args.to_vec();
        repeated.extend(["--backend".into(), name.into()]);
        assert_eq!(
            LaunchRequest::parse(&repeated).expect_err("duplicate").kind,
            "usage"
        );
        let args = ["alpha", "R", "--round", "work", "--backend", name].map(String::from);
        assert_eq!(
            LaunchRequest::parse(&args)
                .expect_err("resume cannot select vendor")
                .kind,
            "round-selection"
        );
    }
    let args = [
        "alpha",
        "R",
        "--letter",
        "/fixture/letter",
        "--backend",
        "other",
    ]
    .map(String::from);
    let unknown = LaunchRequest::parse(&args).expect_err("unknown");
    assert_eq!(unknown.kind, "backend-selection");
    assert!(unknown.detail.contains("other"));
    assert_eq!(
        LaunchRequest::parse(&args[..5])
            .expect_err("missing value")
            .kind,
        "usage"
    );
}

/// ´test:crate:boxed-backend-refusal-precedes-allocation-and-program-probes´
#[test]
fn boxed_backend_refusal_precedes_allocation_and_program_probes() {
    let fixture = TempDir::new().expect("owner home");
    let home = fixture.path();
    let config = home.join(".config/loops/alpha");
    fs::create_dir_all(&config).expect("settings parent");
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        config.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory");
    }
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n").expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let path = config.join("workers.toml");
    for vendors in [
        "claude = [\"/fixture/claude\"]",
        "codex = [\"/fixture/codex\"], claude = [\"/fixture/claude\"]",
    ] {
        fs::write(&path, format!("backend_argv = {{ {vendors} }}\n"))
            .expect("vendor configuration");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("settings mode");
        let error = crate::load_launch_plan(home, "alpha", "R", (0, 0), Some(BoxBackend::Claude))
            .expect_err("do not reach allocation, template or executable probes");
        assert_eq!(error.kind, "backend-unavailable");
        assert!(!home.join(".var").exists());
        assert!(!home.join(".config/loops/allocations.toml").exists());
        let args = [
            "launch",
            "alpha",
            "R",
            "--letter",
            "/fixture/letter",
            "--backend",
            "claude",
        ]
        .map(String::from);
        let error = crate::launch::reaping::scope_preflight_with(home, &args, |_| {
            panic!("backend refusal must precede the proxy probe")
        })
        .expect_err("outer scope refuses Claude before effects");
        assert_eq!(error.kind, "backend-unavailable");
    }
}

/// ´test:crate:boxed-backend-record-readers-do-not-use-launch-readiness´
#[test]
fn boxed_backend_record_readers_do_not_use_launch_readiness() {
    let fixture = TempDir::new().expect("owner home");
    let home = fixture.path();
    let config = home.join(".config/loops/alpha");
    fs::create_dir_all(&config).expect("configuration");
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        config.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory");
    }
    let path = config.join("workers.toml");
    fs::write(&path, "backend_argv = { claude = [\"/fixture/claude\"] }\n")
        .expect("Claude-only settings");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private settings");
    let error = crate::load_plan(home, "alpha", "R", (0, 0))
        .expect_err("operator preview reaches the absent registry");
    assert_eq!(error.kind, "registry-row");
    let error = crate::load_plan_for_record(home, "alpha", "R", (0, 0))
        .expect_err("legacy reader keeps its missing Codex refusal");
    assert_eq!(error.kind, "missing-setting");
    assert_eq!(error.detail, "backend_argv.codex is absent or empty");
    let error = crate::load_launch_plan(home, "alpha", "R", (0, 0), None)
        .expect_err("new Claude launch remains gated before registry access");
    assert_eq!(error.kind, "backend-unavailable");
    assert!(!home.join(".config/loops/registry.toml").exists());
    assert!(!home.join(".var").exists());
}

/// ´test:crate:boxed-backend-claude-layout-is-vendor-specific-and-not-executable´
#[test]
fn boxed_backend_claude_layout_is_vendor_specific_and_not_executable() {
    for vendors in [&["claude"][..], &["codex", "claude"][..]] {
        let mut settings = backend_settings(vendors);
        settings.driver_argv = vec!["/fixture/superloop-lane".into()];
        settings.driver_bin = Some("/fixture/superloop-lane".into());
        settings.template_dir = Some("/fixture/claude-template".into());
        let plan = crate::plan::Plan::build_with_door(
            std::path::Path::new("/fixture/owner"),
            "alpha",
            "R",
            &settings,
            &super::fixture_row(),
            super::fixture_block(),
            (1000, 1000),
            false,
            Some(BoxBackend::Claude),
        )
        .expect("Claude layout");
        assert_eq!(plan.document["backend"], "claude");
        assert_eq!(
            plan.document["environment"]["CLAUDE_CONFIG_DIR"],
            "/home/worker/.claude"
        );
        assert!(plan.document["environment"]["CODEX_HOME"].is_null());
        assert!(
            plan.document["runtime_argv"]
                .as_array()
                .expect("vector")
                .iter()
                .any(|word| word == "/home/worker/.local/bin/claude")
        );
        assert_eq!(plan.document["owner_refresh_hosts"], json!([]));
        assert_eq!(plan.document["box_gate"]["verdict"], "passed");
        assert_eq!(
            crate::plan::verify_box_attestation(&plan.document)
                .expect_err("layout is never runtime acceptance")
                .kind,
            "backend-unavailable"
        );
        let mounts = plan.document["mounts"].as_array().expect("mounts");
        for (target, access) in [
            ("/home/worker", "ro"),
            ("/home/worker/.claude", "rw"),
            ("/home/worker/.claude/settings.json", "ro"),
            ("/home/worker/.claude/CLAUDE.md", "ro"),
        ] {
            assert!(
                mounts
                    .iter()
                    .any(|row| row["target"] == target && row["access"] == access)
            );
        }
        assert!(!plan.json().expect("layout JSON").contains("codex"));
        for field in ["backend", "environment"] {
            let mut changed = plan.document.clone();
            if field == "backend" {
                changed[field] = json!("codex");
            } else {
                changed[field]["CODEX_HOME"] = json!("/home/worker/.codex");
            }
            assert_eq!(
                crate::plan::verify_home_layout(&changed)
                    .expect_err("cross-vendor state")
                    .kind,
                "backend-layout"
            );
        }
    }
}

/// ´test:crate:boxed-backend-claude-home-creates-only-its-state-and-immutable-mountpoints´
#[test]
fn boxed_backend_claude_home_creates_only_its_state_and_immutable_mountpoints() {
    let fixture = TempDir::new().expect("home fixture");
    let root = fixture.path();
    fs::create_dir_all(root.join(".cache/tmp")).expect("home parent");
    fs::create_dir(root.join("runs")).expect("runs parent");
    let settings = backend_settings(&["claude"]);
    let row = json!({"name":"alpha","uid":41001,"runs_root":root.join("runs")});
    let caller = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let plan = crate::plan::Plan::build_with_door(
        root,
        "alpha",
        "R",
        &settings,
        &row,
        super::fixture_block(),
        caller,
        false,
        Some(BoxBackend::Claude),
    )
    .expect("Claude layout");
    let home_parent: std::os::fd::OwnedFd = fs::File::open(root.join(".cache/tmp"))
        .expect("home parent")
        .into();
    let runs_parent: std::os::fd::OwnedFd = fs::File::open(root.join("runs"))
        .expect("runs parent")
        .into();
    let report = crate::home::make_home_pinned(
        &plan,
        &settings,
        b"Fixture brief.\n",
        caller,
        &home_parent,
        &runs_parent,
    )
    .expect("make Claude layout");
    let state = plan.home.join(".claude");
    assert_eq!(
        fs::metadata(&state).expect("state").permissions().mode() & 0o777,
        0o700
    );
    let mut names: Vec<_> = fs::read_dir(&state)
        .expect("state entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["CLAUDE.md", "settings.json"]);
    for name in ["CLAUDE.md", "settings.json"] {
        let path = state.join(name);
        assert_eq!(fs::read(&path).expect("empty mountpoint"), [] as [u8; 0]);
        assert_eq!(
            fs::metadata(&path)
                .expect("mountpoint")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!plan.home.join(".codex").exists());
    assert!(!plan.home.join(".local/sign-in").exists());
    let created = report["created"].as_array().expect("created paths");
    let state_row = created
        .iter()
        .find(|row| row["path"] == state.display().to_string())
        .expect("state report");
    assert_eq!(state_row["wanted"]["uid"], 3000);
    assert_eq!(state_row["wanted"]["gid"], 3000);
    assert_eq!(fs::read(&plan.letter).expect("brief"), b"Fixture brief.\n");
}

fn run(
    home: &std::path::Path,
    request: &LaunchRequest,
) -> Result<serde_json::Value, crate::error::LaneError> {
    run_with_host_root_and_proxy(
        home,
        request,
        home,
        nix::unistd::Uid::effective().as_raw(),
        |_| Ok(("active".into(), "fixture-invocation".into())),
    )
}

fn record_hosts_with_lane_bin(
    home: &std::path::Path,
    request: &RecordHostsRequest,
    lane_bin: &std::path::Path,
) -> Result<serde_json::Value, crate::error::LaneError> {
    record_hosts_with_lane_bin_from(
        home,
        request,
        lane_bin,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
}

fn executable(path: &std::path::Path, source: &str) {
    let source = if path.file_name().is_some_and(|name| name == "entry-fixture") {
        let (interpreter, body) = source.split_once('\n').expect("entry fixture header");
        match interpreter {
            "#!/bin/sh" => format!(
                "#!/bin/sh\nif [ \"$1 $2\" = 'driver-launch --interface-version' ]; then printf '%s\\n' '{ENTRY_INTERFACE_PROBE}'; exit 0; fi\n{body}"
            ),
            "#!/usr/bin/python3" => format!(
                "#!/usr/bin/python3\nimport sys\nif sys.argv[1:] == ['driver-launch', '--interface-version']:\n    print('{ENTRY_INTERFACE_PROBE}')\n    sys.exit(0)\n{body}"
            ),
            _ => panic!("entry fixture interpreter is not declared"),
        }
    } else {
        source.to_owned()
    };
    crate::fixture_exec::write_executable(path, source.as_bytes())
        .expect("closed and synced fixture program");
}

struct RestoreDriver(std::path::PathBuf);

impl Drop for RestoreDriver {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o700),
        ));
    }
}

/// ´test:crate:launch-parser-uses-installed-proxy-by-default´
#[test]
fn launch_parser_uses_installed_proxy_by_default() {
    let request =
        LaunchRequest::parse(&["alpha", "R", "--letter", "/tmp/dispatch.md"].map(String::from))
            .expect("launch form");
    assert!(request.proxy_bin.is_none());
    let digest = "a".repeat(64);
    let args = [
        "alpha",
        "R",
        "--letter",
        "/tmp/dispatch.md",
        "--expect-digest",
        &digest,
    ]
    .map(String::from);
    assert_eq!(
        LaunchRequest::parse(&args)
            .expect("recovery digest")
            .expect_digest
            .as_deref(),
        Some(digest.as_str())
    );
    let mut preview = args.to_vec();
    preview.push("--dry-run".into());
    assert_eq!(
        LaunchRequest::parse(&preview)
            .expect_err("digest is apply-only")
            .kind,
        "settlement-digest"
    );
    let mut malformed = args;
    malformed[5] = "not-a-digest".into();
    assert_eq!(
        LaunchRequest::parse(&malformed)
            .expect_err("invalid digest")
            .kind,
        "settlement-digest"
    );
}

fn assert_resume_plan_pin(home: &std::path::Path, request: &mut LaunchRequest) {
    let selection = json!({"model":"gpt-6-sol","effort":"high"});
    request.round = Some("work".into());
    for worker in [3000, 3001] {
        let (mut plan, _) = crate::load_plan(home, "alpha", "R", (0, 0)).expect("current plan");
        plan.select_worker_uid(worker).expect("reserved identity");
        plan.select_mail_group(43001 + worker - 3000)
            .expect("mail group");
        let birth = loop_home::mail::birth::Identity::for_reservation(
            worker,
            format!("superloop-lane:{}", "R"),
        );
        plan.select_mailbox(
            &home
                .join(".var/loops/alpha/workers")
                .join(&birth.name)
                .join("mail"),
            &birth,
            61000,
        )
        .expect("mail mount");
        plan.select_container_program(&request.podman_bin)
            .expect("runtime");
        plan.select_launch_model(&selection).expect("selection");
        let path = plan
            .driver_dir
            .parent()
            .expect("runs")
            .join(".reservation-R.json");
        for (door, floor, keys) in [
            (true, false, "door"),
            (false, true, "door_floor"),
            (true, true, "door, door_floor"),
            (false, false, ""),
        ] {
            let mut recorded = plan.document.clone();
            if door {
                recorded["door"]["stub_sha256"] = json!("0".repeat(64));
            }
            if floor {
                recorded["door_floor"] = json!("enforce");
            }
            let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,"plan":recorded,"model_selection":selection});
            for dry_run in [true, false] {
                crate::launch::publish_reservation(&path, &record).expect("saved plan");
                let before = fs::read(&path).expect("record bytes");
                let calls = fs::read(home.join("container-calls")).unwrap_or_default();
                request.dry_run = dry_run;
                let error = run(home, request).expect_err("mismatch or missing round letters");
                if keys.is_empty() {
                    assert_ne!(
                        error.kind, "plan-read",
                        "unchanged plan passes admission: {error:?}"
                    );
                    let lock = path.parent().expect("runs").join(".letter-R.lock");
                    if lock.exists() {
                        fs::remove_file(lock).expect("remove fixture mailbox lock");
                    }
                } else {
                    assert_eq!(error.kind, "plan-read");
                    let route = match keys {
                        "door" => {
                            "preview launch LOOP RUN --repin-door --dry-run; review both door objects and preview_sha256; apply launch LOOP RUN --repin-door --expect-digest HEX; then repeat the ordinary resume dry run"
                        }
                        "door_floor" => {
                            "reconcile the named pinned inputs with the protected plan before repeating the ordinary resume dry run; do not rewrite the protected plan to bypass the mismatch"
                        }
                        "door, door_floor" => {
                            "first reconcile the named non-door pinned inputs; repinning refuses non-door drift; then preview launch LOOP RUN --repin-door --dry-run; review both door objects and preview_sha256; apply launch LOOP RUN --repin-door --expect-digest HEX; then repeat the ordinary resume dry run"
                        }
                        _ => panic!("unexpected differing keys: {keys}"),
                    };
                    assert_eq!(
                        error.detail,
                        format!(
                            "protected plan differs from the current pinned plan; differing keys: {keys}; {route}"
                        )
                    );
                    assert_eq!(fs::read(&path).expect("unchanged record"), before);
                    assert_eq!(
                        fs::read(home.join("container-calls")).unwrap_or_default(),
                        calls
                    );
                    assert!(!path.parent().expect("runs").join(".letter-R.lock").exists());
                }
            }
        }
        fs::remove_file(&path).expect("remove pin fixture");
    }
    request.round = None;
    request.dry_run = false;
}

#[allow(clippy::too_many_lines)]
fn assert_dead_dispatch_attempt_wall(home: &std::path::Path, request: &LaunchRequest) {
    let calls = fs::read(home.join("container-calls")).expect("prior runtime calls");
    let settings = home.join(".config/loops/alpha/workers.toml");
    let source = fs::read_to_string(&settings).expect("settings");
    fs::write(&settings, format!("{source}attempt_wall_seconds = 12\n")).expect("explicit wall");
    let (mut plan, _) = crate::load_plan(home, "alpha", "R", (0, 0)).expect("configured plan");
    let selection = json!({"model":request.model,"effort":request.effort,"model_source":"launch-flag","effort_source":"launch-flag"});
    plan.select_worker_uid(3000).expect("worker");
    plan.select_mail_group(43001).expect("mail group");
    let birth =
        loop_home::mail::birth::Identity::for_reservation(3000, format!("superloop-lane:{}", "R"));
    plan.select_mailbox(
        &home
            .join(".var/loops/alpha/workers")
            .join(&birth.name)
            .join("mail"),
        &birth,
        61000,
    )
    .expect("mail mount");
    plan.select_container_program(&request.podman_bin)
        .expect("runtime");
    plan.select_launch_model(&selection).expect("model");
    plan.observe_vendor().expect("observing recovery");
    assert_eq!(plan.document["attempt_wall_seconds"], 12);
    let workspace = super::published_workspace();
    plan.document["compute_workspace"] = workspace.clone();
    plan.document["compute_placement"] = super::published_placement();
    let path = plan
        .driver_dir
        .parent()
        .expect("runs")
        .join(".reservation-R.json");
    let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":plan.document,"model_selection":selection,"letter_source":request.letter,"launcher_pid":crate::dead_pid::DEAD_LOCK_PID,"launcher_start":1,"driver_entry_pid":crate::dead_pid::DEAD_LOCK_PID + 1,"driver_entry_start":1,"helper_pid":crate::dead_pid::DEAD_LOCK_PID + 2,"helper_start":1,"helper_parent_pid":crate::dead_pid::DEAD_LOCK_PID + 3,"helper_parent_start":1,"observer_state":"running","observer_pid":crate::dead_pid::DEAD_LOCK_PID + 4,"observer_start":1});
    crate::launch::publish_reservation(&path, &record).expect("dead dispatch");
    let custody = crate::plan::protected_identity_dir(&plan.driver_dir).expect("custody path");
    fs::create_dir(&custody).expect("custody");
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
    fs::write(&settings, format!("{source}attempt_wall_seconds = 24\n")).expect("changed policy");
    fs::create_dir(&plan.driver_dir).expect("dead driver directory");
    fs::set_permissions(&plan.driver_dir, fs::Permissions::from_mode(0o700))
        .expect("protected driver directory");
    let helper_sockets = [
        crate::container_helper::socket_path(&plan.driver_dir).expect("request socket"),
        crate::container_helper::control_socket_path(&plan.driver_dir).expect("control socket"),
    ];
    for (socket, mode) in helper_sockets.iter().zip([0o660, 0o600]) {
        let slot = crate::SocketSlot::pinned(socket, nix::unistd::Uid::effective().as_raw())
            .expect("pinned helper socket");
        drop(std::os::unix::net::UnixListener::bind(slot.address()).expect("dead helper socket"));
        slot.set_owner_mode(
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
            mode,
        )
        .expect("socket mode");
    }
    let preview = run(home, request).expect("dead dispatch retains pinned wall");
    assert_eq!(
        preview["plan"]["compute_placement"],
        record["plan"]["compute_placement"]
    );
    assert_eq!(preview["plan"]["attempt_wall_seconds"], 12);
    assert_eq!(
        preview["interrupted_settlement"]["state"],
        "would-complete-interrupted-settlement"
    );
    assert_eq!(
        preview["interrupted_settlement"]["helper_sockets_to_remove"],
        json!(helper_sockets)
    );
    assert!(helper_sockets.iter().all(|socket| socket.exists()));
    assert_eq!(
        crate::launch::read_reservation(&path)
            .expect("read")
            .expect("record"),
        record
    );
    let original_runtime = fs::read_to_string(&request.podman_bin).expect("runtime source");
    let container = json!({"id":"b".repeat(64),"name":"superloop-lane-alpha-R-attempt-1",
        "labels":{"org.superloop.loop":"alpha","org.superloop.run":"R"},
        "state":{"Status":"exited","Running":false,"Paused":false,"Restarting":false,"Pid":0,"ExitCode":143,"FinishedAt":"2026-10-18T00:00:00Z"}});
    executable(
        &request.podman_bin,
        &format!(
            "#!/bin/sh\ncase \"$1\" in\nps) printf '%s\\n' '{}'; exit 0;;\ncontainer) test \"$2\" = inspect && test \"$#\" = 3 && test \"$3\" = '{}' || exit 9; printf '%s\\n' '{}'; exit 0;;\nrm) echo unexpected-removal >&2; exit 97;;\nesac\n{}",
            "b".repeat(64),
            "b".repeat(64),
            json!([{"Id":container["id"],"Name":container["name"],"Config":{"Labels":container["labels"]},"State":container["state"]}]),
            original_runtime
                .strip_prefix("#!/bin/sh\n")
                .expect("shell runtime")
        ),
    );
    let exited = run(home, request)
        .expect("original launch previews exited container through installed pins");
    assert_eq!(
        exited["interrupted_settlement"]["containers_to_remove"],
        json!([container])
    );
    assert!(exited["interrupted_settlement"]["preview_sha256"].is_string());
    assert_eq!(exited["plan"]["compute_workspace"], workspace);
    assert_eq!(
        crate::launch::read_reservation(&path)
            .expect("read")
            .expect("record"),
        record
    );
    executable(&request.podman_bin, &original_runtime);
    fs::remove_file(path).expect("remove recovery fixture");
    for socket in helper_sockets {
        fs::remove_file(socket).expect("remove fixture socket");
    }
    fs::remove_dir(&plan.driver_dir).expect("remove fixture driver directory");
    fs::remove_dir(custody).expect("remove recovery custody");
    fs::write(settings, source).expect("restore settings");
    fs::write(home.join("container-calls"), calls).expect("restore runtime call evidence");
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn assert_claude_dry_run(
    home: &Path,
    request: &mut LaunchRequest,
    settings_path: &Path,
    custody: &Path,
    runs: &Path,
    codex_template: &Path,
    image: &str,
) {
    fs::remove_file(custody.join("door-install-generation.json"))
        .expect("no Codex door generation");
    fs::remove_file(custody.join("door-service")).expect("no Codex door service");
    let template = codex_template
        .parent()
        .expect("image templates")
        .parent()
        .expect("template root")
        .join("claude")
        .join(codex_template.file_name().expect("image hash"));
    fs::create_dir_all(template.join("bin")).expect("Claude template bin");
    fs::create_dir_all(template.join("libexec")).expect("Claude template helpers");
    for (path, bytes, mode) in [
        (
            template.join("bin/claude"),
            b"fictional Claude program\n".as_slice(),
            0o550,
        ),
        (template.join("settings.json"), b"{}\n".as_slice(), 0o440),
        (
            template.join("CLAUDE.md"),
            b"fictional charter\n".as_slice(),
            0o440,
        ),
        (
            template.join("libexec/box-init"),
            b"fixed init\n".as_slice(),
            0o440,
        ),
    ] {
        fs::write(&path, bytes).expect("Claude template file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("Claude pin mode");
    }
    let claude_hash = sha256(&template.join("bin/claude")).expect("Claude hash");
    let config_hash = sha256(&template.join("settings.json")).expect("settings hash");
    let charter_hash = sha256(&template.join("CLAUDE.md")).expect("charter hash");
    let manifest = json!({"image_digest":image,"claude_sha256":claude_hash,
        "config_sha256":config_hash,"charter_sha256":charter_hash});
    let manifest_path = template.join("manifest");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o440)).expect("manifest mode");
    for directory in [
        template.join("bin"),
        template.join("libexec"),
        template.clone(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o550)).expect("template mode");
    }
    fs::set_permissions(
        template.parent().expect("vendor root"),
        fs::Permissions::from_mode(0o711),
    )
    .expect("vendor root mode");
    let original = fs::read_to_string(settings_path).expect("settings");
    let common = original
        .lines()
        .filter(|line| !line.starts_with("backend_argv = ") && !line.starts_with("vendor_hosts = "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        settings_path,
        format!(
            "{common}\nbackend_argv = {{ claude = [\"{}\"] }}\n",
            crate::build::payload::CLAUDE_IMAGE_PROGRAM
        ),
    )
    .expect("Claude settings");
    let report_path = custody.join("image-build.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("build report"))
            .expect("build report JSON");
    let help = [
        "  -p, --print",
        "  --output-format <format>  text, json or stream-json",
        "  --verbose",
        "  --permission-mode <mode>  acceptEdits, bypassPermissions, default or plan",
        "  --dangerously-skip-permissions",
        "  --model <model>",
        "  --effort <level>",
        "  -r, --resume [value]",
        "  -h, --help",
    ]
    .join("\n");
    report["claude_version"] = json!("0.1.0");
    report["claude_sha256"] = json!(claude_hash);
    report["claude_source"] = json!("https://fixture.example/claude");
    report["claude_image_program"] = json!(crate::build::payload::CLAUDE_IMAGE_PROGRAM);
    report["build_environment"]["claude_bin"] = json!(template.join("bin/claude"));
    report["claude_exec_probe"] = json!({"argv":["--help"],"stdout":help,
        "required_options":crate::build::payload::CLAUDE_EXEC_OPTIONS,
        "claude_sha256":claude_hash,"image_digest":image,"companions":[]});
    report["claude_runtime"] = json!({"image_digest":image,
        "interpreter":{"path":"/lib64/ld-linux-x86-64.so.2","sha256":"c".repeat(64)},
        "libraries":[{"path":"/lib64/libc.so.6","sha256":"d".repeat(64)}]});
    fs::write(
        &report_path,
        serde_json::to_vec(&report).expect("build JSON"),
    )
    .expect("Claude build report");
    let generation_path = custody.join("install-generation.json");
    let mut generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("generation"))
            .expect("generation JSON");
    generation["claude_sha256"] = json!(claude_hash);
    generation["claude_image_program"] = json!(crate::build::payload::CLAUDE_IMAGE_PROGRAM);
    generation["claude_template_dir"] = json!(template);
    fs::write(
        &generation_path,
        serde_json::to_vec(&generation).expect("generation JSON"),
    )
    .expect("Claude generation");
    let source_dir = custody.join("claude");
    fs::create_dir(&source_dir).expect("fictional source home");
    fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o700)).expect("source mode");
    let source = source_dir.join(".credentials.json");
    fs::write(&source, b"not a token document\n").expect("fictional invalid document");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source file mode");
    let source_before = fs::read(&source).expect("source before");
    request.run = "PreviewClaude".into();
    request.backend = Some(BoxBackend::Claude);
    request.observe = true;
    request.model = Some("fixture-claude".into());
    let mut broken = manifest.clone();
    broken["config_sha256"] = json!("f".repeat(64));
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o640)).expect("manifest edit");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&broken).expect("broken manifest"),
    )
    .expect("break template pin");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o440)).expect("manifest mode");
    let first = run(home, request).expect_err("installed pin refuses before admission");
    assert_eq!(first.kind, "template-pin", "{first:?}");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o640)).expect("manifest edit");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("restored manifest"),
    )
    .expect("restore template pin");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o440)).expect("manifest mode");
    let complete = run(home, request).expect_err("closed gate follows complete preview");
    assert_eq!(complete.kind, "backend-unavailable", "{complete:?}");
    assert!(
        complete.detail.contains("checked at the act"),
        "{complete:?}"
    );
    assert!(
        complete
            .detail
            .contains("all read-only launch preview checks passed")
    );
    assert!(
        complete
            .detail
            .contains("Claude driver contract is checked on launch")
    );
    let marker = source_dir.join(".boxed-refresh-mode");
    fs::write(&marker, b"refresh\n").expect("cutover request");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("mode marker");
    let cutover = run(home, request).expect_err("closed cutover refuses in preview");
    assert_eq!(cutover.kind, "credential-cutover-gate");
    fs::remove_file(&marker).expect("remove cutover request");
    let lock = source_dir.join(".refresh.lock");
    fs::write(&lock, b"").expect("unsafe existing lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).expect("unsafe lock mode");
    let unsafe_lock = run(home, request).expect_err("unsafe existing lock refuses");
    assert_eq!(unsafe_lock.kind, "credential-lock");
    fs::remove_file(&lock).expect("remove unsafe lock");
    let second_link = source_dir.join("linked-source");
    fs::hard_link(&source, &second_link).expect("second source link");
    let linked = run(home, request).expect_err("hard link is a reported fact");
    assert_eq!(linked.kind, "backend-unavailable");
    fs::remove_file(&second_link).expect("remove second link");
    assert_eq!(fs::read(&source).expect("source after"), source_before);
    assert!(!source_dir.join(".refresh.lock").exists());
    assert!(!runs.join(".reservation-PreviewClaude.json").exists());
    request.observe = false;
    let hosts = run(home, request).expect_err("selected vendor host list is required");
    assert_eq!(hosts.kind, "missing-setting");
    assert!(hosts.detail.contains("vendor_hosts.claude"));
    request.observe = true;
    request.dry_run = false;
    let closed = run(home, request).expect_err("changing launch remains gated first");
    assert_eq!(closed.kind, "backend-unavailable");
}

/// ´test:crate:public-preview-reads-dead-preparation-with-unreadable-driver´
#[test]
fn public_preview_reads_dead_preparation_with_unreadable_driver() {
    full_launch_preview_fixture(false);
}

/// ´test:crate:claude-dry-run-reaches-every-launch-check-before-the-gate´
#[test]
fn claude_dry_run_reaches_every_launch_check_before_the_gate() {
    full_launch_preview_fixture(true);
}

#[allow(clippy::too_many_lines)]
fn full_launch_preview_fixture(claude_preview: bool) {
    let fixture = ProtectedRoot::short_socket_root();
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
        .expect("host ancestor mode");
    let home_dir = fixture.path().join("home");
    fs::create_dir(&home_dir).expect("owner home");
    let home = home_dir.as_path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o711)).expect("host home mode");
    let custody = home.join(".config/loops/alpha");
    fs::create_dir_all(&custody).expect("custody");
    for path in [
        home.join(".config"),
        home.join(".config/loops"),
        custody.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("custody mode");
    }
    let runs = home.join(".var/loops/alpha/runs");
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    let sockets = home.join(".var/loops/alpha/sockets");
    let entry = home.join("entry-fixture");
    let podman = home.join("container-fixture");
    let driver = home.join("driver-fixture");
    let lane_bin = home.join("lane-fixture");
    let scratchpad = home.join("scratchpad");
    fs::create_dir(&scratchpad).expect("letter scratchpad");
    fs::set_permissions(&scratchpad, fs::Permissions::from_mode(0o700)).expect("scratchpad mode");
    let letter = scratchpad.join("first-letter");
    let observation = json!({"schema":1,"command":"observed-hosts","loop":"alpha","run":"R","mode":"observing","enforcing":false,"source":runs.join(".observed-R.txt"),"attempted_connect_hosts":{"api.example.com":true,"failed.example.com":false},"connected_hosts":["api.example.com"]});
    executable(&entry, "#!/bin/sh\nexit 0\n");
    executable(
        &podman,
        &format!(
            "#!/bin/sh\nprintf 'called\\n' >> '{}'\nif [ \"$1 $2\" = 'image inspect' ]; then printf '{}\\n'; exit 0; fi\nif [ \"$1\" = unshare ]; then printf '%s\\n' '{}'; exit 0; fi\nif [ \"$1\" = ps ]; then exit 0; fi\nexit 9\n",
            home.join("container-calls").display(),
            "a".repeat(64),
            observation
        ),
    );
    executable(
        &driver,
        "#!/bin/sh\nif [ \"$5\" = --runtime-contract ]; then\n  if [ \"$4\" = codex ]; then printf 'boxed-runtime 1\\n'; exit 0; fi\n  exit 2\nfi\nexit 0\n",
    );
    executable(&lane_bin, "#!/bin/sh\nexit 0\n");
    executable(&home.join("proxy-fixture"), "#!/bin/sh\nexit 0\n");
    fs::create_dir_all(&runs).expect("runs root");
    for path in [
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        runs.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private runs ancestor");
    }
    fs::create_dir_all(template.join("bin")).expect("template bin");
    fs::create_dir_all(template.join("libexec")).expect("template helper directory");
    fs::create_dir_all(sockets.join("vendor")).expect("vendor sockets");
    fs::create_dir_all(sockets.join("door")).expect("door sockets");
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))
        .expect("socket directory mode");
    fs::set_permissions(sockets.join("vendor"), fs::Permissions::from_mode(0o700))
        .expect("vendor socket directory mode");
    fs::set_permissions(sockets.join("door"), fs::Permissions::from_mode(0o750))
        .expect("door socket directory mode");
    fs::create_dir_all(custody.join("lanes/codex")).expect("sign-in place");
    fs::create_dir_all(home.join(".cache/tmp")).expect("home parent");
    fs::write(template.join("bin/codex"), "pinned codex\n").expect("codex pin");
    fs::write(template.join("bin/codex-code-mode-host"), "pinned host\n").expect("host pin");
    fs::write(
        template.join("config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    )
    .expect("policy pin");
    fs::write(template.join("AGENTS.md"), "A worker charter.\n").expect("charter pin");
    let data = home.join("image-data");
    fs::create_dir(&data).expect("image data");
    fs::write(data.join("box-init"), "fixed init\n").expect("init pin");
    fs::write(template.join("libexec/box-init"), "fixed init\n").expect("installed init pin");
    fs::write(template.join("libexec/ssh"), "keyless stub\n").expect("door stub pin");
    fs::write(custody.join("door-service"), "registered service\n").expect("door service pin");
    let image = format!("sha256:{}", "a".repeat(64));
    let codex_hash = sha256(&template.join("bin/codex")).expect("codex hash");
    let host_hash = sha256(&template.join("bin/codex-code-mode-host")).expect("host hash");
    fs::write(template.join("manifest"), serde_json::to_vec(&json!({"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"config_sha256":sha256(&template.join("config.toml")).expect("config hash"),"charter_sha256":sha256(&template.join("AGENTS.md")).expect("charter hash")})).expect("manifest")).expect("manifest file");
    for (path, mode) in [
        (home.join(".var/loops/alpha/runner-templates"), 0o711),
        (home.join(".var/loops/alpha/runner-templates/codex"), 0o711),
        (template.join("bin/codex"), 0o550),
        (template.join("bin/codex-code-mode-host"), 0o550),
        (template.join("config.toml"), 0o440),
        (template.join("AGENTS.md"), 0o440),
        (template.join("manifest"), 0o440),
        (template.join("bin"), 0o550),
        (template.join("libexec"), 0o550),
        (template.join("libexec/box-init"), 0o440),
        (template.join("libexec/ssh"), 0o550),
        (template.clone(), 0o550),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("installed pin mode");
    }
    fs::set_permissions(
        custody.join("door-service"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("door service mode");
    let image_program = "/usr/libexec/superloop/fixture-image-codex";
    assert!(!std::path::Path::new(image_program).exists());
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&json!({"package_inventory":[],"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_host_probe":{"argv":["--help"],"stdout":"host help","sha256":host_hash},"init_sha256":sha256(&data.join("box-init")).expect("init hash"),"codex_image_program":image_program,"build_environment":{"template_dir":data},"codex_exec_probe":{"argv":["exec","--help"],"stdout":"  -m, --model\n  -c, --config\n  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n","required_options":crate::build::CODEX_EXEC_OPTIONS,"codex_sha256":codex_hash,"companions":[{"name":"codex-code-mode-host","path":crate::build::CODEX_HOST_PATH,"sha256":host_hash}]}})).expect("report")).expect("report file");
    fs::write(custody.join("install-generation.json"), serde_json::to_vec(&json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_image_program":image_program,"proxy_bin":home.join("proxy-fixture"),"proxy_sha256":sha256(&home.join("proxy-fixture")).expect("proxy hash"),"init_sha256":sha256(&data.join("box-init")).expect("init hash")})).expect("generation")).expect("generation file");
    fs::write(&letter, "Read this letter.\n").expect("letter");
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display())).expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let allocations = home.join(".config/loops/allocations.toml");
    fs::write(
        &allocations,
        "mail_uid = 61000\n[alpha]\nuids = { base = 3000, count = 2 }\nmail_gids = { base = 43000, count = 3 }\n",
    )
    .expect("allocation");
    fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600)).expect("allocation mode");
    let settings = custody.join("workers.toml");
    let source = format!(
        "runs_root = \"{}\"\nentry_bin = \"{}\"\ndriver_argv = [\"{}\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nbackend_argv = {{ codex = [\"{}\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
        runs.display(),
        entry.display(),
        driver.display(),
        "a".repeat(64),
        template.display(),
        sockets.display(),
        image_program
    );
    fs::write(&settings, &source).expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    let door_generation = custody.join("door-install-generation.json");
    let stub_digest = sha256(&template.join("libexec/ssh")).expect("stub digest");
    fs::write(
        &door_generation,
        serde_json::to_vec(&json!({"schema":2,"agent":{"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"agent_expected_tokens":16384,"entry":"/fixture/entry","loop_home":"/fixture/home"},"phase":"complete","loop":"alpha","template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":sha256(&custody.join("door-service")).expect("service digest"),"unit_dir":custody.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw()})).expect("door generation"),
    )
    .expect("door generation file");
    fs::set_permissions(&door_generation, fs::Permissions::from_mode(0o600))
        .expect("door generation mode");
    fixture_work_route(home);
    let mut request = LaunchRequest {
        backend: None,
        loop_name: "alpha".into(),
        run: "R".into(),
        letter,
        round: None,
        thread_choice: None,
        budget: 3600,
        dry_run: true,
        expect_digest: None,
        compute_workspace: None,
        observe: false,
        podman_bin: podman,
        proxy_bin: Some(home.join("proxy-fixture")),
        model: Some("gpt-6-sol".into()),
        effort: Some("high".into()),
        door_scope: crate::door::Scope::Work,
        rotation_source: None,
    };
    if claude_preview {
        assert_claude_dry_run(
            home,
            &mut request,
            &settings,
            &custody,
            &runs,
            &template,
            &image,
        );
        return;
    }
    // Mutations of the recorded entry response exercise the production launcher,
    // with both preview and changing forms refusing before any run reservation.
    let accepted_entry = fs::read(&entry).expect("entry fixture");
    let allocation_before = fs::read(&allocations).expect("allocation snapshot");
    for response in [
        ENTRY_INTERFACE_PROBE.replace(
            env!("CARGO_PKG_VERSION"),
            concat!(env!("CARGO_PKG_VERSION"), "-incompatible"),
        ),
        ENTRY_INTERFACE_PROBE.replace(
            concat!(" ", env!("CARGO_PKG_VERSION"), " 1"),
            concat!(" ", env!("CARGO_PKG_VERSION"), " 0"),
        ),
        String::new(),
        "malformed".into(),
    ] {
        crate::fixture_exec::write_executable(
            &entry,
            format!("#!/bin/sh\nprintf '%s\\n' '{response}'\n").as_bytes(),
        )
        .expect("refusing entry");
        for dry_run in [true, false] {
            request.dry_run = dry_run;
            let error = run(home, &request).expect_err("entry mismatch refuses first");
            assert_eq!(error.kind, "entry-version");
            assert!(error.detail.contains(ENTRY_INTERFACE_PROBE), "{error:?}");
            assert!(error.detail.contains(&format!("{response:?}")), "{error:?}");
            assert_eq!(fs::read_dir(&runs).expect("runs root").count(), 0);
            assert!(!home.join("container-calls").exists());
            assert_eq!(
                fs::read(&allocations).expect("allocation unchanged"),
                allocation_before
            );
        }
    }
    // The version record is the production j01 --version capture; this
    // legacy stand-in deliberately omits only the new interface query.
    crate::fixture_exec::write_executable(&entry, concat!(r#"#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\n' '{"schema":1,"command":"superloop","kind":"version","message":"version requested","fields":{"type":"version","version":"superloop "#, env!("CARGO_PKG_VERSION"), r#""}}' >&2
    exit 0
fi
exit 2
"#).as_bytes()).expect("legacy entry");
    for dry_run in [true, false] {
        request.dry_run = dry_run;
        let error = run(home, &request).expect_err("legacy entry refuses before reservation");
        assert_eq!(error.kind, "entry-version");
        assert!(error.detail.contains(ENTRY_INTERFACE_PROBE), "{error:?}");
        assert!(
            error
                .detail
                .contains(concat!("superloop ", env!("CARGO_PKG_VERSION"))),
            "{error:?}"
        );
        assert!(error.detail.contains("interface unavailable"), "{error:?}");
        assert_eq!(fs::read_dir(&runs).expect("runs root").count(), 0);
        assert!(!home.join("container-calls").exists());
    }
    crate::fixture_exec::write_executable(&entry, &accepted_entry).expect("restore entry");
    request.dry_run = true;
    let refusal = run(home, &request).expect_err("empty list refuses enforcing launch");
    assert_eq!(refusal.kind, "missing-setting");
    assert!(refusal.detail.contains("vendor_hosts.codex"));
    fs::write(
        &settings,
        format!("{source}vendor_hosts = {{ codex = [\"api.example.com\"] }}\n"),
    )
    .expect("enforcing host list");
    let inactive = |_: &str| Ok(("inactive".into(), String::new()));
    let dead_preview = run_with_host_root_and_proxy(
        home,
        &request,
        home,
        nix::unistd::Uid::effective().as_raw(),
        inactive,
    )
    .expect_err("dead proxy refuses enforcing preview");
    assert_eq!(dead_preview.kind, "proxy-service-death");
    assert!(!runs.join(".letter-R.lock").exists());
    let scope_args = vec![
        "launch".into(),
        "alpha".into(),
        "R".into(),
        "--letter".into(),
        request.letter.display().to_string(),
    ];
    let dead_dispatch = crate::launch::reaping::scope_preflight_with(home, &scope_args, |_| {
        Ok(("inactive".into(), String::new()))
    })
    .expect_err("main dispatch refuses a dead unit before creating a mailbox lock");
    assert_eq!(dead_dispatch.kind, "proxy-service-death");
    assert_eq!(fs::read_dir(&runs).expect("runs root").count(), 0);
    request.dry_run = false;
    let dead_launch = run_with_host_root_and_proxy(
        home,
        &request,
        home,
        nix::unistd::Uid::effective().as_raw(),
        |_| Ok(("inactive".into(), String::new())),
    )
    .expect_err("dead proxy refuses launch before mailbox lock");
    assert_eq!(dead_launch.kind, "proxy-service-death");
    assert_eq!(fs::read_dir(&runs).expect("runs root").count(), 0);
    let saved = runs.join(".reservation-R.json");
    assert_resume_plan_pin(home, &mut request);
    crate::launch::publish_reservation(
        &saved,
        &json!({"schema":1,"phase":"settled","worker_uid":3000,"plan":{"vendor_mode":null}}),
    )
    .expect("settled fixture record");
    request.round = Some("work".into());
    let dead_round = run_with_host_root_and_proxy(
        home,
        &request,
        home,
        nix::unistd::Uid::effective().as_raw(),
        |_| Ok(("inactive".into(), String::new())),
    )
    .expect_err("dead proxy refuses resumed round before letter reconciliation");
    assert_eq!(dead_round.kind, "proxy-service-death");
    assert!(!runs.join(".letter-R.lock").exists());
    crate::launch::publish_reservation(
        &saved,
        &json!({"schema":1,"phase":"settled","worker_uid":3000,"plan":{"vendor_mode":"observing"}}),
    )
    .expect("observing round fixture record");
    let round_args = vec![
        "launch".into(),
        "alpha".into(),
        "R".into(),
        "--round".into(),
        "work".into(),
    ];
    assert!(
        !crate::launch::reaping::scope_preflight_with(home, &round_args, |_| {
            panic!("observing round read vendor proxy unit")
        })
        .expect("observing round proceeds to its own scope")
    );
    fs::remove_file(saved).expect("round fixture record removed");
    request.round = None;
    request.dry_run = true;
    fs::write(&settings, &source).expect("restore observing host list");
    request.observe = true;
    let mut observe_args = scope_args;
    observe_args.push("--observe".into());
    assert!(
        !crate::launch::reaping::scope_preflight_with(home, &observe_args, |_| {
            panic!("observe dispatch read vendor proxy unit")
        })
        .expect("observe launch proceeds to its own scope")
    );
    fs::write(
        &settings,
        source.replace(
            &template.display().to_string(),
            &home.join("outside-template").display().to_string(),
        ),
    )
    .expect("outside template setting");
    let outside = run(home, &request).expect_err("outside template root");
    assert_eq!(outside.kind, "mount-source");
    assert!(!home.join("container-calls").exists());
    assert!(!runs.join(".reservation-R.json").exists());
    assert_eq!(
        select_free_uid(&runs, "R", 3000, 2).expect("name remains free"),
        3000
    );
    fs::write(&settings, &source).expect("restore setting");
    let writable = home.join("loop-writable");
    fs::create_dir(&writable).expect("writable program parent");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).expect("loop-writable mode");
    let writable_entry = writable.join("entry");
    executable(&writable_entry, "#!/bin/sh\nexit 0\n");
    fs::write(
        &settings,
        source.replace(
            &entry.display().to_string(),
            &writable_entry.display().to_string(),
        ),
    )
    .expect("writable entry setting");
    assert_eq!(
        run(home, &request)
            .expect_err("loop-writable entry refused")
            .kind,
        "owner-program"
    );
    fs::write(&settings, &source).expect("restore protected entry");
    request.proxy_bin = None;
    fs::create_dir(runs.join("20260101T000000Z-driver-run")).expect("driver run directory");
    let preview = run_with_host_root_and_proxy(
        home,
        &request,
        home,
        nix::unistd::Uid::effective().as_raw(),
        |_| panic!("observe preview read vendor proxy unit"),
    )
    .expect("observing preview with inactive unit");
    assert_eq!(preview["proxy_service"]["verdict"], "not-applicable");
    assert_eq!(preview["plan"]["door"]["stub_sha256"], stub_digest);
    assert_eq!(preview["selection"]["backend"], "codex");
    let declared = json!({"grant":crate::plan::fixture_workspace_snapshot()["grant"],"baseline_environment_is_public":true}).to_string();
    fs::write(&settings,format!("{source}workspace_policy = {{ quick_policy_digest = {:?}, blacklist_digest = {:?} }}\n", "a".repeat(64),"b".repeat(64))).expect("published policy identities");
    request.compute_workspace = Some(declared);
    let declared_preview = run(home, &request).expect("workspace preview");
    assert_eq!(
        declared_preview["plan"]["compute_workspace"],
        crate::plan::fixture_workspace_snapshot()
    );
    assert!(
        !runs.join(".reservation-R.json").exists(),
        "preview publishes no grant"
    );
    assert_eq!(
        fs::read(&allocations).unwrap(),
        allocation_before,
        "preview allocates no identity"
    );
    request.compute_workspace = None;
    fs::write(&settings, &source).expect("restore legacy configuration");

    request.backend = Some(BoxBackend::Codex);
    let explicit = run(home, &request).expect("explicit Codex preview");
    assert_eq!(explicit["plan"], preview["plan"]);
    assert_eq!(explicit["selection"]["backend"], "codex");
    let mut mixed: toml::Table = toml::from_str(&source).expect("worker settings");
    mixed
        .get_mut("backend_argv")
        .and_then(toml::Value::as_table_mut)
        .expect("backend table")
        .insert(
            "claude".into(),
            toml::Value::Array(vec![toml::Value::String("/fixture/claude".into())]),
        );
    fs::write(&settings, toml::to_string(&mixed).expect("mixed settings")).expect("mixed vendors");
    request.backend = None;
    let mixed_preview = run(home, &request).expect("mixed configuration selects Codex");
    assert_eq!(mixed_preview["plan"], preview["plan"]);
    assert_eq!(mixed_preview["selection"]["backend"], "codex");
    request.backend = Some(BoxBackend::Claude);
    assert_eq!(
        run(home, &request)
            .expect_err("Claude dry run reaches installed door check")
            .kind,
        "door-generation"
    );
    request.dry_run = false;
    assert_eq!(
        run(home, &request)
            .expect_err("changing Claude launch remains gated first")
            .kind,
        "backend-unavailable"
    );
    request.dry_run = true;
    fs::write(&settings, &source).expect("restore Codex configuration");
    request.backend = None;
    assert_dead_dispatch_attempt_wall(home, &request);
    let saved_door_generation = fs::read(&door_generation).expect("saved door generation");
    let mut old_door_generation: serde_json::Value =
        serde_json::from_slice(&saved_door_generation).expect("door generation document");
    old_door_generation
        .as_object_mut()
        .expect("door generation fields")
        .remove("host_door_gid");
    fs::write(
        &door_generation,
        serde_json::to_vec(&old_door_generation).expect("old door generation"),
    )
    .expect("old door generation file");
    let caller = nix::unistd::Uid::effective().as_raw();
    let record_plan = crate::load_plan_for_record(home, "alpha", "R", (caller, 0))
        .expect("record reader does not require current door generation")
        .0;
    assert!(record_plan.document["door"].is_null());
    assert_eq!(
        record_plan.driver_dir.display().to_string(),
        preview["plan"]["driver_dir"].as_str().expect("driver")
    );
    let stale_door = crate::load_plan(home, "alpha", "R", (caller, 0))
        .expect_err("box plan refuses old door generation");
    assert_eq!(stale_door.kind, "door-generation");
    assert_eq!(stale_door.detail, "door generation shape differs");
    for case in [
        "letters",
        "context-use",
        "reaping",
        "harvest",
        "home-layout",
    ] {
        let result = crate::launch::exercise::run_case(home, "alpha", "R", case);
        assert_ne!(
            result.expect_err("fixture has no reservation").kind,
            "door-generation",
            "record-only case {case} must read past a stale door generation"
        );
    }
    for (case, result) in [
        (
            "harvest-private",
            crate::launch::exercise::private_harvest_audit_body(
                home, "alpha", "R", "fixture", caller,
            ),
        ),
        (
            "home-layout-private",
            crate::launch::exercise::layout::private_measure_body(
                home, "alpha", "R", "fixture", caller,
            ),
        ),
    ] {
        assert_ne!(
            result.expect_err("fixture has no reservation").kind,
            "door-generation",
            "record-only {case} must read past a stale door generation"
        );
    }
    let stale_case = crate::launch::exercise::run_case(home, "alpha", "R", "door-shape")
        .expect_err("door case refuses old generation");
    assert_eq!(stale_case.kind, "door-generation");
    assert_eq!(stale_case.detail, "door generation shape differs");
    fs::remove_file(&door_generation).expect("remove fixture generation");
    let absent_case = crate::launch::exercise::run_case(home, "alpha", "R", "door-shape")
        .expect_err("door case requires a generation");
    assert_eq!(absent_case.kind, "door-generation");
    assert_eq!(
        absent_case.detail,
        "registered door generation is absent or names other roots"
    );
    let absent_launch = run(home, &request).expect_err("installed service requires generation");
    assert_eq!(absent_launch.kind, "door-generation");
    assert_eq!(
        absent_launch.detail,
        "registered door generation is absent or names other roots"
    );
    fs::write(&door_generation, saved_door_generation).expect("restore door generation");
    fs::set_permissions(&door_generation, fs::Permissions::from_mode(0o600))
        .expect("restore door generation mode");
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 41001);
    let run_dir = runs.join("R");
    fs::create_dir(&run_dir).expect("loop driver directory");
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o000))
        .expect("unreadable driver mode");
    let restore = RestoreDriver(run_dir.clone());
    let mut old_plan = preview["plan"].clone();
    old_plan
        .as_object_mut()
        .expect("plan object")
        .remove("reservation_census");
    let reservation = runs.join(".reservation-R.json");
    crate::launch::publish_reservation(
        &reservation,
        &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":old_plan,"letter_source":request.letter,"launcher_pid":crate::dead_pid::DEAD_LOCK_PID,"launcher_start":1,"observer_state":"running","observer_pid":crate::dead_pid::DEAD_LOCK_PID + 1,"observer_start":1,"helper_spawn_state":"not-started","reservation_census":preview["plan"]["reservation_census"]}),
    )
    .expect("dead preparation");
    let dead = run(home, &request).expect("public preview reads owner custody only");
    assert_eq!(
        dead["dead_preparation"]["state"],
        "would-retire-dead-preparation"
    );
    assert_eq!(
        dead["dead_preparation"]["attempt_evidence"]["prior_attempt_started"],
        false
    );
    assert_eq!(
        dead["dead_preparation"]["probe_absence"]["labelled_containers"],
        "absent"
    );
    fs::remove_file(&reservation).expect("clear fixture reservation");
    let launch_dir = runs.join(".launch-R");
    fs::create_dir(&launch_dir).expect("protected launch directory");
    fs::set_permissions(&launch_dir, fs::Permissions::from_mode(0o700))
        .expect("launch directory mode");
    fs::write(launch_dir.join("passwd"), b"fixture account\n").expect("passwd fixture");
    fs::write(launch_dir.join("group"), b"fixture group\n").expect("group fixture");
    let run_home = std::path::PathBuf::from(preview["plan"]["home"].as_str().expect("run home"));
    fs::create_dir(&run_home).expect("collectable home");
    let lease = runs.join(".prepare-R.lock");
    fs::write(&lease, b"").expect("existing lease");
    let failed = json!({"schema":1,"phase":"failed","loop":"alpha","run":"R","worker_uid":3000,"plan":old_plan,"letter_source":request.letter,"observer_state":"not-started","helper_spawn_state":"not-started","pre_driver_failure":"bound-source: vendor-socket: source metadata unavailable (NotFound)","settlement_uncertain":false,"driver_end":{"state":"not-started"},"helper_end":{"state":"not-started"},"observer_end":{"state":"not-started","socket":{"state":"not-applicable"}}});
    crate::launch::publish_reservation(&reservation, &failed).expect("terminal preparation");
    let terminal = run(home, &request).expect("public dry run names terminal preparation");
    let recovery = &terminal["dead_preparation"];
    assert_eq!(recovery["state"], "would-retire-dead-preparation");
    assert_eq!(recovery["identities"]["launcher"], serde_json::Value::Null);
    assert_eq!(recovery["presence"]["launcher"], "never-spawned");
    assert_eq!(recovery["presence"]["helper_parent"], "never-spawned");
    assert_eq!(recovery["attempt_evidence"]["prior_attempt_started"], false);
    assert_eq!(
        recovery["retirement_to_journal"]["absence_basis"],
        "recorded-terminal-pre-driver-failure"
    );
    let paths = recovery["retirement_to_journal"]["planned_paths"]
        .as_array()
        .expect("planned retirement paths");
    assert!(
        paths
            .iter()
            .any(|pair| pair["source"].as_str() == run_dir.to_str())
    );
    assert!(
        paths
            .iter()
            .any(|pair| pair["source"].as_str() == launch_dir.to_str())
    );
    assert!(
        paths
            .iter()
            .any(|pair| pair["source"].as_str() == run_home.to_str())
    );
    assert_eq!(
        recovery["retirement_to_journal"]["retained_preparation_lock"],
        lease.display().to_string()
    );
    let mut uncertain = failed.clone();
    uncertain["settlement_uncertain"] = json!(true);
    crate::launch::publish_reservation(&reservation, &uncertain).expect("uncertain record");
    assert_eq!(
        run(home, &request).expect_err("uncertain failure").kind,
        "launch-reservation"
    );
    let mut starting = failed.clone();
    starting["observer_state"] = json!("starting");
    crate::launch::publish_reservation(&reservation, &starting).expect("starting record");
    assert_eq!(
        run(home, &request).expect_err("observer may exist").kind,
        "launch-reservation"
    );
    let mut helper = failed.clone();
    helper["helper_spawn_state"] = json!("starting");
    crate::launch::publish_reservation(&reservation, &helper).expect("helper record");
    assert_eq!(
        run(home, &request).expect_err("helper may exist").kind,
        "launch-reservation"
    );
    for field in [
        "launcher_pid",
        "driver_entry_pid",
        "helper_parent_pid",
        "observer_pid",
    ] {
        let mut pid = failed.clone();
        pid[field] = json!(321);
        crate::launch::publish_reservation(&reservation, &pid).expect("incomplete identity");
        assert_eq!(
            run(home, &request).expect_err("unpaired PID").kind,
            "launch-reservation"
        );
    }
    fs::remove_file(&reservation).expect("clear terminal reservation");
    fs::remove_file(&lease).expect("clear lease");
    fs::remove_dir_all(&launch_dir).expect("clear launch fixture");
    fs::remove_dir(&run_home).expect("clear home fixture");
    drop(restore);
    fs::remove_dir(&run_dir).expect("clear driver fixture");
    let other_proxy = home.join("other-proxy");
    executable(&other_proxy, "#!/bin/sh\nexit 1\n");
    request.proxy_bin = Some(other_proxy);
    let wrong_proxy = run(home, &request).expect_err("override differs from installed proxy");
    assert_eq!(wrong_proxy.kind, "proxy-program");
    request.proxy_bin = None;
    assert_eq!(preview["selection"]["worker_uid"], 3000);
    assert_eq!(preview["plan"]["reservation_census"]["skipped_count"], 1);
    assert_eq!(
        preview["plan"]["reservation_census"]["skipped_names"],
        json!(["20260101T000000Z-driver-run"])
    );
    assert_eq!(preview["observe"], true);
    assert_eq!(preview["enforcing"], false);
    assert_eq!(preview["box_gate"]["verdict"], "passed");
    assert_eq!(preview["box_gate"], preview["plan"]["box_gate"]);
    let runtime_bytes = serde_json::to_vec(&preview["plan"]["runtime_argv"]).expect("runtime JSON");
    assert_eq!(
        preview["box_gate"]["runtime_argv_sha256"],
        crate::build::sha256_bytes(&runtime_bytes, home).expect("runtime digest")
    );
    assert!(
        preview["plan"]["runtime_argv"]
            .as_array()
            .expect("argv")
            .iter()
            .any(|word| word
                .as_str()
                .is_some_and(|word| word.starts_with("SUPERLOOP_VENDOR_SOCKET=")))
    );
    assert_eq!(preview["box_probe"]["verdict"], "passed");
    assert_eq!(
        preview["box_probe"]["image_package_inventory"],
        "bwrap and bubblewrap absent"
    );
    let performed = preview["checks_performed"]
        .as_array()
        .expect("performed checks");
    let future = preview["checks_on_launch"]
        .as_array()
        .expect("future checks");
    assert!(
        performed
            .iter()
            .any(|check| check == "letter size and protected parent")
    );
    assert!(
        !performed
            .iter()
            .any(|check| check == "enforcing vendor socket")
    );
    assert!(
        future
            .iter()
            .any(|check| check == "observing proxy socket readiness")
    );
    assert_eq!(
        preview["plan"]["home"],
        home.join(".cache/tmp/lane-alpha-R").display().to_string()
    );
    assert_eq!(
        preview["plan"]["runtime_argv"][3],
        "--name=superloop-lane-alpha-R-attempt-1"
    );
    assert_eq!(preview["invocation"]["argv"][0], "driver-launch");
    assert_eq!(preview["helper_argv"]["argv"][2], "_container-helper");
    assert_eq!(preview["helper_argv"]["argv"][3], "--run-dir");
    assert_eq!(
        preview["helper_argv"]["argv"]
            .as_array()
            .expect("helper vector")
            .len(),
        13
    );
    assert_eq!(preview["helper_argv"]["argv"][7], "--verified-home-fd");
    assert_eq!(
        preview["helper_argv"]["anchor_manifest"],
        json!({"state":"bound-on-launch","transport":"rights","purposes":["owner-home","runs-root","entry-executable","podman-executable","hash-executable","credential-client","credential-clock","configuration"]})
    );
    assert_eq!(preview["prepare_argv"]["directory_transfer_socket_fd"], 0);
    assert_eq!(preview["prepare_argv"]["timeout_seconds"], 600);
    assert_eq!(preview["setup_argv"]["timeout_seconds"], 600);
    assert_eq!(
        preview["prepare_argv"]["transferred_directory_descriptors"],
        json!([])
    );
    assert_eq!(
        preview["prepare_argv"]["direct_private_directory_fd"],
        serde_json::Value::Null
    );
    assert_eq!(preview["helper_argv"]["argv"][8], "0");
    assert_eq!(preview["helper_argv"]["argv"][9], "--verified-runs-root");
    assert_eq!(
        preview["helper_argv"]["argv"][11],
        "--verified-runs-root-fd"
    );
    let external_runs = fixture.path().join("external-runs");
    let external_letters = fixture.path().join("external-letters");
    fs::create_dir(&external_letters).expect("external letter directory");
    fs::set_permissions(&external_letters, fs::Permissions::from_mode(0o700))
        .expect("external letter mode");
    fs::rename(&runs, &external_runs).expect("move protected runs root outside home");
    let external_letter = external_letters.join("first-letter");
    fs::rename(&request.letter, &external_letter).expect("move protected letter outside home");
    let original_letter = request.letter.clone();
    request.letter = external_letter.clone();
    fs::write(
        &settings,
        source.replace(
            &runs.display().to_string(),
            &external_runs.display().to_string(),
        ),
    )
    .expect("external runs setting");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", external_runs.display())).expect("external runs row");
    let external_preview = run_with_host_root(
        home,
        &request,
        fixture.path(),
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("public preview accepts external runs root and letter");
    let prepare_words = external_preview["prepare_argv"]["argv"]
        .as_array()
        .expect("private vector");
    assert!(prepare_words.iter().all(|word| !matches!(
        word.as_str(),
        Some("--verified-home-fd" | "--verified-runs-root-fd" | "--verified-letter-fd")
    )));
    assert_eq!(
        external_preview["prepare_argv"]["anchor_manifest"],
        json!({"state":"bound-on-launch","transport":"rights","operation":"make-home",
            "purposes":["owner-home","runs-root","entry-executable","podman-executable",
                "hash-executable","configuration","loop-storage","private-storage",
                "identity-executable","credential-client","credential-clock","letter-directory"],
            "optional_purposes":["rotation-source"]})
    );
    assert_eq!(
        external_preview["helper_argv"]["argv"][10],
        external_runs.display().to_string()
    );
    let owner = nix::unistd::Uid::effective().as_raw();
    let home_fd = fs::File::open(home).expect("verified home descriptor");
    let runs_fd = fs::File::open(&external_runs).expect("verified external runs descriptor");
    let letter_fd = fs::File::open(&external_letters).expect("verified external letter descriptor");
    let private = crate::home::activate_private_launch(
        home,
        &home_fd,
        &external_runs,
        &runs_fd,
        Some((&external_letters, &letter_fd)),
        owner,
    )
    .expect("private entry accepts public preview anchors");
    assert_eq!(
        crate::home::read_letter(&external_letter, owner).expect("private external letter"),
        b"Read this letter.\n"
    );
    crate::home::pin_parent(&external_runs, owner).expect("private external runs root");
    drop(private);
    fs::rename(&external_runs, &runs).expect("restore runs root");
    fs::rename(&external_letter, &original_letter).expect("restore letter");
    request.letter = original_letter;
    fs::write(&settings, &source).expect("restore settings");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display())).expect("restore row");
    assert_eq!(
        preview["children_executed"]
            .as_array()
            .expect("children")
            .len(),
        1
    );
    assert_eq!(
        preview["hash_checks_executed"]
            .as_array()
            .expect("hashes")
            .len(),
        5
    );
    assert_eq!(
        preview["hash_checks_executed"][4]["input"],
        template.join("libexec/box-init").display().to_string()
    );
    assert_eq!(
        preview["invocation"]["argv"]
            .as_array()
            .expect("entry words")
            .last(),
        Some(&serde_json::json!(
            "Read /home/worker/brief.txt and carry out the work it describes, reporting as the brief asks."
        ))
    );
    assert_eq!(
        preview["selection"]["method"],
        "in-process read-only runs-root snapshot under shared lock"
    );
    assert_eq!(
        fs::read_to_string(home.join("container-calls")).expect("named image probes"),
        "called\n".repeat(24)
    );
    let build_report = custody.join("image-build.json");
    let original_report = fs::read(&build_report).expect("pinned build report");
    let mut without_program: serde_json::Value =
        serde_json::from_slice(&original_report).expect("build report JSON");
    without_program
        .as_object_mut()
        .expect("build report object")
        .remove("codex_image_program");
    fs::write(
        &build_report,
        serde_json::to_vec(&without_program).expect("missing image program report"),
    )
    .expect("publish missing image program fixture");
    let missing_program =
        run(home, &request).expect_err("dry launch requires recorded image program");
    assert_eq!(missing_program.kind, "build-report");
    assert_eq!(missing_program.detail, "codex_image_program is absent");
    fs::write(&build_report, &original_report).expect("restore build report");
    let mut without_companion: serde_json::Value =
        serde_json::from_slice(&original_report).expect("build report JSON");
    without_companion["codex_exec_probe"]["companions"] = json!([]);
    fs::write(
        &build_report,
        serde_json::to_vec(&without_companion).expect("missing companion report"),
    )
    .expect("publish missing companion fixture");
    assert_eq!(
        run(home, &request)
            .expect_err("dry run requires companion")
            .kind,
        "codex-companion"
    );
    fs::write(&build_report, original_report).expect("restore build report");
    let template_parent = home.join(".var/loops/alpha/runner-templates");
    fs::set_permissions(&template_parent, fs::Permissions::from_mode(0o770))
        .expect("simulate loop-writable template parent");
    let mutable_pin = run(home, &request).expect_err("loop-writable pin refused");
    assert_eq!(mutable_pin.kind, "protected-path");
    fs::set_permissions(&template_parent, fs::Permissions::from_mode(0o711))
        .expect("restore protected template parent");
    assert!(!home.join(".cache/tmp/lane-alpha-R").exists());
    assert!(!home.join(".var/loops/alpha/runs/R").exists());
    fs::create_dir(runs.join("R")).expect("failed observing run directory");
    fs::write(runs.join(".observed-R.txt"), "mode=observing run=R enforcing=false\napi.example.com:443 connected=1\nfailed.example.com:443 connected=0\n").expect("failed run observation");
    let before = fs::read(&settings).expect("settings before list");
    let listed = record_hosts_with_lane_bin(
        home,
        &RecordHostsRequest::parse(
            &[
                "alpha",
                "R",
                "--list",
                "--podman-bin",
                request.podman_bin.to_str().expect("program"),
            ]
            .map(String::from),
        )
        .expect("list form"),
        &lane_bin,
    )
    .expect("list failed run");
    assert_eq!(listed["changed"], false);
    assert_eq!(
        listed["observation"]["connected_hosts"][0],
        "api.example.com"
    );
    assert_eq!(fs::read(&settings).expect("settings after list"), before);
    let selected = RecordHostsRequest::parse(
        &[
            "alpha",
            "R",
            "--host",
            "api.example.com",
            "--podman-bin",
            request.podman_bin.to_str().expect("program"),
        ]
        .map(String::from),
    )
    .expect("selection form");
    let held = crate::install::lock_loop_config(&custody, false).expect("concurrent writer lock");
    let busy = record_hosts_with_lane_bin(home, &selected, &lane_bin)
        .expect_err("record-hosts cannot read and write beside another settings writer");
    assert_eq!(busy.kind, "install-busy");
    fs::write(
        &settings,
        source.replace("memory_bytes = 2147483648", "memory_bytes = 3221225472"),
    )
    .expect("concurrent settings update");
    drop(held);
    let recorded = record_hosts_with_lane_bin(home, &selected, &lane_bin)
        .expect("record-hosts follows completed settings writer");
    assert_eq!(recorded["changed"], true);
    let combined = fs::read_to_string(&settings).expect("combined settings");
    assert!(combined.contains("memory_bytes = 3221225472"));
    assert!(combined.contains("api.example.com"));
    let private_calls = fs::read(home.join("container-calls")).expect("private call record");
    fs::remove_file(&lane_bin).expect("remove lane fixture");
    std::os::unix::fs::symlink("/usr/bin/true", &lane_bin).expect("replace lane fixture");
    let mut rejected = RecordHostsRequest::parse(
        &[
            "alpha",
            "R",
            "--list",
            "--podman-bin",
            request.podman_bin.to_str().expect("program"),
        ]
        .map(String::from),
    )
    .expect("list form");
    let list_error = record_hosts_with_lane_bin(home, &rejected, &lane_bin)
        .expect_err("replaced lane binary refuses list");
    assert_eq!(list_error.kind, "owner-program");
    rejected.list = false;
    rejected.dry_run = true;
    rejected.hosts = vec!["api.example.com".into()];
    let dry_error = record_hosts_with_lane_bin(home, &rejected, &lane_bin)
        .expect_err("replaced lane binary refuses dry run");
    assert_eq!(dry_error.kind, "owner-program");
    assert_eq!(
        fs::read(home.join("container-calls")).expect("no new private read"),
        private_calls
    );
}

/// ´claim:superlooplane:service-reservation-key-binds-held-runtime´
/// ´test:crate:proxy-refresh-preserves-live-helper-pins´
#[test]
#[allow(clippy::too_many_lines)]
fn proxy_refresh_preserves_live_helper_pins() {
    if std::env::var_os("SUPERLOOP_REFRESH_PROOF").is_none() {
        let output = crate::fixture_exec::output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "tests::launch::proxy_refresh_preserves_live_helper_pins",
                    "--nocapture",
                ])
                .env("SUPERLOOP_REFRESH_PROOF", "1")
                .env("_CONTAINERS_USERNS_CONFIGURED", "1")
                .env(
                    "_CONTAINERS_ROOTLESS_UID",
                    nix::unistd::Uid::effective().as_raw().to_string(),
                ),
        )
        .expect("proof child");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let fixture = if std::env::var_os("SUPERLOOP_ROUND_PROOF").is_some() {
        ProtectedRoot::declared_root()
    } else {
        ProtectedRoot::short_socket_root()
    };
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
        .expect("host ancestor mode");
    let home_dir = fixture.path().join("home");
    fs::create_dir(&home_dir).expect("owner home");
    let home = home_dir.as_path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o711)).expect("host home mode");
    let custody = home.join(".config/loops/alpha");
    fs::create_dir_all(&custody).expect("custody");
    for path in [
        home.join(".config"),
        home.join(".config/loops"),
        custody.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("custody mode");
    }
    let runs = home.join(".var/loops/alpha/runs");
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    let sockets = home.join(".var/loops/alpha/sockets");
    let entry = home.join("entry-fixture");
    let podman = home.join("container-fixture");
    let driver = home.join("driver-fixture");
    let lane_bin = home.join("lane-fixture");
    let scratchpad = home.join("scratchpad");
    fs::create_dir(&scratchpad).expect("letter scratchpad");
    fs::set_permissions(&scratchpad, fs::Permissions::from_mode(0o700)).expect("scratchpad mode");
    let letter = scratchpad.join("first-letter");
    let observation = json!({"schema":1,"command":"observed-hosts","loop":"alpha","run":"R","mode":"observing","enforcing":false,"source":runs.join(".observed-R.txt"),"attempted_connect_hosts":{"api.example.com":true,"failed.example.com":false},"connected_hosts":["api.example.com"]});
    executable(&entry, "#!/bin/sh\nexit 0\n");
    executable(
        &podman,
        &format!(
            "#!/bin/sh\nprintf 'called\\n' >> '{}'\nif [ \"$1 $2\" = 'image inspect' ]; then printf '{}\\n'; exit 0; fi\nif [ \"$1\" = unshare ]; then printf '%s\\n' '{}'; exit 0; fi\nif [ \"$1\" = ps ]; then exit 0; fi\nexit 9\n",
            home.join("container-calls").display(),
            "a".repeat(64),
            observation
        ),
    );
    executable(
        &driver,
        "#!/bin/sh\nif [ \"$5\" = --runtime-contract ]; then printf 'boxed-runtime 1\\n'; fi\nexit 0\n",
    );
    executable(&lane_bin, "#!/bin/sh\nexit 0\n");
    executable(&home.join("proxy-fixture"), "#!/bin/sh\nexit 0\n");
    fs::create_dir_all(&runs).expect("runs root");
    for path in [
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        runs.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private runs ancestor");
    }
    // This stand-in models child results; real mapped ownership is exercised by the rootless entry tests.
    fs::set_permissions(
        home.join(".var/loops/alpha"),
        fs::Permissions::from_mode(0o711),
    )
    .expect("provisioned loop storage mode");
    let private_storage = home.join(".var/loops/alpha/private");
    fs::create_dir(&private_storage).expect("provisioned private storage");
    fs::set_permissions(&private_storage, fs::Permissions::from_mode(0o700))
        .expect("private storage mode");
    fs::create_dir_all(template.join("bin")).expect("template bin");
    fs::create_dir_all(template.join("libexec")).expect("template helper directory");
    fs::create_dir_all(sockets.join("vendor")).expect("vendor sockets");
    fs::create_dir_all(sockets.join("door")).expect("door sockets");
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))
        .expect("socket directory mode");
    fs::set_permissions(sockets.join("vendor"), fs::Permissions::from_mode(0o700))
        .expect("vendor socket directory mode");
    fs::set_permissions(sockets.join("door"), fs::Permissions::from_mode(0o750))
        .expect("door socket directory mode");
    fs::create_dir_all(custody.join("lanes/codex")).expect("sign-in place");
    fs::create_dir_all(home.join(".cache/tmp")).expect("home parent");
    fs::write(template.join("bin/codex"), "pinned codex\n").expect("codex pin");
    fs::write(template.join("bin/codex-code-mode-host"), "pinned host\n").expect("host pin");
    fs::write(
        template.join("config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    )
    .expect("policy pin");
    fs::write(template.join("AGENTS.md"), "A worker charter.\n").expect("charter pin");
    let data = home.join("image-data");
    fs::create_dir(&data).expect("image data");
    fs::write(data.join("box-init"), "fixed init\n").expect("init pin");
    fs::write(template.join("libexec/box-init"), "fixed init\n").expect("installed init pin");
    fs::write(template.join("libexec/ssh"), "keyless stub\n").expect("door stub pin");
    fs::write(custody.join("door-service"), "registered service\n").expect("door service pin");
    let image = format!("sha256:{}", "a".repeat(64));
    let codex_hash = sha256(&template.join("bin/codex")).expect("codex hash");
    let host_hash = sha256(&template.join("bin/codex-code-mode-host")).expect("host hash");
    fs::write(template.join("manifest"), serde_json::to_vec(&json!({"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"config_sha256":sha256(&template.join("config.toml")).expect("config hash"),"charter_sha256":sha256(&template.join("AGENTS.md")).expect("charter hash")})).expect("manifest")).expect("manifest file");
    for (path, mode) in [
        (home.join(".var/loops/alpha/runner-templates"), 0o711),
        (home.join(".var/loops/alpha/runner-templates/codex"), 0o711),
        (template.join("bin/codex"), 0o550),
        (template.join("bin/codex-code-mode-host"), 0o550),
        (template.join("config.toml"), 0o440),
        (template.join("AGENTS.md"), 0o440),
        (template.join("manifest"), 0o440),
        (template.join("bin"), 0o550),
        (template.join("libexec"), 0o550),
        (template.join("libexec/box-init"), 0o440),
        (template.join("libexec/ssh"), 0o550),
        (template.clone(), 0o550),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("installed pin mode");
    }
    fs::set_permissions(
        custody.join("door-service"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("door service mode");
    let image_program = "/usr/libexec/superloop/fixture-image-codex";
    assert!(!std::path::Path::new(image_program).exists());
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&json!({"package_inventory":[],"image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_host_probe":{"argv":["--help"],"stdout":"host help","sha256":host_hash},"init_sha256":sha256(&data.join("box-init")).expect("init hash"),"codex_image_program":image_program,"build_environment":{"template_dir":data},"codex_exec_probe":{"argv":["exec","--help"],"stdout":"  -m, --model\n  -c, --config\n  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n","required_options":crate::build::CODEX_EXEC_OPTIONS,"codex_sha256":codex_hash,"companions":[{"name":"codex-code-mode-host","path":crate::build::CODEX_HOST_PATH,"sha256":host_hash}]}})).expect("report")).expect("report file");
    fs::write(custody.join("install-generation.json"), serde_json::to_vec(&json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":codex_hash,"codex_host_sha256":host_hash,"codex_image_program":image_program,"proxy_bin":home.join("proxy-fixture"),"proxy_sha256":sha256(&home.join("proxy-fixture")).expect("proxy hash"),"init_sha256":sha256(&data.join("box-init")).expect("init hash")})).expect("generation")).expect("generation file");
    fs::write(&letter, "Read this letter.\n").expect("letter");
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = {}, launch = \"src\", runs_root = \"{}\" }}]\n", nix::unistd::Gid::effective().as_raw(), runs.display())).expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let allocations = home.join(".config/loops/allocations.toml");
    fs::write(
        &allocations,
        "mail_uid = 61000\n[alpha]\nuids = { base = 3000, count = 2 }\nmail_gids = { base = 43000, count = 3 }\n",
    )
    .expect("allocation");
    fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600)).expect("allocation mode");
    let settings = custody.join("workers.toml");
    let source = format!(
        "runs_root = \"{}\"\nentry_bin = \"{}\"\ndriver_argv = [\"{}\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nbackend_argv = {{ codex = [\"{}\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
        runs.display(),
        entry.display(),
        driver.display(),
        "a".repeat(64),
        template.display(),
        sockets.display(),
        image_program
    );
    fs::write(&settings, &source).expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    let door_generation = custody.join("door-install-generation.json");
    let stub_digest = sha256(&template.join("libexec/ssh")).expect("stub digest");
    fs::write(
        &door_generation,
        serde_json::to_vec(&json!({"schema":2,"agent":{"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"agent_expected_tokens":16384,"entry":"/fixture/entry","loop_home":"/fixture/home"},"phase":"complete","loop":"alpha","template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":sha256(&custody.join("door-service")).expect("service digest"),"unit_dir":custody.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw()})).expect("door generation"),
    )
    .expect("door generation file");
    fs::set_permissions(&door_generation, fs::Permissions::from_mode(0o600))
        .expect("door generation mode");

    fs::write(
        &settings,
        format!("{source}vendor_hosts = {{ codex = [] }}\n"),
    )
    .expect("observing settings");
    fs::copy(template.join("config.toml"), data.join("config.toml")).expect("source config");
    fs::copy(template.join("AGENTS.md"), data.join("AGENTS.md")).expect("source charter");
    let report_path = custody.join("image-build.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report")).expect("JSON");
    report["schema"] = json!(1);
    report["command"] = json!("build");
    report["build_environment"]["podman_bin"] = json!(podman);
    report["tools_commit"] = json!("fixture");
    report["build_environment"]["codex_bin"] = json!(template.join("bin/codex"));
    report["build_environment"]["codex_host_bin"] =
        json!(template.join("bin/codex-code-mode-host"));
    fs::write(
        &report_path,
        serde_json::to_vec(&report).expect("report JSON"),
    )
    .expect("report");
    let generation_path = custody.join("install-generation.json");
    let mut generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("record")).expect("JSON");
    generation["tools_commit"] = json!("fixture");
    generation["template_dir"] = json!(template);
    generation["socket_dir"] = json!(sockets);
    generation["unit_dir"] = json!(home.join(".config/systemd/user"));
    generation["source_fingerprint"] = json!("a".repeat(64));
    fs::write(
        &generation_path,
        serde_json::to_vec(&generation).expect("generation JSON"),
    )
    .expect("generation");
    let private_report = json!({"schema":1,"changed":0,"source_fingerprint":"a".repeat(64),"source_sha256":{"codex":codex_hash,"codex_host":host_hash,"init":report["init_sha256"]},"destinations":[{"complete":true}],"sign_in":{"changes":[]},"hash_checks":[1,2,3,4,5,6]});
    executable(
        &podman,
        &format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'image inspect' ]; then printf '{}\\n'; else printf '%s\\n' '{}'; fi\n",
            "a".repeat(64),
            private_report
        ),
    );
    fixture_work_route(home);
    let launch = LaunchRequest {
        backend: None,
        loop_name: "alpha".into(),
        run: "R".into(),
        letter: letter.clone(),
        round: None,
        thread_choice: None,
        budget: 3600,
        dry_run: true,
        expect_digest: None,
        compute_workspace: None,
        observe: true,
        podman_bin: podman.clone(),
        proxy_bin: Some(home.join("proxy-fixture")),
        model: Some("gpt-6-sol".into()),
        effort: Some("high".into()),
        door_scope: crate::door::Scope::Work,
        rotation_source: None,
    };
    let preview = run(home, &launch).expect("production launch reads the original generation");
    assert_eq!(preview["dry_run"], true);
    assert!(
        !custody.join(".install-generation.lock").exists(),
        "preview does not create the writer lock"
    );
    drop(
        crate::install::lock_launch_generation(&custody, false)
            .expect("changing launch establishes stable generation lock"),
    );
    let first = crate::fixture_exec::SharedLauncher::start(&custody);
    let second = crate::fixture_exec::SharedLauncher::start(&custody);
    assert_eq!(
        run(home, &launch).expect("launch reads beside two live shared holders")["dry_run"],
        true
    );
    let selection = json!({"model":"gpt-6-sol","effort":"high","model_source":"launch-flag","effort_source":"launch-flag"});
    for (name, uid, holder) in [("R", 3000, &first), ("S", 3001, &second)] {
        let (mut plan, _) = crate::load_plan(home, "alpha", name, (0, 0)).expect("plan");
        plan.select_worker_uid(uid).expect("worker");
        plan.select_mail_group(43001 + uid - 3000)
            .expect("mail group");
        let birth = loop_home::mail::birth::Identity::for_reservation(
            uid,
            format!("superloop-lane:{name}"),
        );
        plan.select_mailbox(
            &home
                .join(".var/loops/alpha/workers")
                .join(&birth.name)
                .join("mail"),
            &birth,
            61000,
        )
        .expect("mail mount");
        plan.select_container_program(&podman).expect("podman");
        plan.observe_vendor().expect("observing");
        plan.select_launch_model(&selection).expect("selection");
        let identity = crate::plan::protected_identity_dir(&plan.driver_dir).expect("identity");
        fs::create_dir_all(&identity).expect("identity directory");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).expect("identity mode");
        for (name, bytes) in [
            (
                "passwd",
                format!("worker:x:{uid}:{uid}::/home/worker:/bin/sh\n"),
            ),
            (
                "group",
                format!(
                    "worker:x:{uid}:\nloop:x:{}:worker\n",
                    nix::unistd::Gid::effective().as_raw()
                ),
            ),
        ] {
            fs::write(identity.join(name), bytes).expect("identity file");
            fs::set_permissions(identity.join(name), fs::Permissions::from_mode(0o440))
                .expect("identity file mode");
        }
        let (pid, start) = holder.identity();
        let record = json!({"schema":1,"phase":"started","loop":"alpha","run":name,"worker_uid":uid,"launcher_pid":pid,"launcher_start":start,"plan":plan.document,"model_selection":selection,"letter_source":letter});
        let reservation = runs.join(format!(".reservation-{name}.json"));
        fs::write(
            &reservation,
            serde_json::to_vec(&record).expect("reservation JSON"),
        )
        .expect("reservation");
        fs::set_permissions(reservation, fs::Permissions::from_mode(0o600))
            .expect("reservation mode");
    }
    for path in [&report_path, &generation_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("repair input mode");
    }
    let mut repair = crate::repair::RepairRequest {
        loop_name: "alpha".into(),
        dry_run: true,
    };
    let repair_preview = crate::repair::run_with_lane_bin(
        home,
        &repair,
        &lane_bin,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("blocked repair preview");
    assert_eq!(repair_preview["command"], "repair");
    assert_eq!(repair_preview["blocked"], true);
    assert_eq!(
        repair_preview["busy"],
        json!(["run R (started)", "run S (started)"])
    );
    assert!(
        repair_preview.get("install").is_none(),
        "blocked work has no measured install count"
    );
    assert!(repair_preview.get("image").is_none(), "build did not run");
    repair.dry_run = false;
    let refusal = crate::repair::run_with_lane_bin(
        home,
        &repair,
        &lane_bin,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect_err("repair refuses before build");
    assert_eq!(refusal.kind, "install-busy");
    assert!(refusal.detail.contains("run R (started)"));
    assert!(refusal.detail.contains("run S (started)"));
    for (run, uid) in [("R", 3000), ("S", 3001)] {
        let birth =
            loop_home::mail::birth::Identity::for_reservation(uid, format!("superloop-lane:{run}"));
        fs::create_dir_all(
            home.join(".var/loops/alpha/workers")
                .join(&birth.name)
                .join("mail"),
        )
        .expect("fixture mailbox source for pin reconstruction");
    }
    if [
        "SUPERLOOP_READER_PROOF",
        "SUPERLOOP_REPORT_PROOF",
        "SUPERLOOP_HARVEST_PROOF",
        "SUPERLOOP_IMPORT_PROOF",
        "SUPERLOOP_CHECKPOINT_PROOF",
        "SUPERLOOP_CHECKOUT_PROOF",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some())
    {
        super::reader_custody::exercise(home, &runs, &podman);
        return;
    }
    if std::env::var_os("SUPERLOOP_CREATION_PROOF").is_some()
        || std::env::var_os("SUPERLOOP_WORKSPACE_CREATION_PROOF").is_some()
    {
        super::runtime_preparation::exercise_creation(home, &runs, &podman);
        return;
    }
    if std::env::var_os("SUPERLOOP_RUNTIME_PROOF").is_some() {
        super::runtime_preparation::exercise(home, &runs, &podman);
        return;
    }
    if std::env::var_os("SUPERLOOP_ROUND_PROOF").is_some() {
        let root = fixture.path().to_path_buf();
        super::helper_service::rounds_acceptance(home, &runs, &podman);
        drop(fixture);
        assert!(
            !root.exists(),
            "resumed helper fixture root removed: {}",
            root.display()
        );
        return;
    }
    if std::env::var_os("SUPERLOOP_SERVICE_PROOF").is_some() {
        super::helper_service::exercise(home, &runs, &podman);
        return;
    }
    crate::container_helper::fixture_reserved_program_attempt(home, &runs.join("R"));
    let before = crate::container_helper::fixture_pinned_request(home, &runs, "R", &podman)
        .expect("helper before refresh");
    let mut install = crate::install::InstallRequest {
        loop_name: "alpha".into(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: true,
        repair: false,
        podman_bin: Some(podman.clone()),
        data_dir: data,
        proxy_bin: home.join("proxy-fixture"),
        unit_dir: None,
    };
    let invoke = |request: &crate::install::InstallRequest| {
        crate::install::run_with_lane_bin(
            home,
            request,
            &lane_bin,
            home,
            nix::unistd::Uid::effective().as_raw(),
        )
    };
    let blocked = invoke(&install).expect("full preview blocked");
    assert_eq!(blocked["blocked"], true);
    assert_eq!(blocked["changed"], 0);
    assert_eq!(
        blocked["busy"],
        json!(["run R (started)", "run S (started)"])
    );
    install.dry_run = false;
    assert_eq!(
        invoke(&install)
            .expect_err("changing full install blocked")
            .kind,
        "install-busy"
    );
    executable(
        &install.proxy_bin,
        "#!/bin/sh\n# deployed proxy two\nexit 0\n",
    );
    install.scope = crate::install::InstallScope::ProxyRecord;
    install.dry_run = true;
    let preview = invoke(&install).expect("record-only preview beside live launchers");
    assert_eq!(preview["changed"], 1);
    assert_eq!(preview["blocked"], false);
    assert_eq!(preview["exclusive_configuration_lock_required"], false);
    assert_eq!(
        crate::install::read_generation(&generation_path).expect("preview record"),
        Some(generation.clone())
    );
    install.dry_run = false;
    let refreshed = invoke(&install).expect("record-only refresh beside live launchers");
    assert_eq!(refreshed["changed"], 1);
    assert_eq!(refreshed["blocked"], false);
    let after = crate::container_helper::fixture_pinned_request(home, &runs, "R", &podman)
        .expect("later helper request accepts refreshed generation");
    assert_eq!(before, after, "the run's pins remain unchanged");
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("refreshed generation"))
            .expect("JSON");
    for (key, value) in generation.as_object().expect("object") {
        if key != "proxy_sha256" {
            assert_eq!(&record[key], value, "unchanged {key}");
        }
    }
    assert_ne!(record["proxy_sha256"], generation["proxy_sha256"]);
    assert_eq!(invoke(&install).expect("repeat refresh")["changed"], 0);
    let generation_hold =
        crate::install::lock_generation(&custody, false, false).expect("launch preparation lock");
    assert_eq!(
        invoke(&install)
            .expect_err("refresh cannot interleave launch reads")
            .kind,
        "install-busy"
    );
    install.dry_run = true;
    let busy = invoke(&install).expect("generation contention preview");
    assert_eq!(busy["blocked"], true);
    assert_eq!(busy["changed"], 0);
    assert_eq!(busy["busy"], json!([GENERATION_CONTENTION_NOTE]));
    install.dry_run = false;
    drop(generation_hold);
    // Only the following full-install advice cases require unit source templates.
    for name in ["vendor-proxy.service.in", "worker.service.in"] {
        fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(name),
            install.data_dir.join(name),
        )
        .expect("unit source for installation advice");
    }
    for key in [
        "proxy_bin",
        "image_digest",
        "codex_sha256",
        "codex_host_sha256",
        "init_sha256",
        "template_dir",
        "source_fingerprint",
        "codex_image_program",
        "tools_commit",
    ] {
        let mut drift = record.clone();
        let alternate = home.join("alternate-proxy");
        executable(&alternate, "#!/bin/sh\nexit 0\n");
        drift[key] = if key == "proxy_bin" {
            json!(alternate)
        } else {
            json!("different")
        };
        fs::write(
            &generation_path,
            serde_json::to_vec(&drift).expect("drift JSON"),
        )
        .expect("drift");
        let error = invoke(&install).expect_err("nonproxy pin cannot refresh");
        assert!(error.detail.contains(key), "{key}: {error:?}");
        assert_eq!(
            error.kind,
            "install-proxy-refresh",
            "{key}: {}",
            error.line()
        );
        if key == "proxy_bin" {
            assert!(error.detail.contains(&format!(
                "--refresh-proxy --proxy-bin '{}'",
                alternate.display()
            )));
        } else {
            assert!(
                error
                    .detail
                    .contains("superloop-lane install --pilot alpha")
                    || error.detail.contains("full install --pilot")
            );
        }
    }
    fs::write(
        &generation_path,
        serde_json::to_vec(&record).expect("restore JSON"),
    )
    .expect("restore");
    for key in ["socket_dir", "template_dir", "tools_commit", "unit_dir"] {
        let mut drift = record.clone();
        let alternate = home.join("alternate-proxy");
        drift["proxy_bin"] = json!(alternate);
        drift[key] = json!("also-different");
        fs::write(
            &generation_path,
            serde_json::to_vec(&drift).expect("two differences"),
        )
        .expect("publish two differences");
        let error = invoke(&install).expect_err("path correction cannot repair another pin");
        assert_eq!(error.kind, "install-proxy-refresh");
        assert!(
            error
                .detail
                .starts_with(&format!("{key} differs from the installed generation;")),
            "{key}: {error:?}"
        );
        assert!(error.detail.contains(&format!(
            "install --pilot alpha --proxy-bin '{}' without --refresh-proxy",
            alternate.display()
        )));
        assert!(error.detail.contains(&format!(
            "then run superloop-lane install --pilot alpha --refresh-proxy --proxy-bin '{}'",
            alternate.display()
        )));
    }
    fs::write(
        &generation_path,
        serde_json::to_vec(&record).expect("restore pins"),
    )
    .expect("restore both pins");
    assert!(crate::container_helper::fixture_pinned_request(home, &runs, "S", &podman).is_ok());
    let defaults = crate::install::InstallRequest::parse(&[
        "--pilot".into(),
        "--refresh-proxy".into(),
        "alpha".into(),
        "--podman-bin".into(),
        podman.display().to_string(),
    ])
    .expect("no proxy or data flags");
    assert_eq!(
        invoke(&defaults).expect("recorded proxy and build report data defaults")["changed"],
        0
    );
    let sibling = home.join("superloop-lane-vendor-proxy");
    executable(&sibling, "#!/bin/sh\n# runtime sibling\nexit 0\n");
    assert_eq!(
        invoke(&defaults)
            .expect_err("present sibling requires provenance")
            .kind,
        "proxy-provenance"
    );
    assert_eq!(
        invoke(&install).expect("explicit path takes precedence over bad sibling")["changed"],
        0
    );
    fs::write(
        home.join("superloop-lane-vendor-proxy.provenance"),
        format!(
            "sha256-prefix: {}\n",
            &sha256(&sibling).expect("sibling digest")[..16]
        ),
    )
    .expect("runtime provenance");
    fs::set_permissions(
        home.join("superloop-lane-vendor-proxy.provenance"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("provenance mode");
    let refusal =
        invoke(&defaults).expect_err("verified sibling cannot silently change the installed path");
    assert_eq!(refusal.kind, "install-proxy-refresh");
    assert!(refusal.detail.contains("proxy_bin"));
    let command = refusal
        .detail
        .strip_prefix("proxy_bin differs from the installed generation; run ")
        .expect("correcting command")
        .split_once(", keeping the same explicit source, runtime and unit-directory options; moving the proxy path")
        .expect("retained options and move limitation")
        .0;
    let parsed = crate::fixture_exec::output(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -- {command}; printf '%s\\0' \"$@\"")),
    )
    .expect("parse quoted correcting command");
    assert!(parsed.status.success());
    let words: Vec<String> = parsed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8(word.to_vec()).expect("command word"))
        .collect();
    assert_eq!(&words[..2], ["superloop-lane", "install"]);
    let mut arguments = words[2..].to_vec();
    arguments.extend([
        "--podman-bin".into(),
        install
            .podman_bin
            .as_deref()
            .expect("selected fixture program")
            .display()
            .to_string(),
        "--data-dir".into(),
        install.data_dir.display().to_string(),
    ]);
    let correction = crate::install::InstallRequest::parse(&arguments).expect("named remedy");
    executable(
        &install.proxy_bin,
        "#!/bin/sh\n# corrected recorded proxy\nexit 0\n",
    );
    let corrected = invoke(&correction).expect("named remedy succeeds beside both live launchers");
    assert_eq!(corrected["changed"], 1);
    assert_eq!(corrected["proxy_bin"], record["proxy_bin"]);
    assert_eq!(
        corrected["proxy_sha256"],
        sha256(&install.proxy_bin).expect("corrected digest")
    );
    assert_eq!(invoke(&correction).expect("remedy repeat")["changed"], 0);
    let mut expected = record;
    expected["proxy_sha256"] = corrected["proxy_sha256"].clone();
    assert_eq!(
        crate::install::read_generation(&generation_path).expect("unchanged generation"),
        Some(expected)
    );
    assert!(crate::container_helper::fixture_pinned_request(home, &runs, "R", &podman).is_ok());
    assert!(crate::container_helper::fixture_pinned_request(home, &runs, "S", &podman).is_ok());
    drop(first);
    drop(second);
    fs::remove_file(runs.join(".reservation-R.json")).expect("release R");
    fs::remove_file(runs.join(".reservation-S.json")).expect("release S");
    fs::remove_dir_all(home.join(".var/loops/alpha/workers"))
        .expect("reset synthetic pin sources with their synthetic reservations");
    refresh_during_changing_launch(home, &launch, &install, &lane_bin, &source, &private_report);
    pre_driver_save_failure_windows(home, &launch, &lane_bin);
    helper_start_failure_windows(home, &launch, &lane_bin);
}

fn pad_pre_driver_save(path: &std::path::Path) -> Result<(), crate::error::LaneError> {
    let mut record = crate::launch::read_reservation(path)?.expect("preparing reservation");
    assert_eq!(record["phase"], "preparing");
    assert_eq!(record["helper_spawn_state"], "not-started");
    record["fixture_padding"] = json!("");
    let size = serde_json::to_vec(&record).expect("reservation JSON").len();
    let limit = usize::try_from(crate::launch::MAX_RESERVATION_BYTES).expect("reader bound");
    record["fixture_padding"] = json!("x".repeat(limit - size));
    crate::launch::publish_reservation(path, &record)?;
    assert_eq!(
        fs::metadata(path).expect("saved metadata").len(),
        crate::launch::MAX_RESERVATION_BYTES
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn pre_driver_save_failure_windows(
    home: &std::path::Path,
    launch: &LaunchRequest,
    lane_bin: &std::path::Path,
) {
    let settings_path = home.join(".config/loops/alpha/workers.toml");
    let settings = fs::read_to_string(&settings_path).expect("settings");
    for (name, kind, observe, identity) in [
        ("Prepare", "prepare-home", false, None),
        ("Executable", "owner-program", false, None),
        ("Runtime", "prepare-runtime", false, None),
        ("Primary", "bound-source", false, None),
        ("PublishPrimary", "bound-source", false, None),
        ("Launcher", "helper-session", false, Some(false)),
        ("Scope", "run-scope", false, Some(true)),
        ("Observer", "proxy-start", true, None),
        ("Deferred", "bound-source", true, None),
        ("DeferredProbe", "bound-source", true, None),
        ("PublishDeferred", "bound-source", true, None),
    ] {
        fs::write(
            &settings_path,
            if observe {
                settings.replace("codex = [\"api.example.com\"]", "codex = []")
            } else {
                settings.clone()
            },
        )
        .expect("window settings");
        let mut request = LaunchRequest::parse(
            &[
                "alpha",
                name,
                "--letter",
                launch.letter.to_str().expect("letter"),
                "--podman-bin",
                launch.podman_bin.to_str().expect("runtime"),
                "--dry-run",
            ]
            .map(String::from),
        )
        .expect("window request");
        request.model = launch.model.clone();
        request.effort = launch.effort.clone();
        request.proxy_bin = launch.proxy_bin.clone();
        request.observe = observe;
        request.dry_run = true;
        executable(
            &request.podman_bin,
            "#!/bin/sh\nprintf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        );
        let preview = run(home, &request).expect("window preview");
        let plan = &preview["plan"];
        let driver = std::path::Path::new(plan["driver_dir"].as_str().expect("driver"));
        let evidence = crate::plan::protected_identity_dir(driver)
            .expect("identity")
            .join("launch-evidence.json");
        let path = home
            .join(".var/loops/alpha/runs")
            .join(format!(".reservation-{name}.json"));
        let seed = json!({"schema":1,"phase":"preparing","loop":"alpha","run":name,"worker_uid":plan["worker_uid"],"plan":plan,"model_selection":preview["selection"]["model"],"probe_starts":[],"imports":[],"harvest_agreement":null,"collection":null,"observer_state":"not-started","helper_spawn_state":"not-started"});
        fs::write(
            home.join("pre-driver-window.json"),
            json!({"seed":seed,"path":path,"evidence":evidence,"lane":lane_bin,"window":name})
                .to_string(),
        )
        .expect("window inputs");
        executable(
            &request.podman_bin,
            r"#!/usr/bin/python3
import json, os, pathlib, signal, socket, sys
home = pathlib.Path.cwd()
f = json.loads((home / 'pre-driver-window.json').read_text())
args = sys.argv[1:]
window = f['window']
def save(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(value))
    path.chmod(0o600)
if args[:2] == ['image', 'inspect']:
    print('a' * 64)
elif '_make-home' in args:
    save(f['path'], f['seed'])
    if window == 'Prepare':
        sys.exit(9)
    if window == 'Executable':
        pathlib.Path(f['lane']).chmod(0o600)
    print('{}')
elif '_prepare-runtime' in args:
    stage = os.environ.get('SUPERLOOP_MATRIX_STAGE', '')
    if (window, stage) in [('Runtime', ''), ('PublishPrimary', 'publish-primary'), ('Deferred', 'prepare-deferred'), ('PublishDeferred', 'publish-deferred')]:
        sys.exit(9)
    if not stage:
        save(f['evidence'], {'runtime_argv': [] if window == 'Primary' else f['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/brief.txt', 'operation': 'read'}]}})
    if stage == 'prepare-deferred':
        save(f['evidence'], {'runtime_argv': f['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'measured', 'rows': [{'name': 'vendor-socket', 'state': 'deferred'}], 'deferred_source_row': {'name': 'vendor-socket', 'state': 'absent' if window == 'DeferredProbe' else 'pending', 'target': '/home/worker/.local/vendor/proxy.sock', 'operation': 'connect'}}})
    print('{}')
elif '--socket' in args:
    if window == 'Observer':
        sys.exit(9)
    channel = socket.socket(socket.AF_UNIX)
    path = args[args.index('--socket') + 1]
    channel.bind(path)
    os.chmod(path, 0o660)
    signal.pause()
elif args and args[0] == 'ps':
    pass
else:
    print('{}')
",
        );
        crate::launch::fixture_before_pre_driver_save(pad_pre_driver_save, identity);
        request.dry_run = false;
        let error = crate::launch::fixture_run_with_program(home, &request, lane_bin)
            .expect_err("startup refusal");
        fs::set_permissions(lane_bin, fs::Permissions::from_mode(0o700)).expect("restore lane");
        assert_eq!(error.kind, kind, "{name}: {error:?}");
        assert!(
            error
                .detail
                .contains("failure record save: reservation-size:"),
            "{name}: {error:?}"
        );
        assert_eq!(
            fs::metadata(&path).expect("original retained").len(),
            crate::launch::MAX_RESERVATION_BYTES
        );
        let retained = crate::launch::read_reservation(&path)
            .expect("bounded reader")
            .expect("original");
        assert_eq!(retained["phase"], "preparing");
        if let (Some(pid), Some(start)) = (
            retained["observer_pid"].as_u64(),
            retained["observer_start"].as_u64(),
        ) {
            assert_eq!(
                crate::container_helper::process_presence(u32::try_from(pid).expect("pid"), start),
                crate::container_helper::ProcessPresence::Absent
            );
        }
        fs::remove_file(&path).expect("release fixture UID");
    }
    fs::write(settings_path, settings).expect("restore settings");
}

#[allow(clippy::too_many_lines)]
fn helper_start_failure_windows(
    home: &std::path::Path,
    launch: &LaunchRequest,
    lane_bin: &std::path::Path,
) {
    let runs = home.join(".var/loops/alpha/runs");
    let vendor = home.join(".var/loops/alpha/sockets/vendor/proxy.sock");
    fs::remove_file(&vendor).expect("prior fixture socket");
    let _vendor = std::os::unix::net::UnixListener::bind(&vendor).expect("vendor socket");
    fs::set_permissions(&vendor, fs::Permissions::from_mode(0o660)).expect("vendor mode");
    for name in ["Before", "BeforeParent", "After", "SaveAfter"] {
        let before_spawn = name == "Before";
        let mut request = LaunchRequest::parse(
            &[
                "alpha",
                name,
                "--letter",
                launch.letter.to_str().expect("letter"),
                "--podman-bin",
                launch.podman_bin.to_str().expect("runtime"),
                "--dry-run",
            ]
            .map(String::from),
        )
        .expect("launch form");
        request.model = launch.model.clone();
        request.effort = launch.effort.clone();
        // Restore the image probe before deriving the next fixture's production plan.
        executable(
            &request.podman_bin,
            "#!/bin/sh\nprintf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        );
        let preview = run(home, &request).expect("public preview");
        let plan = &preview["plan"];
        let driver = std::path::Path::new(plan["driver_dir"].as_str().expect("driver"));
        let evidence = crate::plan::protected_identity_dir(driver)
            .expect("identity")
            .join("launch-evidence.json");
        let seed = json!({"schema":1,"phase":"preparing","loop":"alpha","run":name,"worker_uid":plan["worker_uid"],"plan":plan,"model_selection":preview["selection"]["model"],"probe_starts":[],"imports":[],"harvest_agreement":null,"collection":null,"observer_state":"not-started","helper_spawn_state":"not-started"});
        fs::write(
            home.join("helper-window.json"),
            json!({"seed":seed,"evidence":evidence,"lane":lane_bin,"before":before_spawn})
                .to_string(),
        )
        .expect("fixture inputs");
        executable(
            &request.podman_bin,
            r"#!/usr/bin/python3
import json, os, pathlib, socket, sys
home = pathlib.Path.cwd()
f = json.loads((home / 'helper-window.json').read_text())
args = sys.argv[1:]
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(value))
    path.chmod(0o600)
if args[:2] == ['image', 'inspect']:
    print('a' * 64)
elif '_make-home' in args:
    save(home / '.var/loops/alpha/runs' / ('.reservation-' + f['seed']['run'] + '.json'), f['seed'])
    print('{}')
elif '_prepare-runtime' in args:
    transfer = socket.socket(fileno=0)
    data, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(36))
    assert data == bytes([1]) and flags == 0 and len(ancillary) == 1
    assert len(ancillary[0][2]) == 36 and transfer.recv(1) == b''
    for offset in range(0, 36, 4):
        os.close(int.from_bytes(ancillary[0][2][offset:offset+4], sys.byteorder, signed=True))
    manifest = json.loads(args[args.index('--anchor-manifest') + 1])
    assert manifest['operation'] == 'prepare-runtime'
    assert [record['purpose'] for record in manifest['records']] == ['owner-home', 'runs-root', 'entry-executable', 'podman-executable', 'hash-executable', 'configuration', 'loop-storage', 'private-storage', 'identity-executable']
    if 'SUPERLOOP_MATRIX_STAGE' not in os.environ:
        save(pathlib.Path(f['evidence']), {'runtime_argv': f['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/brief.txt', 'operation': 'read'}]}})
    elif f['before'] and os.environ['SUPERLOOP_MATRIX_STAGE'] == 'publish-primary':
        pathlib.Path(f['lane']).chmod(0o600)
    print('{}')
elif '_container-helper' in args:
    transfer = socket.socket(fileno=0)
    data, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(32))
    assert data == bytes([1]) and flags == 0 and len(ancillary) == 1
    assert len(ancillary[0][2]) == 32 and transfer.recv(1) == b''
    for offset in range(0, 32, 4):
        os.close(int.from_bytes(ancillary[0][2][offset:offset+4], sys.byteorder, signed=True))
    manifest = json.loads(args[args.index('--anchor-manifest') + 1])
    assert [record['purpose'] for record in manifest['records']] == ['owner-home', 'runs-root', 'entry-executable', 'podman-executable', 'hash-executable', 'credential-client', 'credential-clock', 'configuration']
    sys.exit(9)
elif args and args[0] == 'ps':
    pass
else:
    print('{}')
",
        );
        request.dry_run = false;
        if name == "BeforeParent" || name == "SaveAfter" {
            crate::launch::fixture_before_helper_parent(|reservation| {
                let mut saved = crate::launch::read_reservation(reservation)
                    .expect("read before parent save")
                    .expect("preparing reservation");
                assert_eq!(saved["phase"], "preparing");
                assert_eq!(saved["helper_spawn_state"], "starting");
                assert!(saved["helper_parent_pid"].is_null());
                assert!(saved["helper_parent_start"].is_null());
                if saved["run"] == "SaveAfter" {
                    saved["fixture_padding"] = json!("");
                    let size = serde_json::to_vec(&saved)
                        .expect("encoded reservation")
                        .len();
                    let limit = usize::try_from(crate::launch::MAX_RESERVATION_BYTES)
                        .expect("reservation bound");
                    saved["fixture_padding"] = json!("x".repeat(limit - size));
                    crate::launch::publish_reservation(reservation, &saved)
                        .expect("valid reservation at the reader limit");
                }
                Err(crate::error::LaneError::operation(
                    "helper-parent-record",
                    "injected after spawn and before identity save",
                ))
            });
        }
        let refusal = crate::launch::fixture_run_with_program(home, &request, lane_bin)
            .expect_err("startup window refusal");
        fs::set_permissions(lane_bin, fs::Permissions::from_mode(0o700)).expect("restore lane");
        assert_eq!(
            refusal.kind,
            if before_spawn {
                "owner-program"
            } else if name == "BeforeParent" || name == "SaveAfter" {
                "helper-parent-record"
            } else {
                "helper-start"
            },
            "{refusal:?}"
        );
        let path = runs.join(format!(".reservation-{name}.json"));
        let mut saved = crate::launch::read_reservation(&path)
            .expect("reader")
            .expect("failed reservation");
        if name == "SaveAfter" {
            assert_eq!(refusal.status, 1);
            assert!(refusal.line().starts_with("helper-parent-record:"));
            assert!(
                refusal
                    .detail
                    .contains("failure record save: reservation-size:")
            );
            assert_eq!(saved["phase"], "preparing");
            assert_eq!(saved["helper_spawn_state"], "starting");
            assert!(saved["helper_parent_pid"].is_null());
            saved
                .as_object_mut()
                .expect("record")
                .remove("fixture_padding");
            saved["launcher_pid"] = json!(u32::MAX);
            saved["launcher_start"] = json!(1);
            crate::launch::publish_reservation(&path, &saved).expect("release padding");
            let retire = crate::launch::retire::RetireRequest::parse(
                &["alpha", name, "--dry-run"].map(String::from),
            )
            .expect("retire form");
            assert_eq!(
                crate::launch::retire::run(home, &retire)
                    .expect_err("unsaved evidence refuses")
                    .kind,
                "retire-uncertain"
            );
            assert!(path.exists());
            continue;
        }
        assert_eq!(saved["phase"], "failed");
        assert_eq!(saved["driver_end"]["state"], "not-started");
        assert_eq!(
            saved["helper_end"]["state"],
            if before_spawn {
                "not-started"
            } else {
                "completed"
            }
        );
        if before_spawn {
            assert_eq!(saved["helper_spawn_state"], "not-started");
            assert!(saved["helper_parent_pid"].is_null());
        } else {
            assert_eq!(saved["helper_spawn_state"], "running");
            assert_eq!(
                crate::container_helper::process_presence(
                    u32::try_from(saved["helper_parent_pid"].as_u64().expect("parent PID"))
                        .expect("PID range"),
                    saved["helper_parent_start"].as_u64().expect("parent tick"),
                ),
                crate::container_helper::ProcessPresence::Absent
            );
            assert_eq!(
                saved["helper_end"]["parent_pid"],
                saved["helper_parent_pid"]
            );
            assert_eq!(
                saved["helper_end"]["parent_start"],
                saved["helper_parent_start"]
            );
            assert_eq!(saved["helper_end"]["successful"], false);
            assert!(
                saved["helper_end"]["detail"]
                    .as_str()
                    .expect("startup refusal")
                    .contains(refusal.kind)
            );
        }
        if before_spawn {
            check_resumed_pre_spawn_retention(home, &request, lane_bin, &path, &saved);
            // The retained resume is not a recovered first dispatch. Restore this
            // fixture's original failed dispatch for its separate retirement check.
            crate::launch::publish_reservation(&path, &saved).expect("first-dispatch fixture");
            // This fixture models private verification without provisioning a mailbox.
            // Its synthetic binding must not turn the unborn retirement case into
            // a namespace-root retirement rehearsal.
            saved
                .as_object_mut()
                .expect("fixture reservation")
                .remove("mail_birth");
        }
        crate::launch::census::run(home, "alpha").expect("census reads startup failure");
        // The real launcher is this test process; model its later exit for retirement.
        saved["launcher_pid"] = json!(u32::MAX);
        saved["launcher_start"] = json!(1);
        crate::launch::publish_reservation(&path, &saved).expect("launcher ended");
        let mut retire = crate::launch::retire::RetireRequest::parse(
            &["alpha", name, "--dry-run"].map(String::from),
        )
        .expect("retire preview form");
        let preview = crate::launch::retire::run(home, &retire)
            .expect("startup failure has retirement route");
        retire.dry_run = false;
        retire.expect_digest = Some(preview["preview_sha256"].as_str().expect("digest").into());
        crate::launch::retire::run(home, &retire).expect("retire startup failure");
        assert!(!path.exists());
    }
}

#[allow(clippy::too_many_lines)]
fn check_resumed_pre_spawn_retention(
    home: &std::path::Path,
    request: &LaunchRequest,
    lane_bin: &std::path::Path,
    path: &std::path::Path,
    seed: &serde_json::Value,
) {
    let _mail_standin = crate::build::mail_standin::register(&request.podman_bin);
    let worker_home = std::path::Path::new(seed["plan"]["home"].as_str().expect("worker home"));
    let inbox = worker_home.join(".local/inbox");
    fs::create_dir_all(&inbox).expect("retained home inbox");
    for path in [
        home.join(".cache"),
        home.join(".cache/tmp"),
        worker_home.to_path_buf(),
        worker_home.join(".local"),
        inbox.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protected inbox ancestor");
    }
    let letter = b"Continue the work.\n";
    fs::write(inbox.join("next.md"), letter).expect("placed next letter");
    fs::set_permissions(inbox.join("next.md"), fs::Permissions::from_mode(0o600))
        .expect("private letter");
    for failure in ["inspect", "spawn"] {
        let mut saved = seed.clone();
        // Public previews enrich the plan; private reservations pin only the plan itself.
        for key in ["declared_sources", "reservation_census"] {
            saved["plan"].as_object_mut().expect("plan").remove(key);
        }
        saved["phase"] = json!("settled");
        saved["thread_id"] = json!("fixture-thread");
        saved["rounds"][0]["phase"] = json!("settled");
        saved["helper_spawn_state"] = json!("running");
        for field in ["driver_entry_pid", "helper_pid", "helper_parent_pid"] {
            saved[field] = json!(u32::MAX);
        }
        for field in ["driver_entry_start", "helper_start", "helper_parent_start"] {
            saved[field] = json!(1);
        }
        saved["mail_birth"] = json!({"name":"fixture","uid":saved["worker_uid"],"reservation":format!("superloop-lane:{}",request.run)});
        let birth = &saved["mail_birth"];
        let binding = json!({"worker_uid":birth["uid"],"step":"next","sender":"alpha","recipient":format!("alpha+{}",birth["name"].as_str().expect("birth name")),"delivery":"2026-01-01T00:00:00.000Z","journal_identity":"fixture-journal","inbox_name":"alpha.2026-01-01T00:00:00.000Z.letter","bytes":letter.len(),"evidence_digest":sha256(&inbox.join("next.md")).expect("letter hash"),"stop":false});
        saved["mail"]
            .as_array_mut()
            .expect("mail")
            .push(binding.clone());
        crate::launch::publish_reservation(path, &saved).expect("settled prior round");
        fs::write(
            home.join("resume-window.json"),
            json!({"failure":failure,"lane":lane_bin,"binding":binding}).to_string(),
        )
        .expect("resume fixture");
        executable(
            &request.podman_bin,
            r"#!/usr/bin/python3
import json, pathlib, sys
home = pathlib.Path.cwd()
f = json.loads((home / 'resume-window.json').read_text())
if '_bind-mail' in sys.argv:
    assert '--verify-only' in sys.argv, 'resume must not republish retained mail'
    print(json.dumps(f['binding']))
elif '--preflight-round' in sys.argv:
    print(json.dumps({'state':'passed',
        'step':sys.argv[sys.argv.index('--preflight-round')+1],
        'budget_seconds':int(sys.argv[sys.argv.index('--budget')+1]),'changed':False}))
elif '_inspect-round' in sys.argv:
    if '--record' in sys.argv:
        if f['failure'].startswith('inspect'):
            sys.exit(9)
        pathlib.Path(f['lane']).chmod(0o600)
    print(json.dumps({'thread_id': 'fixture-thread'}))
elif sys.argv[1:2] == ['ps']:
    pass
else:
    raise RuntimeError('unexpected spawn')
",
        );
        let resumed = LaunchRequest::parse(
            &[
                "alpha",
                request.run.as_str(),
                "--round",
                "next",
                "--podman-bin",
                request.podman_bin.to_str().expect("runtime"),
            ]
            .map(String::from),
        )
        .expect("resume form");
        let before = fs::read(path).expect("settled bytes before resume");
        let error = crate::launch::fixture_run_with_program(home, &resumed, lane_bin)
            .expect_err("resumed round fails before spawn");
        fs::set_permissions(lane_bin, fs::Permissions::from_mode(0o700)).expect("restore lane");
        assert_eq!(
            error.kind,
            if failure.starts_with("inspect") {
                "round-evidence"
            } else {
                "owner-program"
            },
            "{error:?}"
        );
        let retained = crate::launch::read_reservation(path)
            .expect("reader")
            .expect("retained round");
        // This fixture models verification, not the namespace cleanup/absence proof.
        assert!(error.detail.contains("; retained: "), "{error}");
        assert_eq!(retained["phase"], "preparing");
        assert_eq!(
            retained["round_rollback"]["before"],
            String::from_utf8(before).expect("JSON")
        );
        assert!(retained.get("dispatch_intent").is_none());
        assert_eq!(retained["helper_spawn_state"], "not-started", "{error}");
        assert!(retained["helper_end"].is_null());
        assert!(retained["driver_end"].is_null());
        assert!(retained["helper_parent_pid"].is_null());
        assert!(retained["helper_parent_start"].is_null());
        assert_eq!(retained["rounds"][1]["phase"], "running");
        assert_eq!(retained["rounds"][0]["phase"], "settled");
    }
}

const GENERATION_CONTENTION_NOTE: &str = "preparing-or-starting names are candidates whose generation hold may already be released; a possible unnamed holder has an unpublished reservation or launcher identity, or is another install, refresh or repair, including a preview, holding the generation lock";

#[allow(clippy::too_many_lines)]
fn refresh_during_changing_launch(
    home: &std::path::Path,
    launch: &LaunchRequest,
    install: &crate::install::InstallRequest,
    lane_bin: &std::path::Path,
    settings_source: &str,
    private_report: &serde_json::Value,
) {
    let custody = home.join(".config/loops/alpha");
    let runs = home.join(".var/loops/alpha/runs");
    fs::write(
        custody.join("workers.toml"),
        format!("{settings_source}vendor_hosts = {{ codex = [\"api.example.com\"] }}\n"),
    )
    .expect("enforcing settings");
    let vendor = home.join(".var/loops/alpha/sockets/vendor/proxy.sock");
    let _vendor = std::os::unix::net::UnixListener::bind(&vendor).expect("vendor socket");
    fs::set_permissions(&vendor, fs::Permissions::from_mode(0o660)).expect("vendor mode");
    let mut changing = LaunchRequest {
        backend: None,
        loop_name: launch.loop_name.clone(),
        run: "T".into(),
        letter: launch.letter.clone(),
        round: None,
        thread_choice: None,
        budget: launch.budget,
        dry_run: true,
        expect_digest: None,
        compute_workspace: None,
        observe: false,
        podman_bin: launch.podman_bin.clone(),
        proxy_bin: launch.proxy_bin.clone(),
        model: launch.model.clone(),
        effort: launch.effort.clone(),
        door_scope: crate::door::Scope::Work,
        rotation_source: None,
    };
    let preview = run(home, &changing).expect("changing fixture preview");
    changing.dry_run = false;
    let plan = &preview["plan"];
    let driver_dir = std::path::Path::new(plan["driver_dir"].as_str().expect("driver dir"));
    let identity = crate::plan::protected_identity_dir(driver_dir).expect("identity");
    let seed = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"T","worker_uid":plan["worker_uid"],"plan":plan,"model_selection":preview["selection"]["model"],"probe_starts":[]});
    fs::write(home.join("launch-fixture.json"), json!({"seed":seed,"evidence":identity.join("launch-evidence.json"),"private":private_report}).to_string()).expect("fixture inputs");
    // The stand-in supplies private child results and helper transport, while the
    // production launcher owns its locks, reservation updates and driver callback.
    executable(
        &changing.podman_bin,
        r"#!/usr/bin/python3
import json, os, pathlib, socket, sys, time
home = pathlib.Path.cwd()
fixture = json.loads((home / 'launch-fixture.json').read_text())
runs = home / '.var/loops/alpha/runs'
args = sys.argv[1:]
def wait(name):
    end = time.monotonic() + 30
    while not (home / name).exists():
        if time.monotonic() >= end:
            raise RuntimeError('fixture timeout: ' + name)
        time.sleep(.01)
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(value))
    path.chmod(0o600)
if args[:2] == ['image', 'inspect']:
    print('a' * 64)
elif 'lane-install-private' in args:
    if (home / 'preview-armed').exists():
        (home / 'preview-ready').touch()
        wait('preview-release')
    print(json.dumps(fixture['private']))
elif '_make-home' in args:
    (home / 'unpublished-ready').touch()
    wait('unpublished-release')
    save(runs / '.reservation-T.json', fixture['seed'])
    (home / 'unidentified-ready').touch()
    wait('unidentified-release')
    print('{}')
elif '_prepare-runtime' in args:
    transfer = socket.socket(fileno=0)
    data, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(36))
    assert data == bytes([1]) and flags == 0 and len(ancillary) == 1
    assert len(ancillary[0][2]) == 36 and transfer.recv(1) == b''
    for offset in range(0, 36, 4):
        os.close(int.from_bytes(ancillary[0][2][offset:offset+4], sys.byteorder, signed=True))
    manifest = json.loads(args[args.index('--anchor-manifest') + 1])
    assert manifest['operation'] == 'prepare-runtime'
    assert [record['purpose'] for record in manifest['records']] == ['owner-home', 'runs-root', 'entry-executable', 'podman-executable', 'hash-executable', 'configuration', 'loop-storage', 'private-storage', 'identity-executable']
    if 'SUPERLOOP_MATRIX_STAGE' not in os.environ:
        save(pathlib.Path(fixture['evidence']), {'runtime_argv': fixture['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/brief.txt', 'operation': 'read'}]}})
    print('{}')
elif '_container-helper' in args:
    transfer = socket.socket(fileno=0)
    data, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(32))
    assert data == bytes([1]) and flags == 0 and len(ancillary) == 1
    assert len(ancillary[0][2]) == 32 and transfer.recv(1) == b''
    for offset in range(0, 32, 4):
        os.close(int.from_bytes(ancillary[0][2][offset:offset+4], sys.byteorder, signed=True))
    manifest = json.loads(args[args.index('--anchor-manifest') + 1])
    assert [record['purpose'] for record in manifest['records']] == ['owner-home', 'runs-root', 'entry-executable', 'podman-executable', 'hash-executable', 'credential-client', 'credential-clock', 'configuration']
    (home / 'preparing-ready').touch()
    wait('preparing-release')
    request = socket.socket(socket.AF_UNIX)
    request.bind(str(runs / '.container-T.sock'))
    os.chmod(runs / '.container-T.sock', 0o660)
    control = socket.socket(socket.AF_UNIX)
    control.bind(str(runs / '.control-T.sock'))
    os.chmod(runs / '.control-T.sock', 0o600)
    control.listen(1)
    control.settimeout(30)
    client, _ = control.accept()
    assert client.recv(1) == b'C'
    client.sendall(b'K')
elif '_settle-evidence' in args or (args and args[0] == 'run'):
    print('{}')
else:
    print(json.dumps(fixture['private']))
",
    );
    executable(
        &home.join("entry-fixture"),
        r"#!/usr/bin/python3
import pathlib, sys, time
home = pathlib.Path.cwd()
(home / 'driver-ready').touch()
end = time.monotonic() + 30
while not (home / 'driver-release').exists():
    if time.monotonic() >= end:
        raise RuntimeError('driver fixture timeout')
    time.sleep(.01)
sys.exit(7)
",
    );
    let invoke = |request: &crate::install::InstallRequest| {
        crate::install::run_with_lane_bin(
            home,
            request,
            lane_bin,
            home,
            nix::unistd::Uid::effective().as_raw(),
        )
    };
    fs::write(home.join("preview-armed"), b"pause").expect("arm private preview");
    std::thread::scope(|scope| {
        let mut refresh = install.clone();
        refresh.dry_run = true;
        let preview = scope.spawn(move || invoke(&refresh));
        let began = std::time::Instant::now();
        while !home.join("preview-ready").exists() && !preview.is_finished() {
            assert!(
                began.elapsed().as_secs() < 35,
                "waiting for private preview"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            home.join("preview-ready").exists(),
            "preview stopped before private preflight: {:?}",
            preview.join()
        );
        changing.dry_run = true;
        assert_eq!(
            run(home, &changing).expect("launch shares preview generation hold")["dry_run"],
            true
        );
        let error = invoke(install).expect_err("preview still excludes a changing refresh");
        assert_eq!(error.kind, "install-busy");
        assert_eq!(error.detail, GENERATION_CONTENTION_NOTE);
        fs::write(home.join("preview-release"), b"go").expect("release private preview");
        assert_eq!(
            preview
                .join()
                .expect("preview thread")
                .expect("completed preview")["blocked"],
            false
        );
        changing.dry_run = false;
    });
    fs::remove_file(home.join("preview-armed")).expect("disarm private preview");
    std::thread::scope(|scope| {
        let launcher =
            scope.spawn(|| crate::launch::fixture_run_with_program(home, &changing, lane_bin));
        let wait = |marker: &str| {
            let began = std::time::Instant::now();
            while !home.join(marker).exists() && !launcher.is_finished() {
                assert!(began.elapsed().as_secs() < 35, "waiting for {marker}");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };
        for stage in ["unpublished", "unidentified"] {
            wait(&format!("{stage}-ready"));
            assert!(home.join(format!("{stage}-ready")).exists());
            let reservation = crate::launch::read_reservation(&runs.join(".reservation-T.json"))
                .expect("publication stage");
            if stage == "unpublished" {
                assert!(reservation.is_none());
            } else {
                let reservation = reservation.expect("published without identity");
                assert_eq!(reservation["phase"], "preparing");
                assert!(reservation.get("launcher_pid").is_none());
                assert!(reservation.get("launcher_start").is_none());
            }
            let mut refresh = install.clone();
            refresh.dry_run = true;
            let blocked = invoke(&refresh).expect("unpublished holder blocks preview");
            assert_eq!(blocked["blocked"], true);
            assert_eq!(blocked["busy"], json!([GENERATION_CONTENTION_NOTE]));
            refresh.dry_run = false;
            let error = invoke(&refresh).expect_err("unpublished holder blocks refresh");
            assert_eq!(error.kind, "install-busy");
            assert_eq!(error.detail, GENERATION_CONTENTION_NOTE);
            fs::write(home.join(format!("{stage}-release")), b"go").expect("release publication");
        }
        wait("preparing-ready");
        assert!(
            home.join("preparing-ready").exists(),
            "launcher stopped before preparation: {:?}",
            launcher.join()
        );
        let mut refresh = install.clone();
        refresh.dry_run = false;
        let preparing = crate::launch::read_reservation(&runs.join(".reservation-T.json"))
            .expect("production preparation")
            .expect("published preparing reservation");
        assert_eq!(preparing["phase"], "preparing");
        assert_eq!(preparing["launcher_pid"], std::process::id());
        assert_eq!(
            preparing["launcher_start"],
            crate::container_helper::process_start(std::process::id()).expect("launcher start")
        );
        assert!(preparing.get("driver_entry_pid").is_none());
        let error = invoke(&refresh).expect_err("preparing launch blocks refresh");
        assert_eq!(error.kind, "install-busy");
        assert!(
            error.detail.contains("run T (preparing-or-starting)"),
            "{error:?}"
        );
        assert!(error.detail.contains(GENERATION_CONTENTION_NOTE));
        refresh.dry_run = true;
        let blocked = invoke(&refresh).expect("preparing preview");
        assert_eq!(
            blocked["busy"],
            json!(["run T (preparing-or-starting)", GENERATION_CONTENTION_NOTE])
        );
        fs::write(home.join("preparing-release"), b"go").expect("release preparation");
        wait("driver-ready");
        assert!(
            home.join("driver-ready").exists(),
            "launcher stopped before driver: {:?}",
            launcher.join()
        );
        // The child may run before its parent's spawn callback. Wait for the
        // callback's published identity and the subsequent release, boundedly.
        let began = std::time::Instant::now();
        loop {
            match crate::install::lock_generation(&custody, true, false) {
                Ok(probe) => {
                    drop(probe);
                    break;
                }
                Err(error) => {
                    assert_eq!(error.kind, "install-busy");
                    assert!(
                        began.elapsed().as_secs() < 5,
                        "generation held after driver start"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
        let record = crate::launch::read_reservation(&runs.join(".reservation-T.json"))
            .expect("record")
            .expect("reservation");
        assert!(record["driver_entry_pid"].as_u64().is_some());
        assert_eq!(record["phase"], "preparing");
        assert_eq!(record["worker_uid"], 3000);
        assert!(!launcher.is_finished(), "driver remains live");
        let unpublished_hold = crate::install::lock_launch_generation(&custody, false)
            .expect("another launch holds generation before publication");
        let unnamed = runs.join(".reservation-U.json");
        for publish_identityless in [false, true] {
            if publish_identityless {
                crate::launch::publish_reservation(&unnamed, &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"U","worker_uid":3001,"plan":{}})).expect("reservation before launcher identity");
            }
            refresh.dry_run = true;
            let blocked =
                invoke(&refresh).expect("unpublished holder beside driver-started candidate");
            assert_eq!(blocked["blocked"], true);
            assert_eq!(
                blocked["busy"],
                json!(["run T (preparing-or-starting)", GENERATION_CONTENTION_NOTE])
            );
            refresh.dry_run = false;
            let error = invoke(&refresh).expect_err("unnamed hold still excludes changing refresh");
            assert_eq!(error.kind, "install-busy");
            assert_eq!(
                error.detail,
                format!("run T (preparing-or-starting), {GENERATION_CONTENTION_NOTE}")
            );
        }
        fs::remove_file(unnamed).expect("release unnamed reservation");
        drop(unpublished_hold);
        executable(
            &refresh.proxy_bin,
            "#!/bin/sh\n# proxy deployed while driver runs\nexit 0\n",
        );
        refresh.dry_run = false;
        let refreshed = invoke(&refresh).expect("refresh beside changing launcher after callback");
        assert_eq!(refreshed["changed"], 1);
        assert_eq!(refreshed["blocked"], false);
        assert!(
            !launcher.is_finished(),
            "refresh completes before driver exit"
        );
        fs::write(home.join("driver-release"), b"go").expect("release driver");
        let result = launcher
            .join()
            .expect("launcher thread")
            .expect_err("fixture has no held work cgroup for settlement");
        assert_eq!(result.kind, "run-reaping", "{result:?}");
        let ended = crate::launch::read_reservation(&runs.join(".reservation-T.json"))
            .expect("ended record")
            .expect("ended reservation");
        assert_eq!(ended["driver_end"]["state"], "completed");
        assert_eq!(ended["driver_end"]["successful"], false);
        assert!(
            ended["driver_end"]["detail"]
                .as_str()
                .expect("driver refusal")
                .contains("driver-launch")
        );
    });
}
