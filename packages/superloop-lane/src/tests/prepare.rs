use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::symlink;
use std::path::Path;

use tempfile::TempDir;

use crate::build::{self, BuildRequest, sha256};
use crate::install::{self, InstallRequest};
use crate::prepare::run_with_entry_bin;

fn executable(path: &Path, body: &str) {
    crate::fixture_exec::write_executable(path, format!("#!/bin/sh\n{body}\n").as_bytes())
        .expect("closed and synced fixture program");
}

fn empty_loop() -> (TempDir, std::path::PathBuf) {
    let fixture = TempDir::new_in("/tmp").expect("fixture root");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let config = home.join(".config/loops");
    fs::create_dir_all(&config).expect("configuration root");
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("config mode");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("loops mode");
    let runs = home.join("runs");
    fs::write(config.join("registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"work/alpha\", runs_root = \"{}\" }}]\n", runs.display())).expect("registry row");
    fs::set_permissions(
        config.join("registry.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("registry mode");
    let entry = home.join("superloop");
    executable(&entry, "exit 0");
    executable(
        &home.join("superloop-lane"),
        "if [ \"$5\" = --runtime-contract ]; then printf 'boxed-runtime 1\\n'; fi\nexit 0",
    );
    (fixture, entry)
}

/// ´test:crate:prepare-seeds-empty-configuration-and-repeats-without-writing´
#[test]
fn prepare_seeds_empty_configuration_and_repeats_without_writing() {
    let (fixture, entry) = empty_loop();
    let home = fixture.path();
    let settings = home.join(".config/loops/alpha/workers.toml");
    let ledger = home.join(".config/loops/allocations.toml");
    assert!(!home.join(".config/loops/alpha").exists());
    let preview = run_with_entry_bin(home, "alpha", true, &entry).expect("preview");
    assert!(preview["sign_in_metadata"]["group_repair"].is_null());
    assert!(!home.join(".config/loops/alpha").exists());
    assert_eq!(preview["would_write_settings"], true);
    assert_eq!(preview["would_seed_settings"][2], "driver_argv");
    assert_eq!(preview["would_seed_settings"][3], "resources");
    assert_eq!(preview["allocation"]["would_allocate"], true);
    assert!(!settings.exists());
    assert!(!ledger.exists());
    let first = run_with_entry_bin(home, "alpha", false, &entry).expect("first prepare");
    assert_eq!(first["changed"], 2);
    assert_eq!(first["settings_written"][2], "driver_argv");
    assert_eq!(first["settings_written"][3], "resources");
    assert!(
        fs::read_to_string(&settings)
            .expect("settings")
            .contains("vendor_hosts = { codex = [] }")
    );
    assert_eq!(
        fs::metadata(&settings)
            .expect("settings mode")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    // Provisioning adds service search to the shared host configuration roots.
    let service = nix::unistd::geteuid().as_raw() + 1;
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
    ] {
        loop_home::mail::acl::install(&fs::File::open(path).expect("root"), service, true)
            .expect("provisioning search grant");
    }
    for path in [&ledger, &home.join(".config/loops/registry.toml")] {
        loop_home::mail::acl::install(&fs::File::open(path).expect("file"), service, false)
            .expect("provisioning read grant");
    }
    let before = fs::read(&ledger).expect("ledger bytes");
    let settings_before = fs::read(&settings).expect("settings bytes");
    let second = run_with_entry_bin(home, "alpha", false, &entry).expect("repeat prepare");
    assert_eq!(second["changed"], 0);
    assert_eq!(second["settings_written"], serde_json::json!([]));
    assert_eq!(fs::read(&ledger).expect("ledger unchanged"), before);
    assert_eq!(
        fs::read(&settings).expect("settings unchanged"),
        settings_before
    );
}

/// ´test:crate:prepare-seeds-only-absent-launch-defaults´
#[test]
fn prepare_seeds_only_absent_launch_defaults() {
    let (fixture, entry) = empty_loop();
    let home = fixture.path();
    run_with_entry_bin(home, "alpha", false, &entry).expect("first prepare");
    let path = home.join(".config/loops/alpha/workers.toml");
    let mut parsed: toml::Value =
        toml::from_str(&fs::read_to_string(&path).expect("settings")).expect("parsed settings");
    let table = parsed.as_table_mut().expect("settings table");
    table.remove("driver_argv");
    table.insert(
        "resources".into(),
        toml::from_str::<toml::Value>(
            "resources = { memory_bytes = 4294967296, pids_max = 256, cpu_shares = 768 }",
        )
        .expect("custom resources")["resources"]
            .clone(),
    );
    fs::write(
        &path,
        toml::to_string_pretty(&parsed).expect("serialized settings"),
    )
    .expect("partial settings");
    let filled = run_with_entry_bin(home, "alpha", false, &entry).expect("seed missing driver");
    assert_eq!(filled["changed"], 1);
    assert_eq!(
        filled["settings_written"],
        serde_json::json!(["driver_argv"])
    );
    let after = crate::settings::Settings::read(&path).expect("filled settings");
    assert_eq!(after.resources.expect("preserved resources").pids_max, 256);
    let source = fs::read(&path).expect("filled bytes");
    assert_eq!(
        run_with_entry_bin(home, "alpha", false, &entry).expect("repeat")["changed"],
        0
    );
    assert_eq!(fs::read(&path).expect("unchanged bytes"), source);
}

/// ´test:crate:prepare-refuses-an-unverified-sibling-driver´
#[test]
fn prepare_refuses_an_unverified_sibling_driver() {
    let (fixture, entry) = empty_loop();
    let home = fixture.path();
    fs::remove_file(home.join("superloop-lane")).expect("remove driver fixture");
    let refusal = run_with_entry_bin(home, "alpha", false, &entry)
        .expect_err("missing sibling driver refuses");
    assert_eq!(refusal.kind, "owner-program");
    assert!(!home.join(".config/loops/alpha/workers.toml").exists());
}

/// ´test:crate:prepare-refuses-dangling-ledger-symlink-in-preview-and-live-run´
#[test]
fn prepare_refuses_dangling_ledger_symlink_in_preview_and_live_run() {
    let (fixture, entry) = empty_loop();
    let home = fixture.path();
    let ledger = home.join(".config/loops/allocations.toml");
    let missing = home.join(".config/loops/missing-ledger");
    symlink(&missing, &ledger).expect("dangling ledger symlink");
    for dry_run in [true, false] {
        let refusal = run_with_entry_bin(home, "alpha", dry_run, &entry)
            .expect_err("unsafe ledger is refused");
        assert_eq!(refusal.kind, "allocations-read");
        assert_eq!(refusal.status, 2);
        assert_eq!(
            fs::read_link(&ledger).expect("ledger symlink remains"),
            missing
        );
        assert!(!missing.exists());
    }
}

/// ´test:crate:installed-seed-requires-recorded-image-program-and-repeats´
#[test]
#[allow(clippy::too_many_lines)]
fn installed_seed_requires_recorded_image_program_and_repeats() {
    let (fixture, entry) = empty_loop();
    let home = fixture.path();
    fs::create_dir_all(home.join(".cache/tmp")).expect("build context parent");
    fs::set_permissions(home.join(".cache"), fs::Permissions::from_mode(0o700))
        .expect("cache mode");
    fs::set_permissions(home.join(".cache/tmp"), fs::Permissions::from_mode(0o700))
        .expect("tmp mode");
    assert_eq!(
        run_with_entry_bin(home, "alpha", false, &entry).expect("prepare")["changed"],
        2
    );
    let codex = home.join("codex");
    executable(
        &codex,
        "case \"$1 $2\" in 'exec --help') printf '%s\\n' '  -m, --model' '  -c, --config' '  --json' '  --sandbox' '  --add-dir' '  --skip-git-repo-check' '  -C, --cd' '  -o, --output-last-message';; *) printf 'codex-cli 0.1.0\\n';; esac",
    );
    let codex_host = home.join("codex-code-mode-host");
    executable(&codex_host, "printf 'Code mode host fixture\\n'");
    let podman = home.join("podman");
    executable(
        &podman,
        &format!(
            "case \"$1 $2\" in\n  'image exists') exit 0 ;;\n  'image inspect') printf '{}\\n' ;;\n  'build --pull=never') exit 0 ;;\n  'run --rm') printf 'ca-certificates 1\\ngit 2\\n' ;;\n  *) printf '{{\"schema\":1,\"changed\":0,\"source_fingerprint\":\"{}\",\"source_sha256\":{{\"codex\":\"{}\",\"codex_host\":\"{}\",\"init\":\"{}\"}},\"destinations\":[],\"hash_checks\":[1,2,3,4,5,6]}}\\n' ;;\nesac",
            "b".repeat(64),
            "a".repeat(64),
            sha256(&codex).expect("codex hash"),
            sha256(&codex_host).expect("host hash"),
            sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init"))
                .expect("init hash")
        ),
    );
    let build_request = BuildRequest {
        loop_name: "alpha".into(),
        claude: None,
        base_image: format!("registry.example/base@sha256:{}", "a".repeat(64)),
        codex_sha256: sha256(&codex).expect("codex hash"),
        codex_bin: codex,
        codex_host_sha256: sha256(&codex_host).expect("host hash"),
        codex_host_bin: codex_host,
        codex_version: "0.1.0".into(),
        codex_source: "https://registry.example/codex-0.1.0".into(),
        podman_bin: podman.clone(),
        template_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("data"),
        dry_run: false,
    };
    let pending = BuildRequest {
        dry_run: true,
        ..build_request.clone()
    };
    let before_build =
        fs::read(home.join(".config/loops/alpha/workers.toml")).expect("prepared settings");
    let build_preview = build::run(home, &pending).expect("build preview");
    assert_eq!(
        build_preview["would_seed_settings"][0],
        "backend_argv.codex"
    );
    assert_eq!(
        build_preview["codex_image_program"],
        "/usr/libexec/superloop/codex"
    );
    assert_eq!(
        fs::read(home.join(".config/loops/alpha/workers.toml")).expect("preview leaves settings"),
        before_build
    );
    let built = build::run(home, &build_request).expect("build after prepare");
    assert_eq!(built["action"], "build");
    assert_eq!(built["settings_written"][1], "backend_argv.codex");
    assert_eq!(
        crate::settings::Settings::read(&home.join(".config/loops/alpha/workers.toml"))
            .expect("seeded settings")
            .backend_argv["codex"],
        vec!["/usr/libexec/superloop/codex"]
    );
    let settings_path = home.join(".config/loops/alpha/workers.toml");
    let mut prior: toml::Value =
        toml::from_str(&fs::read_to_string(&settings_path).expect("built settings"))
            .expect("parsed built settings");
    prior["backend_argv"]
        .as_table_mut()
        .expect("backend table")
        .remove("codex");
    fs::write(
        &settings_path,
        toml::to_string_pretty(&prior).expect("prior format"),
    )
    .expect("prior settings");
    let repaired = build::run(home, &build_request).expect("reuse seeds absent backend");
    assert_eq!(repaired["action"], "reuse");
    assert_eq!(
        repaired["settings_written"],
        serde_json::json!(["backend_argv.codex"])
    );
    assert_eq!(repaired["changed"], true);
    let built_settings =
        fs::read(home.join(".config/loops/alpha/workers.toml")).expect("built settings bytes");
    assert_eq!(
        build::run(home, &build_request).expect("repeat build")["changed"],
        false
    );
    assert_eq!(
        fs::read(home.join(".config/loops/alpha/workers.toml")).expect("unchanged built settings"),
        built_settings
    );
    let proxy = home.join("proxy");
    executable(&proxy, "exit 0");
    let lane = home.join("superloop-lane");
    let install_request = InstallRequest {
        loop_name: "alpha".into(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: false,
        repair: false,
        podman_bin: Some(podman),
        data_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("data"),
        proxy_bin: proxy,
        unit_dir: None,
    };
    let first = install::run_with_lane_bin(
        home,
        &install_request,
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("first install");
    assert_eq!(first["allocation"]["allocated"], false);
    let second = install::run_with_lane_bin(
        home,
        &install_request,
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("repeat install");
    assert_eq!(second["changed"], 0);
    let installed = crate::settings::Settings::read(&settings_path).expect("installed settings");
    let template = installed.template_dir.expect("installed template path");
    let socket = installed.socket_dir.expect("installed socket path");
    fs::create_dir_all(template.join("bin")).expect("installed template directories");
    fs::create_dir_all(template.join("libexec")).expect("installed helper directory");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init"),
        template.join("libexec/box-init"),
    )
    .expect("installed private init fixture");
    fs::create_dir_all(socket.join("vendor")).expect("installed socket directories");
    fs::create_dir_all(home.join(".config/loops/alpha/lanes/codex")).expect("sign-in directory");
    fs::create_dir_all(home.join("runs")).expect("runs root");
    fs::copy(&build_request.codex_bin, template.join("bin/codex"))
        .expect("installed codex fixture");
    fs::copy(
        &build_request.codex_host_bin,
        template.join("bin/codex-code-mode-host"),
    )
    .expect("installed host fixture");
    fs::write(
        template.join("config.toml"),
        "sandbox_mode = \"workspace-write\"\n",
    )
    .expect("installed policy");
    fs::write(template.join("AGENTS.md"), "A worker charter.\n").expect("installed charter");
    let manifest = serde_json::json!({
        "image_digest":built["image_digest"],
        "codex_sha256":sha256(&template.join("bin/codex")).expect("codex hash"),
        "codex_host_sha256":sha256(&template.join("bin/codex-code-mode-host")).expect("host hash"),
        "config_sha256":sha256(&template.join("config.toml")).expect("policy hash"),
        "charter_sha256":sha256(&template.join("AGENTS.md")).expect("charter hash"),
    });
    fs::write(
        template.join("manifest"),
        serde_json::to_vec(&manifest).expect("manifest bytes"),
    )
    .expect("installed manifest");
    for (path, mode) in [
        (home.join(".var"), 0o700),
        (home.join(".var/loops"), 0o700),
        (home.join(".var/loops/alpha"), 0o700),
        (home.join(".var/loops/alpha/runner-templates"), 0o711),
        (home.join(".var/loops/alpha/runner-templates/codex"), 0o711),
        (template.join("bin"), 0o550),
        (template.join("libexec"), 0o550),
        (template.join("libexec/box-init"), 0o440),
        (template.join("bin/codex"), 0o550),
        (template.join("bin/codex-code-mode-host"), 0o550),
        (template.join("config.toml"), 0o440),
        (template.join("AGENTS.md"), 0o440),
        (template.join("manifest"), 0o440),
        (template.clone(), 0o550),
        (home.join("runs"), 0o700),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("installed mode");
    }
    let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let worker_unit = home.join(".config/systemd/user/superloop-lane-worker@alpha.service");
    assert!(!worker_unit.exists());
    let settled_preview = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: true,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("settled repair preview");
    assert_eq!(settled_preview["would_change"], serde_json::json!([]));
    assert_eq!(settled_preview["changed"], 0);
    let settled = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: false,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("settled repair");
    assert_eq!(settled["would_change"], serde_json::json!([]));
    assert_eq!(settled["changed"], 0);
    let settled_repeat = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: false,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("repeat settled repair");
    assert_eq!(settled_repeat["would_change"], serde_json::json!([]));
    assert_eq!(settled_repeat["changed"], 0);
    assert!(!worker_unit.exists());
    fs::write(&unit, b"[Unit]\nDescription=drift\n").expect("drifted unit");
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).expect("unit mode");
    let repair_preview = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: true,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("repair preview");
    assert_eq!(repair_preview["changed"], 1);
    assert_eq!(
        fs::read(&unit).expect("preview unit"),
        b"[Unit]\nDescription=drift\n"
    );
    let repaired = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: false,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("repair unit");
    assert_eq!(repair_preview["changed"], repaired["changed"]);
    assert!(repaired["changed"].as_u64().expect("changed count") > 0);
    let repeated = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: false,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("repeat repair");
    assert_eq!(repeated["changed"], 0);
    let intact_settings = fs::read_to_string(&settings_path).expect("intact settings");
    let drifted_settings = intact_settings.replace(
        built["image_digest"].as_str().expect("image pin"),
        &format!("sha256:{}", "c".repeat(64)),
    );
    fs::write(&settings_path, &drifted_settings).expect("drifted settings pin");
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).expect("unsafe unit mode");
    let refused = crate::repair::run_with_lane_bin(
        home,
        &crate::repair::RepairRequest {
            loop_name: "alpha".into(),
            dry_run: false,
        },
        &lane,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect_err("unsafe unit before pin change");
    assert_eq!(refused.kind, "repair-unit");
    assert_eq!(
        fs::read_to_string(&settings_path).expect("settings after refusal"),
        drifted_settings
    );
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).expect("restore unit mode");
    fs::write(&settings_path, intact_settings).expect("restore settings pin");
    let report_path = home.join(".config/loops/alpha/image-build.json");
    let generation_path = home.join(".config/loops/alpha/install-generation.json");
    let mut old_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("build report"))
            .expect("parsed build report");
    old_report["tools_commit"] = "earlier-tools-commit".into();
    old_report
        .as_object_mut()
        .expect("report object")
        .remove("codex_image_program");
    let historical_template = home.join("historical-template");
    fs::create_dir(&historical_template).expect("historical template directory");
    let historical_containerfile = historical_template.join("Containerfile");
    let current_containerfile = build_request.template_dir.join("Containerfile");
    fs::copy(&current_containerfile, &historical_containerfile)
        .expect("identical historical Containerfile");
    fs::copy(
        build_request.template_dir.join("box-init"),
        historical_template.join("box-init"),
    )
    .expect("identical historical init");
    assert_eq!(
        fs::read(&historical_containerfile).expect("historical bytes"),
        fs::read(&current_containerfile).expect("current bytes")
    );
    old_report["build_environment"]["template_dir"] =
        historical_template.display().to_string().into();
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&old_report).expect("old report"),
    )
    .expect("fixture old report");
    let mut old_generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("installed generation"))
            .expect("parsed generation");
    old_generation["tools_commit"] = "earlier-tools-commit".into();
    fs::write(
        &generation_path,
        serde_json::to_vec_pretty(&old_generation).expect("old generation"),
    )
    .expect("fixture old generation");
    let mut prior: toml::Value =
        toml::from_str(&fs::read_to_string(&settings_path).expect("installed settings"))
            .expect("parsed installed settings");
    prior["backend_argv"]
        .as_table_mut()
        .expect("backend table")
        .remove("codex");
    fs::write(
        &settings_path,
        toml::to_string_pretty(&prior).expect("old settings"),
    )
    .expect("fixture missing backend");
    executable(
        install_request
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        &format!(
            "if [ \"$1 $2\" = 'image exists' ]; then [ \"$3\" = '{}' ] && exit 1; exit 0; fi\nif [ \"$1 $2\" = 'image inspect' ]; then printf '{}\\n'; exit 0; fi\nexit 9",
            build_request.base_image,
            "b".repeat(64)
        ),
    );
    let report_before = fs::read(&report_path).expect("old report bytes");
    let generation_before = fs::read(&generation_path).expect("old generation bytes");
    let settings_before = fs::read(&settings_path).expect("old settings bytes");
    fs::remove_file(&historical_containerfile).expect("historical file gone");
    let missing_preview = build::run(home, &pending).expect_err("recorded program required");
    assert_eq!(missing_preview.kind, "build-report");
    assert_eq!(missing_preview.detail, "codex_image_program is absent");
    let missing_live = build::run(home, &build_request).expect_err("live seed also refuses");
    assert_eq!(missing_live.kind, "build-report");
    assert_eq!(missing_live.detail, "codex_image_program is absent");
    assert_eq!(
        fs::read(&settings_path).expect("settings unchanged"),
        settings_before
    );
    assert_eq!(
        fs::read(&report_path).expect("report unchanged"),
        report_before
    );
    assert_eq!(
        fs::read(&generation_path).expect("generation unchanged"),
        generation_before
    );
    fs::copy(&current_containerfile, &historical_containerfile)
        .expect("restore identical historical Containerfile");
    let matching_preview =
        build::run(home, &pending).expect_err("matching template is not a fallback");
    assert_eq!(matching_preview.kind, "build-report");
    assert_eq!(matching_preview.detail, "codex_image_program is absent");
    old_report["codex_image_program"] = built["codex_image_program"].clone();
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&old_report).expect("recorded program report"),
    )
    .expect("restore current report shape");
    let report_before = fs::read(&report_path).expect("current report bytes");
    let seed_preview = build::run(home, &pending).expect("installed seed preview");
    assert_eq!(seed_preview["action"], "seed-settings");
    assert_eq!(seed_preview["build_argv"], serde_json::Value::Null);
    assert_eq!(seed_preview["recorded_install_matches"], true);
    assert_eq!(seed_preview["local_image_available"], true);
    assert_eq!(
        seed_preview["probes_executed"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        seed_preview["would_seed_settings"],
        serde_json::json!(["backend_argv.codex"])
    );
    let seed = build::run(home, &build_request).expect("seed installed image setting");
    assert_eq!(seed["action"], "seed-settings");
    assert_eq!(
        seed["settings_written"],
        serde_json::json!(["backend_argv.codex"])
    );
    assert_eq!(
        fs::read(&report_path).expect("report unchanged"),
        report_before
    );
    assert_eq!(
        fs::read(&generation_path).expect("generation unchanged"),
        generation_before
    );
    assert_eq!(
        crate::settings::Settings::read(&settings_path)
            .expect("seeded settings")
            .image_digest,
        built["image_digest"].as_str().map(str::to_owned)
    );
    let seeded_settings = fs::read(&settings_path).expect("seeded settings bytes");
    let repeat_preview = build::run(home, &pending).expect("repeat seed preview");
    assert_eq!(repeat_preview["action"], "seed-settings");
    assert_eq!(repeat_preview["would_seed_settings"], serde_json::json!([]));
    assert_eq!(repeat_preview["build_argv"], serde_json::Value::Null);
    let repeat = build::run(home, &build_request).expect("repeat without base image");
    assert_eq!(repeat["action"], "seed-settings");
    assert_eq!(repeat["changed"], false);
    assert_eq!(repeat["settings_written"], serde_json::json!([]));
    assert_eq!(repeat["recorded_install_matches"], true);
    assert_eq!(repeat["local_image_available"], true);
    assert_eq!(
        fs::read(&settings_path).expect("settings unchanged"),
        seeded_settings
    );
    assert_eq!(
        fs::read(&report_path).expect("report unchanged"),
        report_before
    );
    assert_eq!(
        fs::read(&generation_path).expect("generation unchanged"),
        generation_before
    );
    let mut altered: toml::Value =
        toml::from_str(std::str::from_utf8(&seeded_settings).expect("seeded settings text"))
            .expect("seeded settings parse");
    altered["socket_dir"] = toml::Value::String(home.join("wrong-socket").display().to_string());
    fs::write(
        &settings_path,
        toml::to_string_pretty(&altered).expect("altered settings"),
    )
    .expect("alter socket");
    let socket_error = build::run(home, &pending).expect_err("mismatched installed socket");
    assert_eq!(socket_error.kind, "install-generation");
    fs::write(&settings_path, &seeded_settings).expect("restore settings");
    let podman_bytes = fs::read(
        install_request
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
    )
    .expect("podman fixture bytes");
    executable(
        install_request
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        "if [ \"$1 $2\" = 'image exists' ]; then exit 1; fi\nexit 9",
    );
    let image_error = build::run(home, &pending).expect_err("pruned installed image");
    assert_eq!(image_error.kind, "image-exists");
    fs::write(
        install_request
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        podman_bytes,
    )
    .expect("restore podman fixture");
    assert_eq!(
        fs::read(&settings_path).expect("settings still seeded"),
        seeded_settings
    );
    let allocations_path = home.join(".config/loops/allocations.toml");
    let mut allocations = loop_home::allocations::Allocations::read(&allocations_path)
        .expect("installed allocations");
    allocations
        .ensure_mail_groups("alpha", &[41001])
        .expect("fixture mail allocation");
    fs::write(
        &allocations_path,
        format!("mail_uid = 61000\n{}", allocations.to_toml()),
    )
    .expect("provisioned fixture allocation");
    let (plan, _) = crate::load_plan(
        home,
        "alpha",
        "pilot-1",
        (
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
        ),
    )
    .expect("plan after an empty-directory bootstrap");
    let printed = plan.json().expect("printed plan");
    let document: serde_json::Value = serde_json::from_str(&printed).expect("plan document");
    assert_eq!(document["run"], "pilot-1");
    assert_eq!(
        document["driver_bin"],
        home.join("superloop-lane").display().to_string()
    );
    let argv = document["runtime_argv"].as_array().expect("runtime vector");
    for (option, value) in [
        ("--memory", "2147483648"),
        ("--pids-limit", "128"),
        ("--cpu-shares", "512"),
    ] {
        assert!(argv.iter().any(|arg| arg == &format!("{option}={value}")));
    }
    let image_program = Path::new("/usr/libexec/superloop/codex");
    assert!(!image_program.exists());
    fs::remove_file(&historical_containerfile).expect("retire old build checkout template");
    let letter = home.join("letter");
    fs::write(&letter, "Launch this run.\n").expect("letter");
    let launch = crate::launch::LaunchRequest {
        loop_name: "alpha".into(),
        run: "pilot-1".into(),
        letter,
        round: None,
        budget: 3600,
        dry_run: true,
        expect_digest: None,
        observe: true,
        podman_bin: install_request
            .podman_bin
            .expect("selected fixture program"),
        proxy_bin: Some(home.join("proxy")),
        model: Some("gpt-6-sol".into()),
        effort: Some("high".into()),
        door_scope: crate::door::Scope::Work,
        rotation_source: None,
    };
    let preview = crate::launch::run_with_host_root(
        home,
        &launch,
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("launch preview uses image program, not a host path");
    assert_eq!(preview["dry_run"], true);
}
