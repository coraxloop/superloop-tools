use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

use crate::build::sha256;
use crate::install::{
    InstallRequest, install_allocation, lock_allocations, lock_loop_config, private_spec,
    run_proxy, run_with_lane_bin,
};

/// ´test:crate:shared-private-preflight-keeps-changing-install-exclusive´
#[test]
fn shared_private_preflight_keeps_changing_install_exclusive() {
    use std::os::fd::AsFd as _;
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let config = home.join("config");
    fs::create_dir(&config).expect("config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("config mode");
    let public = lock_loop_config(&config, true).expect("public shared preflight");
    let other = lock_loop_config(&config, true).expect("live launcher");
    let handed = crate::install::InstallGuard::from_handed_mode(
        &config,
        home,
        nix::unistd::Uid::effective().as_raw(),
        public
            .as_fd()
            .try_clone_to_owned()
            .expect("handed descriptor"),
        true,
    )
    .expect("private preflight binds shared beside launcher");
    handed
        .verify(&config, true)
        .expect("read-only private preflight");
    assert_eq!(
        handed
            .verify(&config, false)
            .expect_err("changing private work refuses shared")
            .kind,
        "install-lock"
    );
    assert!(lock_loop_config(&config, false).is_err());
    drop(handed);
    drop(public);
    drop(other);
    let exclusive = lock_loop_config(&config, false).expect("changing install");
    exclusive
        .verify(&config, false)
        .expect("exclusive requirement retained");
}

/// ´test:crate:allocation-writer-chooses-first-free-block-and-refuses-contention´
#[test]
fn allocation_writer_chooses_first_free_block_and_refuses_contention() {
    let fixture = TempDir::new_in("/tmp").expect("fixture root");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let parent = home.join(".config/loops");
    fs::create_dir_all(&parent).expect("allocation parent");
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("config mode");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("loops mode");
    write_registry_fixture(&parent);
    let path = parent.join("allocations.toml");
    fs::write(&path, "[alpha]\nuids = { base = 3000, count = 4 }\n").expect("existing allocation");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("ledger mode");
    let lock = lock_allocations(&path, false, false)
        .expect("lock")
        .expect("held lock");
    assert_eq!(
        install_allocation(home, "beta", true, false)
            .expect_err("busy ledger")
            .kind,
        "install-busy"
    );
    drop(lock);
    assert_eq!(
        install_allocation(home, "beta", true, true).expect("dry run")["base"],
        3004
    );
    assert!(
        !fs::read_to_string(&path)
            .expect("unchanged ledger")
            .contains("[beta]")
    );
    let written = install_allocation(home, "beta", true, false).expect("write allocation");
    assert_eq!(written["base"], 3004);
    assert_eq!(written["count"], 64);
    assert!(
        fs::read_to_string(path)
            .expect("written ledger")
            .contains("[beta]\nuids = { base = 3004, count = 64 }")
    );
}
use crate::install_private;

fn write_registry_fixture(parent: &Path) {
    let registry = parent.join("registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }, { name = \"beta\", uid = 41002, launch = \"dev/beta\" }]\n").expect("registry fixture");
    fs::set_permissions(registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
}

fn allocation_home() -> TempDir {
    let fixture = TempDir::new_in("/tmp").expect("fixture root");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let parent = home.join(".config/loops");
    fs::create_dir_all(&parent).expect("allocation parent");
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("config mode");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("loops mode");
    write_registry_fixture(&parent);
    fixture
}

/// ´test:crate:private-install-preflight-reaches-ledger-beneath-bound-home´
#[test]
fn private_install_preflight_reaches_ledger_beneath_bound_home() {
    let fixture = allocation_home();
    let home = fixture.path();
    let owner = nix::unistd::Uid::effective().as_raw();
    let settings_dir = home.join(".config/loops/alpha");
    fs::create_dir(&settings_dir).expect("settings directory");
    fs::set_permissions(&settings_dir, fs::Permissions::from_mode(0o700)).expect("settings mode");
    let settings_path = settings_dir.join("workers.toml");
    fs::write(
        &settings_path,
        "backend_argv = { codex = [\"/usr/bin/codex\"] }\n",
    )
    .expect("settings");
    fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o600))
        .expect("settings file mode");
    let ledger = home.join(".config/loops/allocations.toml");
    fs::write(&ledger, "[alpha]\nuids = { base = 3000, count = 64 }\n").expect("allocation");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("allocation mode");
    let inherited = fs::File::open(home).expect("verified home descriptor");
    crate::home::bind_private_home(home, &inherited, owner).expect("private descriptor matches");
    assert!(
        crate::settings::Settings::read_beneath(&settings_path, home)
            .expect("private settings")
            .configures("codex")
    );
    let root = home.join(".config/loops");
    let pinned =
        crate::home::pin_parent_beneath(&root, home, owner).expect("private configuration root");
    let block = loop_home::allocations::Allocations::read_beneath(&ledger, &root, &pinned)
        .expect("private allocation reader")
        .require("alpha")
        .expect("worker block");
    assert_eq!((block.base, block.count), (3000, 64));
}

/// ´test:crate:nonpilot-refusal-does-not-create-ledger´
#[test]
fn nonpilot_refusal_does_not_create_ledger() {
    let fixture = allocation_home();
    let ledger = fixture.path().join(".config/loops/allocations.toml");
    let error =
        install_allocation(fixture.path(), "alpha", false, false).expect_err("missing allocation");
    assert_eq!(error.kind, "allocations");
    assert!(!ledger.exists());
}

/// ´test:crate:allocation-writer-survives-restrictive-umask-and-stale-temp´
#[test]
fn allocation_writer_survives_restrictive_umask_and_stale_temp() {
    if let Some(home) = std::env::var_os("ALLOCATION_UMASK_TEST_HOME") {
        let home = Path::new(&home);
        let parent = home.join(".config/loops");
        let suffix =
            crate::install::NEXT_ALLOCATION_TEMP.load(std::sync::atomic::Ordering::Relaxed);
        let stale = parent.join(format!(".allocations-{}-{suffix}.tmp", std::process::id()));
        fs::write(&stale, "stale").expect("stale temporary");
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o000))
            .expect("interrupted temporary mode");
        assert!(!parent.join("allocations.toml").exists());
        let result = install_allocation(home, "alpha", true, false);
        assert_eq!(result.expect("allocation succeeds")["base"], 3000);
        let ledger = parent.join("allocations.toml");
        assert_eq!(
            fs::metadata(&ledger).expect("ledger").permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(&stale).expect("stale temporary remains").len(),
            5
        );
        assert_eq!(
            install_allocation(home, "alpha", true, false).expect("repeat")["allocated"],
            false
        );
        return;
    }
    let fixture = allocation_home();
    let output = Command::new("sh")
        .args(["-c", "umask 0777; exec \"$1\" \"$2\"", "sh"])
        .arg(std::env::current_exe().expect("test binary"))
        .arg("allocation_writer_survives_restrictive_umask_and_stale_temp")
        .env("ALLOCATION_UMASK_TEST_HOME", fixture.path())
        .output()
        .expect("child test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn make_parent(path: &Path) {
    fs::create_dir_all(path).expect("fixture parent");
}

fn executable(path: &Path, contents: &str) {
    crate::fixture_exec::write_executable(path, contents.as_bytes())
        .expect("closed and synced fixture program");
}

fn run(
    home: &Path,
    request: &InstallRequest,
) -> Result<serde_json::Value, crate::error::LaneError> {
    run_with_lane_bin(
        home,
        request,
        &home.join("lane-fixture"),
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
}

fn run_named_install_remedy(home: &Path, command: &str, original: &InstallRequest) {
    let parsed = crate::fixture_exec::output(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -- {command}; printf '%s\\0' \"$@\"")),
    )
    .expect("parse printed remedy");
    assert!(parsed.status.success());
    let words = parsed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8(word.to_vec()).expect("command word"))
        .collect::<Vec<_>>();
    assert_eq!(&words[..2], ["superloop-lane", "install"]);
    let mut arguments = words[2..].to_vec();
    arguments.extend([
        "--podman-bin".into(),
        original
            .podman_bin
            .as_deref()
            .expect("selected fixture program")
            .display()
            .to_string(),
        "--data-dir".into(),
        original.data_dir.display().to_string(),
    ]);
    if !arguments.iter().any(|argument| argument == "--proxy-bin") {
        arguments.extend([
            "--proxy-bin".into(),
            original.proxy_bin.display().to_string(),
        ]);
    }
    if let Some(unit_dir) = &original.unit_dir {
        arguments.extend(["--unit-dir".into(), unit_dir.display().to_string()]);
    }
    let request = InstallRequest::parse(&arguments).expect("printed remedy parses");
    let result = run(home, &request).expect("printed remedy succeeds");
    assert_eq!(
        result["proxy_bin"],
        original.proxy_bin.display().to_string()
    );
    if request.scope == crate::install::InstallScope::ProxyRecord {
        assert_eq!(
            result["changed"], 0,
            "full install already recorded the digest"
        );
    }
}

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(value).expect("fixture JSON")).expect("write JSON");
}

fn select_fixture_vendors(home: &Path, codex: bool, claude: bool, worker: u32) {
    use serde_json::json;
    use std::fmt::Write as _;
    let config = home.join(".config/loops/alpha");
    let settings_path = config.join("workers.toml");
    let mut settings: toml::Value =
        toml::from_str(&fs::read_to_string(&settings_path).expect("settings")).expect("TOML");
    let mut vendors = toml::map::Map::new();
    for (selected, name) in [(codex, "codex"), (claude, "claude")] {
        if selected {
            vendors.insert(name.into(), toml::Value::Array(Vec::new()));
        }
    }
    settings["vendor_hosts"] = toml::Value::Table(vendors);
    fs::write(settings_path, toml::to_string(&settings).expect("TOML")).expect("settings");
    fs::write(
        home.join(".config/loops/allocations.toml"),
        format!("[alpha]\nuids = {{ base = {worker}, count = 1 }}\n"),
    )
    .expect("allocation");
    let report_path = config.join("image-build.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report")).expect("JSON");
    report["base_image"] = json!(format!("registry.example/base@sha256:{}", "a".repeat(64)));
    report["codex_version"] = json!("0.1.0");
    report["codex_source"] = json!("https://fixture.example/codex");
    report["build_environment"]["podman_bin"] = json!(home.join("podman"));
    if !codex {
        for key in [
            "codex_sha256",
            "codex_host_sha256",
            "codex_image_program",
            "codex_version",
            "codex_source",
        ] {
            report.as_object_mut().expect("report object").remove(key);
        }
        for key in ["codex_bin", "codex_host_bin"] {
            report["build_environment"]
                .as_object_mut()
                .expect("environment")
                .remove(key);
        }
    }
    let claude_bin = home.join("claude");
    fs::copy("/usr/bin/true", &claude_bin).expect("native fixture");
    fs::set_permissions(&claude_bin, fs::Permissions::from_mode(0o700)).expect("program mode");
    let claude_hash = sha256(&claude_bin).expect("program hash");
    if claude {
        let mut help = String::new();
        for option in crate::build::payload::CLAUDE_EXEC_OPTIONS {
            writeln!(help, "  {option}").expect("help");
        }
        help.push_str("stream-json bypassPermissions acceptEdits plan\n");
        report["claude_version"] = json!("0.1.0");
        report["claude_sha256"] = json!(claude_hash);
        report["claude_source"] = json!("https://fixture.example/claude");
        report["claude_image_program"] = json!("/usr/libexec/superloop/claude");
        report["build_environment"]["claude_bin"] = json!(claude_bin);
        report["claude_exec_probe"] = json!({"argv":["--help"],"stdout":help,"required_options":crate::build::payload::CLAUDE_EXEC_OPTIONS,"claude_sha256":claude_hash,"image_digest":report["image_digest"],"companions":[]});
        report["claude_runtime"] = json!({"image_digest":report["image_digest"],"interpreter":{"path":"/lib64/ld-linux-x86-64.so.2","sha256":"c".repeat(64)},"libraries":[{"path":"/lib64/libc.so.6","sha256":"d".repeat(64)}]});
    }
    write_json(&report_path, &report);
    for name in ["private-current.json", "private-target.json"] {
        let path = home.join(name);
        let mut private: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("private report")).expect("JSON");
        if !codex {
            for key in ["codex", "codex_host"] {
                private["source_sha256"]
                    .as_object_mut()
                    .expect("source hashes")
                    .remove(key);
            }
        }
        if claude {
            private["source_sha256"]["claude"] = json!(claude_hash);
        }
        write_json(&path, &private);
    }
}

/// ´test:crate:configured-vendor-install-refresh-and-repair-inputs-share-generation´
#[test]
fn configured_vendor_install_refresh_and_repair_inputs_share_generation() {
    for worker in [3000, 3001] {
        for (codex, claude) in [(true, false), (false, true), (true, true)] {
            let (fixture, mut request) = refresh_fixture();
            let home = fixture.path();
            select_fixture_vendors(home, codex, claude, worker);
            request.pilot = false;
            let installed = run(home, &request).expect("configured full install");
            assert_eq!(installed["allocation"]["base"], worker);
            assert_ne!(worker, 41001, "registry loop identity differs");
            let vendors: Vec<_> = [(codex, "codex"), (claude, "claude")]
                .into_iter()
                .filter_map(|(selected, name)| selected.then_some(name))
                .collect();
            assert_eq!(installed["installed_backends"], serde_json::json!(vendors));
            assert_eq!(
                run(home, &request).expect("repeat full install")["changed"],
                0
            );
            request.pilot = true;
            assert_eq!(
                run(home, &request).expect("repeat pilot install")["changed"],
                0
            );
            let path = home.join(".config/loops/alpha/install-generation.json");
            let before: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("generation")).expect("JSON");
            assert_eq!(before.get("codex_sha256").is_some(), codex);
            assert_eq!(before.get("claude_sha256").is_some(), claude);
            executable(&request.proxy_bin, "#!/bin/sh\nexit 7\n");
            let refreshed = run(home, &refresh_request(&request)).expect("proxy-only refresh");
            assert_eq!(refreshed["changed"], 1);
            let after: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("generation")).expect("JSON");
            for key in [
                "codex_sha256",
                "codex_host_sha256",
                "claude_sha256",
                "claude_image_program",
                "claude_template_dir",
                "source_fingerprint",
            ] {
                assert_eq!(before.get(key), after.get(key), "refresh retained {key}");
            }
            let built: serde_json::Value = serde_json::from_slice(
                &fs::read(home.join(".config/loops/alpha/image-build.json")).expect("report"),
            )
            .expect("JSON");
            let reconstructed = crate::repair::build_request(
                &crate::repair::RepairRequest {
                    loop_name: "alpha".into(),
                    dry_run: true,
                },
                &built,
            )
            .expect("repair reconstructs actual payload set");
            assert_eq!(!reconstructed.codex_bin.as_os_str().is_empty(), codex);
            assert_eq!(reconstructed.claude.is_some(), claude);
            if let Some(input) = reconstructed.claude {
                assert_eq!(input.sha256, built["claude_sha256"]);
            }
        }
    }
}

// The private child keeps separate observed and post-install states. Only a changing
// invocation carrying the public fingerprint may publish the latter and its payload.
fn refresh_fixture() -> (TempDir, InstallRequest) {
    let fixture = allocation_home();
    let home = fixture.path();
    let custody = home.join(".config/loops/alpha");
    fs::create_dir(&custody).expect("custody");
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
    for name in [
        "lane-fixture",
        "entry-fixture",
        "codex",
        "codex-host",
        "proxy",
    ] {
        executable(&home.join(name), "#!/bin/sh\nexit 0\n");
    }
    let data = home.join("data");
    fs::create_dir(&data).expect("data");
    for name in ["box-init", "vendor-proxy.service.in", "worker.service.in"] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(name),
            data.join(name),
        )
        .expect("source");
    }
    let digest = sha256(&home.join("codex")).expect("Codex digest");
    let init = sha256(&data.join("box-init")).expect("init digest");
    let image = format!("sha256:{}", "a".repeat(64));
    let settings = custody.join("workers.toml");
    fs::write(
        &settings,
        format!(
            "entry_bin = \"{}\"\nimage_digest = \"{image}\"\nvendor_hosts = {{ codex = [] }}\n",
            home.join("entry-fixture").display()
        ),
    )
    .expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    write_json(
        &custody.join("image-build.json"),
        &serde_json::json!({"image_digest":image,"codex_sha256":digest,"codex_host_sha256":digest,"init_sha256":init,"codex_image_program":"/usr/libexec/superloop/codex","tools_commit":"fixture","build_environment":{"codex_bin":home.join("codex"),"codex_host_bin":home.join("codex-host"),"template_dir":data}}),
    );
    install_allocation(home, "alpha", true, false).expect("allocation");
    let target = serde_json::json!({"schema":1,"changed":0,"source_fingerprint":"a".repeat(64),"source_sha256":{"codex":digest,"codex_host":digest,"init":init},"destinations":[{"path":home.join("private-payload"),"exists":true,"complete":true}],"charter_refresh":false,"sign_in":{"changes":[]},"hash_checks":[]});
    write_json(&home.join("private-target.json"), &target);
    let mut current = target;
    current["destinations"][0]["exists"] = serde_json::json!(false);
    current["destinations"][0]["complete"] = serde_json::json!(false);
    write_json(&home.join("private-current.json"), &current);
    executable(
        &home.join("podman"),
        &format!(
            "#!/bin/sh\nset -eu\ncd '{}'\nif test -f private-failure; then cat private-failure >&2; exit 2; fi\ncase \" $* \" in\n*' --dry-run '*) if test -f publication-block; then chmod 500 .config/loops/alpha; fi; cat private-current.json ;;\n*) case \" $* \" in *' --expected-source-sha256 '*) ;; *) exit 9 ;; esac\nprintf 'changing\\n' >> private-invocations\ncp private-target.json private-current.json\nprintf 'installed\\n' > private-payload\ncat private-current.json ;;\nesac\n",
            home.display()
        ),
    );
    let request = InstallRequest {
        loop_name: "alpha".into(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: false,
        repair: false,
        podman_bin: Some(home.join("podman")),
        data_dir: data,
        proxy_bin: home.join("proxy"),
        unit_dir: None,
    };
    (fixture, request)
}

fn refresh_request(installed: &InstallRequest) -> InstallRequest {
    InstallRequest {
        scope: crate::install::InstallScope::ProxyRecord,
        ..installed.clone()
    }
}

// This unprivileged fixture drives public install with a stubbed template report.
// It proves real sign-in metadata convergence, public preview/act count parity,
// repeat-zero behavior and the named refusal for a mismatched act count. It does
// not prove template copying, namespace admission or private descriptor transfer.
// The production path is main's _install-private -> run_payloads -> converge ->
// with_sign_in; vendor_private_entry_installs_configured_payloads_for_two_workers
// exercises that binary entry with transferred descriptors and count assertions.
// That test requires provisioned namespace root and mapped loop/worker UIDs.
// Measured on r002f43's node on 2026-10-23: the node account's unshare --user --map-root-user
// refused Operation not permitted, and podman/newuidmap were absent. Do not count
// the ignored namespace test as successful private-entry coverage in that gate.
/// ´test:crate:pilot-install-counts-each-sign-in-operation-in-preview-and-act´
#[test]
#[allow(clippy::too_many_lines)]
fn pilot_install_counts_each_sign_in_operation_in_preview_and_act() {
    if let Some(path) = std::env::var_os("SUPERLOOP_COUNT_HOME") {
        let home = Path::new(&path);
        let dry = std::env::var_os("SUPERLOOP_COUNT_DRY").is_some();
        let base: serde_json::Value = serde_json::from_slice(
            &fs::read(home.join("count-base.json")).expect("private template report"),
        )
        .expect("report JSON");
        let sign_in = crate::sign_in::converge(
            home,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
            3000,
            dry,
        )
        .expect("production sign-in convergence");
        let mut report = crate::install_private::with_sign_in(base, sign_in)
            .expect("production private accounting");
        if !dry && home.join("count-mismatch").exists() {
            report["changed"] = serde_json::json!(report["changed"].as_u64().expect("count") + 1);
        }
        write_json(&home.join("count-result.json"), &report);
        return;
    }
    let (fixture, mut request) = refresh_fixture();
    let home = fixture.path();
    run(home, &request).expect("initial public installation");
    let sign_in = home.join(".config/loops/alpha/lanes/codex");
    fs::create_dir_all(sign_in.join("sessions")).expect("sign-in tree");
    fs::set_permissions(
        sign_in.parent().expect("lanes"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("lanes mode");
    fs::set_permissions(&sign_in, fs::Permissions::from_mode(0o700)).expect("root mode");
    fs::set_permissions(sign_in.join("sessions"), fs::Permissions::from_mode(0o755))
        .expect("directory drift");
    for name in ["auth.json", "sessions/one.json", "sessions/two.json"] {
        fs::write(sign_in.join(name), b"synthetic fixture state").expect("sign-in file");
        fs::set_permissions(sign_in.join(name), fs::Permissions::from_mode(0o644))
            .expect("file drift");
    }
    let mut base: serde_json::Value = serde_json::from_slice(
        &fs::read(home.join("private-target.json")).expect("template report"),
    )
    .expect("JSON");
    base["destinations"] = serde_json::json!([{"path":sign_in,"exists":true,"complete":true}]);
    write_json(&home.join("count-base.json"), &base);
    executable(
        request
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        &format!(
            "#!/bin/sh\nset -eu\ncase \" $* \" in *' --dry-run '*) export SUPERLOOP_COUNT_DRY=1 ;; *) unset SUPERLOOP_COUNT_DRY ;; esac\nexport SUPERLOOP_COUNT_HOME='{}'\n'{}' --exact tests::install::pilot_install_counts_each_sign_in_operation_in_preview_and_act > /dev/null\ncat '{}/count-result.json'\n",
            home.display(),
            std::env::current_exe().expect("test executable").display(),
            home.display()
        ),
    );
    request.dry_run = true;
    let preview = run(home, &request).expect("pilot preview");
    assert_eq!(
        preview["change_counts"]["private_destination_and_sign_in_operations"],
        4
    );
    assert_eq!(preview["changed"], 4);
    assert_eq!(
        fs::metadata(sign_in.join("auth.json"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    request.dry_run = false;
    let acted = run(home, &request).expect("pilot act");
    assert_eq!(acted["changed"], preview["changed"]);
    assert_eq!(acted["change_counts"], preview["change_counts"]);
    request.dry_run = true;
    assert_eq!(run(home, &request).expect("repeat preview")["changed"], 0);
    fs::write(home.join("count-mismatch"), b"unexpected act").expect("mismatch fixture");
    request.dry_run = false;
    let error = run(home, &request).expect_err("act count must match preflight");
    assert_eq!(error.kind, "install-private");
    assert!(error.detail.contains("change count differs from preview"));
    // A missing sign-in root is created by the template writer, once, in both forms.
    let creation = serde_json::json!({"changes":[{"path":sign_in,"action":"create-directory"}]});
    base["changed"] = serde_json::json!(1);
    base["destinations"][0]["complete"] = serde_json::json!(false);
    assert_eq!(
        crate::install_private::with_sign_in(base.clone(), creation).expect("creation preview")["changed"],
        1
    );
    assert_eq!(
        crate::install_private::with_sign_in(base.clone(), serde_json::json!({"changes":[]}))
            .expect("creation act")["changed"],
        1
    );
    base.as_object_mut().expect("report").remove("changed");
    assert_eq!(
        crate::install_private::with_sign_in(base, serde_json::json!({"changes":[]}))
            .expect_err("missing count refuses")
            .kind,
        "install-private"
    );
}

fn assert_refresh_directory_custody(error: &crate::error::LaneError, path: &Path) {
    let expected = format!(
        "install-conflict: {} differs: expected directory uid={} gid={} mode=0700; ",
        path.display(),
        nix::unistd::Uid::effective(),
        nix::unistd::Gid::effective()
    );
    assert!(error.detail.starts_with(&expected), "{error:?}");
}

/// ´test:crate:refresh-refusal-sites-execute-against-installed-fixture´
#[test]
fn refresh_refusal_sites_execute_against_installed_fixture() {
    use serde_json::json;
    for case in [
        "unfinished",
        "proxy",
        "source",
        "pending",
        "unit-directory",
        "worker-unit",
        "retired-directory",
        "oversized",
        "invalid",
    ] {
        let (fixture, installed) = refresh_fixture();
        let home = fixture.path();
        run(home, &installed).expect("installed baseline");
        let generation_path = home.join(".config/loops/alpha/install-generation.json");
        let mut generation: serde_json::Value =
            serde_json::from_slice(&fs::read(&generation_path).expect("generation")).expect("JSON");
        let private_path = home.join("private-current.json");
        let mut private: serde_json::Value =
            serde_json::from_slice(&fs::read(&private_path).expect("private")).expect("JSON");
        let units = home.join(".config/systemd/user");
        let expected = match case {
            "unfinished" => {
                generation["phase"] = json!("preparing");
                generation["proxy_sha256"] = json!("b".repeat(64));
                write_json(&generation_path, &generation);
                "unfinished different generation"
            }
            "proxy" => {
                generation
                    .as_object_mut()
                    .expect("object")
                    .remove("proxy_bin");
                write_json(&generation_path, &generation);
                "recorded proxy_bin is absent"
            }
            "source" => {
                private["source_sha256"]["init"] = json!("b".repeat(64));
                write_json(&private_path, &private);
                "private source snapshot init"
            }
            "pending" => {
                generation["phase"] = json!("preparing");
                generation["source_fingerprint"] = json!("b".repeat(64));
                write_json(&generation_path, &generation);
                "names another source snapshot"
            }
            "unit-directory" => {
                private["charter_refresh"] = json!(true);
                write_json(&private_path, &private);
                fs::set_permissions(&units, fs::Permissions::from_mode(0o755))
                    .expect("unsafe units");
                "user"
            }
            "worker-unit" => {
                private["charter_refresh"] = json!(true);
                write_json(&private_path, &private);
                let worker = units.join("superloop-lane-worker@alpha.service");
                fs::write(&worker, "unsafe").expect("worker");
                fs::set_permissions(worker, fs::Permissions::from_mode(0o777))
                    .expect("unsafe worker");
                "superloop-lane-worker@alpha.service"
            }
            "retired-directory" => {
                private["charter_refresh"] = json!(true);
                write_json(&private_path, &private);
                let retired = units.join("retired");
                fs::create_dir_all(&retired).expect("retired");
                fs::set_permissions(retired, fs::Permissions::from_mode(0o755))
                    .expect("unsafe retired");
                "retired"
            }
            "oversized" => {
                fs::write(&private_path, "x".repeat(65537)).expect("oversized report");
                "private report exceeds"
            }
            "invalid" => {
                fs::write(&private_path, "not JSON").expect("invalid report");
                "invalid private report"
            }
            _ => unreachable!(),
        };
        let error = run(home, &refresh_request(&installed)).expect_err(case);
        assert_eq!(error.kind, "install-proxy-refresh", "{case}: {error:?}");
        if matches!(case, "unit-directory" | "retired-directory") {
            let path = if case == "unit-directory" {
                units
            } else {
                units.join("retired")
            };
            assert_refresh_directory_custody(&error, &path);
        } else {
            assert!(error.detail.contains(expected), "{case}: {error:?}");
        }
    }
}

/// ´test:crate:refresh-unsafe-vendor-unit-remedy-restores-custody´
#[test]
fn refresh_unsafe_vendor_unit_remedy_restores_custody() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("installed baseline");
    let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let private_path = home.join("private-current.json");
    let mut private: serde_json::Value =
        serde_json::from_slice(&fs::read(&private_path).expect("private")).expect("JSON");
    private["charter_refresh"] = serde_json::json!(true);
    write_json(&private_path, &private);
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o666)).expect("unsafe unit");
    let error = run(home, &refresh_request(&installed)).expect_err("custody refusal");
    assert!(error.detail.contains("restore safe custody"), "{error:?}");
    assert!(!error.detail.contains("run superloop-lane repair"));
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).expect("restore custody");
    private["charter_refresh"] = serde_json::json!(false);
    write_json(&private_path, &private);
    run(home, &refresh_request(&installed)).expect("restored prerequisite");
}

/// ´test:crate:refresh-incomplete-generation-unit-remedy-does-not-name-repair´
#[test]
fn refresh_incomplete_generation_unit_remedy_does_not_name_repair() {
    for absent in [true, false] {
        let (fixture, installed) = refresh_fixture();
        let home = fixture.path();
        run(home, &installed).expect("installed baseline");
        let generation = home.join(".config/loops/alpha/install-generation.json");
        if absent {
            fs::remove_file(&generation).expect("absent generation");
        } else {
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&generation).expect("generation")).expect("JSON");
            value["phase"] = serde_json::json!("preparing");
            write_json(&generation, &value);
        }
        let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
        fs::write(&unit, "conflicting unit\n").expect("unit drift");
        let error = run(home, &refresh_request(&installed)).expect_err("incomplete generation");
        assert!(
            error.detail.contains("remove the conflicting unit"),
            "{error:?}"
        );
        assert!(!error.detail.contains("run superloop-lane repair"));
        fs::remove_file(unit).expect("remove conflicting unit");
        run(home, &installed).expect("full installation completes");
        run(home, &refresh_request(&installed)).expect("refresh after completion");
    }
}

fn run_full_refresh_remedy(home: &Path, detail: &str, installed: &InstallRequest) {
    let first = detail
        .split_once(", run ")
        .expect("full remedy")
        .1
        .split_once(" without --refresh-proxy")
        .expect("full form")
        .0;
    run_named_install_remedy(home, first, installed);
    let second = detail
        .split_once("; then run ")
        .expect("refresh remedy")
        .1
        .split_once(" with those same options.")
        .expect("retained options")
        .0;
    run_named_install_remedy(home, second, installed);
}

/// ´test:crate:refresh-absent-and-pending-generations-run-named-install´
#[test]
fn refresh_absent_and_pending_generations_run_named_install() {
    for state in ["fresh", "absent", "preparing"] {
        let (fixture, installed) = refresh_fixture();
        let home = fixture.path();
        let generation = home.join(".config/loops/alpha/install-generation.json");
        if state != "fresh" {
            run(home, &installed).expect("initial install");
            if state == "absent" {
                fs::remove_file(&generation).expect("absent generation");
            } else {
                let mut record: serde_json::Value =
                    serde_json::from_slice(&fs::read(&generation).expect("record")).expect("JSON");
                record["phase"] = serde_json::json!("preparing");
                write_json(&generation, &record);
            }
        }
        let error = run(home, &refresh_request(&installed)).expect_err("no complete generation");
        assert_eq!(error.kind, "install-proxy-refresh");
        assert!(
            error
                .detail
                .starts_with("completed pilot generation is absent;")
        );
        run_full_refresh_remedy(home, &error.detail, &installed);
        assert_eq!(
            crate::install::read_generation(&generation)
                .expect("record")
                .expect("present")["phase"],
            "complete"
        );
        assert!(home.join("private-payload").is_file());
    }
}

/// ´test:crate:refresh-private-changes-run-stateful-named-install´
#[test]
fn refresh_private_changes_run_stateful_named_install() {
    for field in [
        "source_fingerprint",
        "charter",
        "private destinations",
        "sign-in metadata",
    ] {
        for mixed in [false, true] {
            let (fixture, installed) = refresh_fixture();
            let home = fixture.path();
            run(home, &installed).expect("initial install");
            let current_path = home.join("private-current.json");
            let mut current: serde_json::Value =
                serde_json::from_slice(&fs::read(&current_path).expect("private state"))
                    .expect("JSON");
            let mut target = current.clone();
            match field {
                "source_fingerprint" => {
                    current[field] = serde_json::json!("b".repeat(64));
                    target[field] = current[field].clone();
                }
                "charter" => current["charter_refresh"] = serde_json::json!(true),
                "private destinations" => {
                    current["destinations"][0]["complete"] = serde_json::json!(false);
                }
                _ => current["sign_in"]["changes"] = serde_json::json!([{"action":"repair"}]),
            }
            write_json(&current_path, &current);
            write_json(&home.join("private-target.json"), &target);
            fs::remove_file(home.join("private-payload")).expect("pending private work");
            let before = fs::read_to_string(home.join("private-invocations")).expect("invocations");
            let mut refresh = refresh_request(&installed);
            if mixed {
                refresh.proxy_bin = home.join("alternate-proxy");
                executable(&refresh.proxy_bin, "#!/bin/sh\nexit 0\n");
            }
            let error = run(home, &refresh).expect_err("private work precedes proxy remedy");
            assert_eq!(error.kind, "install-proxy-refresh");
            assert!(
                error.detail.starts_with(&format!("{field} differs from")),
                "{error:?}"
            );
            assert!(!home.join("private-payload").exists());
            assert_eq!(
                fs::read_to_string(home.join("private-invocations")).expect("no mutation"),
                before
            );
            run_full_refresh_remedy(home, &error.detail, &installed);
            assert_eq!(
                fs::read_to_string(home.join("private-invocations")).expect("changing invocation"),
                format!("{before}changing\n")
            );
            assert_eq!(
                fs::read(&current_path).expect("converged"),
                fs::read(home.join("private-target.json")).expect("target")
            );
            assert_eq!(
                fs::read_to_string(home.join("private-payload")).expect("payload"),
                "installed\n"
            );
        }
    }
}

/// ´test:crate:refresh-malformed-preflight-names-producer-restoration´
#[test]
fn refresh_malformed_preflight_names_producer_restoration() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    let state = home.join("private-current.json");
    let good: serde_json::Value =
        serde_json::from_slice(&fs::read(&state).expect("state")).expect("JSON");
    let mut refresh = refresh_request(&installed);
    refresh.proxy_bin = home.join("alternate-proxy");
    executable(&refresh.proxy_bin, "#!/bin/sh\nexit 0\n");
    for (field, bad) in [
        ("source_fingerprint", serde_json::Value::Null),
        ("source_fingerprint", serde_json::json!("short")),
        ("source_fingerprint", serde_json::json!("A".repeat(64))),
        ("source_fingerprint", serde_json::json!("z".repeat(64))),
        ("destinations", serde_json::Value::Null),
        ("destinations", serde_json::json!([{"complete":"yes"}])),
        ("sign_in", serde_json::json!({})),
        ("sign_in", serde_json::json!({"changes":false})),
        ("charter_refresh", serde_json::json!("yes")),
    ] {
        let mut broken = good.clone();
        broken[field] = bad;
        write_json(&state, &broken);
        let error = run(home, &refresh).expect_err("malformed producer before proxy advice");
        assert_eq!(error.kind, "install-proxy-refresh");
        assert!(
            error.detail.contains("working private preflight"),
            "{error:?}"
        );
        assert!(!error.detail.contains("run superloop-lane install"));
        write_json(&state, &good);
        let correction = run(home, &refresh).expect_err("only proxy remains");
        let command = correction
            .detail
            .split_once("; run ")
            .expect("correction")
            .1
            .split_once(", keeping ")
            .expect("options")
            .0;
        run_named_install_remedy(home, command, &installed);
    }
}

/// ´test:crate:refresh-private-failures-preserve-stderr-and-run-restoration´
#[test]
fn refresh_private_failures_preserve_stderr_and_run_restoration() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    for detail in [
        "install-source: source differs from pinned bytes",
        "install-destination: destination is unreadable",
        "install-conflict: destination has altered type, owner or mode",
        "sign-in-path: sign-in is neither a directory nor a regular file",
    ] {
        for mixed in [false, true] {
            fs::write(home.join("private-failure"), detail).expect("private failure");
            let mut refresh = refresh_request(&installed);
            if mixed {
                refresh.proxy_bin = home.join("alternate-proxy");
                executable(&refresh.proxy_bin, "#!/bin/sh\nexit 0\n");
            }
            let error = run(home, &refresh).expect_err("private prerequisite");
            assert_eq!(error.kind, "install-proxy-refresh");
            assert!(error.detail.contains(detail), "{error:?}");
            assert!(
                error
                    .detail
                    .contains("restore the private source, destination or runtime prerequisite")
            );
            assert!(!error.detail.contains("run superloop-lane install"));
            fs::remove_file(home.join("private-failure"))
                .expect("restore named private prerequisite");
            if mixed {
                let correction = run(home, &refresh)
                    .expect_err("only proxy remains after prerequisite restoration");
                let command = correction
                    .detail
                    .split_once("; run ")
                    .expect("correction")
                    .1
                    .split_once(", keeping ")
                    .expect("options")
                    .0;
                run_named_install_remedy(home, command, &installed);
            } else {
                run(home, &refresh).expect("restored prerequisite succeeds");
            }
        }
    }
}

/// ´test:crate:refresh-custody-and-publication-run-named-restoration´
#[test]
fn refresh_custody_and_publication_run_named_restoration() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    let custody = home.join(".config/loops/alpha");
    let refresh = refresh_request(&installed);
    for (path, mode) in [
        (custody.clone(), 0o700),
        (custody.join("workers.toml"), 0o600),
        (home.join(".config/loops/allocations.toml"), 0o600),
    ] {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).expect("unsafe custody");
        let error = run(home, &refresh).expect_err("custody prerequisite");
        assert_eq!(error.kind, "install-proxy-refresh");
        assert!(
            error.detail.contains("restore the named prerequisite"),
            "{error:?}"
        );
        assert!(!error.detail.contains("run superloop-lane install"));
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("restore named custody");
        run(home, &refresh).expect("restored custody succeeds");
    }
    for path in [
        home.join(".config/loops/registry.toml"),
        custody.join("image-build.json"),
    ] {
        let original = fs::read(&path).expect("prerequisite");
        fs::write(&path, "invalid prerequisite").expect("invalid input");
        let error = run(home, &refresh).expect_err("input prerequisite");
        assert_eq!(error.kind, "install-proxy-refresh");
        assert!(error.detail.contains("restore the named prerequisite"));
        assert!(!error.detail.contains("run superloop-lane install"));
        fs::write(&path, original).expect("restore named input prerequisite");
        run(home, &refresh).expect("restored input succeeds");
    }
    let generation = custody.join("install-generation.json");
    let original = fs::read(&generation).expect("generation");
    fs::write(&generation, "invalid generation").expect("malformed generation");
    let error = run(home, &refresh).expect_err("generation prerequisite");
    assert!(error.detail.contains("restore valid generation custody"));
    fs::write(&generation, &original).expect("restore named generation custody");
    run(home, &refresh).expect("restored generation refresh");
    fs::write(home.join("publication-block"), "block").expect("publication failure trigger");
    executable(&installed.proxy_bin, "#!/bin/sh\n# updated proxy\nexit 0\n");
    let error = run(home, &refresh).expect_err("publication custody failure");
    // Restore permissions before assertions so a failing test can remove its fixture.
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700))
        .expect("restore writable generation custody");
    fs::remove_file(home.join("publication-block")).expect("remove publication failure");
    assert!(
        error
            .detail
            .contains("restore writable and durable custody"),
        "{error:?}"
    );
    assert_eq!(
        fs::read(&generation).expect("failed publication preserved generation"),
        original
    );
    assert_eq!(
        run(home, &refresh).expect("publication after restoration")["changed"],
        1
    );
    assert_eq!(
        run(home, &refresh).expect("publication repeat")["changed"],
        0
    );
}

/// ´test:crate:refresh-installed-settings-restoration-and-transition´
#[test]
fn refresh_installed_settings_restoration_and_transition() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    let custody = home.join(".config/loops/alpha");
    let settings = custody.join("workers.toml");
    let original = fs::read_to_string(&settings).expect("settings");
    for key in ["template_dir", "socket_dir"] {
        let missing = original
            .lines()
            .filter(|line| !line.starts_with(key))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&settings, &missing).expect("missing setting");
        let error =
            run(home, &refresh_request(&installed)).expect_err("installed settings missing");
        assert!(
            error
                .detail
                .contains("lacks derived paths while installed inputs exist")
        );
        assert!(error.detail.contains("restore template_dir="));
        assert!(!error.detail.contains("run superloop-lane install"));
        fs::write(&settings, &original).expect("restore named derived settings");
        run(home, &refresh_request(&installed)).expect("restored settings");
        fs::write(
            &settings,
            format!(
                "{key} = \"{}\"\n{missing}\n",
                home.join("conflicting-path").display()
            ),
        )
        .expect("conflicting setting");
        let error = run(home, &refresh_request(&installed)).expect_err("derived setting conflict");
        assert!(error.detail.contains(&format!("{key} differs from")));
        assert!(error.detail.contains(&format!("so {key} is")));
        assert!(!error.detail.contains("run superloop-lane install"));
        fs::write(&settings, &original).expect("restore the named setting to its specified path");
        run(home, &refresh_request(&installed)).expect("restored conflicting setting");
    }
    let report_path = custody.join("image-build.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report")).expect("JSON");
    let old = report["image_digest"].as_str().expect("image").to_owned();
    let next = format!("sha256:{}", "c".repeat(64));
    report["image_digest"] = serde_json::json!(next);
    write_json(&report_path, &report);
    fs::write(&settings, original.replace(&old, &next)).expect("coherent image transition");
    let error = run(home, &refresh_request(&installed)).expect_err("transition requires install");
    assert!(error.detail.contains("installed settings"));
    run_full_refresh_remedy(home, &error.detail, &installed);
    assert!(
        fs::read_to_string(&settings)
            .expect("updated settings")
            .contains(&"c".repeat(64))
    );
}

// Supply real build metadata and a stateful private installation for the public repair entry.
fn prepare_refresh_repair(home: &Path, installed: &InstallRequest) {
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"work/alpha\", runs_root = \"{}\" }}]\n", home.join("runs").display())).expect("repair registry");
    let settings_path = home.join(".config/loops/alpha/workers.toml");
    let source = fs::read_to_string(&settings_path).expect("settings");
    fs::write(&settings_path, format!("driver_argv = ['{}']\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n{source}", home.join("lane-fixture").display())).expect("repair plan inputs");
    executable(
        &home.join("codex"),
        "#!/bin/sh\ncase \"$1 $2\" in 'exec --help') printf '%s\\n' '  -m, --model' '  -c, --config' '  --json' '  --sandbox' '  --add-dir' '  --skip-git-repo-check' '  -C, --cd' '  -o, --output-last-message';; *) printf 'codex-cli 0.1.0\\n';; esac\n",
    );
    executable(
        &home.join("codex-host"),
        "#!/bin/sh\nprintf 'Code mode host fixture\\n'\n",
    );
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/Containerfile"),
        installed.data_dir.join("Containerfile"),
    )
    .expect("build template");
    fs::create_dir_all(home.join(".cache/tmp")).expect("build context parent");
    for path in [home.join(".cache"), home.join(".cache/tmp")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("build custody");
    }
    let podman = fs::read_to_string(
        installed
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
    )
    .expect("stateful private program");
    let cases = format!(
        "case \"$1 $2\" in\n'image exists'|'build --pull=never') exit 0 ;;\n'image inspect') printf '{}\\n'; exit 0 ;;\n'run --rm') printf 'ca-certificates 1\\ngit 2\\n'; exit 0 ;;\nesac\n",
        "a".repeat(64)
    );
    executable(
        installed
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        &podman.replacen("set -eu\n", &format!("set -eu\n{cases}"), 1),
    );
    let request = crate::build::BuildRequest {
        loop_name: "alpha".into(),
        claude: None,
        base_image: format!("registry.example/base@sha256:{}", "a".repeat(64)),
        codex_bin: home.join("codex"),
        codex_host_bin: home.join("codex-host"),
        codex_version: "0.1.0".into(),
        codex_sha256: sha256(&home.join("codex")).expect("Codex hash"),
        codex_host_sha256: sha256(&home.join("codex-host")).expect("host hash"),
        codex_source: "https://registry.example/codex-0.1.0".into(),
        podman_bin: installed
            .podman_bin
            .clone()
            .expect("selected fixture program"),
        template_dir: installed.data_dir.clone(),
        dry_run: false,
    };
    crate::build::run(home, &request).expect("build repairable fixture");
    for name in ["private-current.json", "private-target.json"] {
        let path = home.join(name);
        let mut private: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("private state")).expect("state");
        private["source_sha256"]["codex"] = serde_json::json!(request.codex_sha256);
        private["source_sha256"]["codex_host"] = serde_json::json!(request.codex_host_sha256);
        write_json(&path, &private);
    }
}

/// ´test:crate:repair-accepts-complete-base-build-record´
#[test]
fn repair_accepts_complete_base_build_record() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    prepare_refresh_repair(home, &installed);
    let path = home.join(".config/loops/alpha/image-build.json");
    let measured: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("measured fixture inputs")).expect("report");
    // The complete record was captured from the production base executable.
    // Bind this fixture's different programs, image and source directory;
    // preserve the base's field set, package inventory and child records.
    let source = include_str!("../../tests/fixtures/base-image-build.json")
        .replace("@HOME@", home.to_str().expect("home"))
        .replace("@DATA@", installed.data_dir.to_str().expect("data"));
    let mut base: serde_json::Value = serde_json::from_str(&source).expect("base record");
    for key in [
        "codex_sha256",
        "codex_host_sha256",
        "codex_source",
        "codex_exec_probe",
        "codex_host_probe",
        "image_digest",
        "template_sha256",
        "init_sha256",
        "build_environment",
    ] {
        assert!(base.get(key).is_some(), "base already contains {key}");
        base[key] = measured[key].clone();
    }
    write_json(&path, &base);
    run(home, &installed).expect("install base evidence");
    let before = fs::read(&path).expect("base bytes");
    for dry_run in [true, false] {
        let repaired = crate::repair::run_with_lane_bin(
            home,
            &crate::repair::RepairRequest {
                loop_name: "alpha".into(),
                dry_run,
            },
            &home.join("lane-fixture"),
            home,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("public repair accepts complete base evidence");
        assert_eq!(repaired["command"], "repair");
        assert_eq!(repaired["image"]["action"], "seed-settings");
        assert_eq!(fs::read(&path).expect("retained report"), before);
    }
}

/// ´test:crate:refresh-publication-ignores-full-install-unit-prerequisites´
#[test]
fn refresh_publication_ignores_full_install_unit_prerequisites() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    let refresh = refresh_request(&installed);
    let unit_dir = home.join(".config/systemd/user");
    let retired = unit_dir.join("retired");
    fs::create_dir(&retired).expect("retired directory");
    fs::write(
        unit_dir.join("superloop-lane-worker@alpha.service"),
        "old worker unit\n",
    )
    .expect("worker unit");
    fs::write(
        unit_dir.join("superloop-lane-vendor@alpha.service"),
        "old lane path\n",
    )
    .expect("vendor unit");
    for name in ["vendor-proxy.service.in", "worker.service.in"] {
        fs::remove_file(installed.data_dir.join(name)).expect("unit source absent");
    }
    for path in [&unit_dir, &retired] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o777)).expect("unit custody differs");
    }
    executable(
        &installed.proxy_bin,
        "#!/bin/sh\n# new proxy digest\nexit 0\n",
    );
    executable(&home.join("replacement-lane"), "#!/bin/sh\nexit 0\n");
    let result = run_with_lane_bin(
        home,
        &refresh,
        &home.join("replacement-lane"),
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("record refresh keeps its original admission boundary");
    assert_eq!(result["changed"], 1);
    assert_eq!(run(home, &refresh).expect("refresh repeat")["changed"], 0);
    assert_eq!(
        fs::read_to_string(unit_dir.join("superloop-lane-vendor@alpha.service"))
            .expect("unit untouched"),
        "old lane path\n"
    );
}

/// ´test:crate:refresh-printed-refusal-runs-shell-remedy´
#[test]
fn refresh_printed_refusal_runs_shell_remedy() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    run(home, &installed).expect("initial install");
    let mut refresh = refresh_request(&installed);
    refresh.proxy_bin = home.join("alternate-proxy");
    executable(&refresh.proxy_bin, "#!/bin/sh\nexit 0\n");
    let error = run(home, &refresh).expect_err("printed path correction");
    let printed = error.line();
    assert!(printed.contains("--proxy-bin '"));
    assert!(!printed.contains("\\'"));
    let command = printed
        .split_once("; run ")
        .expect("named command")
        .1
        .split_once(", keeping ")
        .expect("options")
        .0;
    run_named_install_remedy(home, command, &installed);
    let controls = crate::error::LaneError::input("fixture", "quote ' and \\\n\t\r\u{1b}é");
    assert_eq!(controls.line(), "fixture: quote ' and \\\\n\\t\\r\\u{1b}é");
    fs::write(
        home.join("private-failure"),
        "source: restore 'quoted' path\\name\n",
    )
    .expect("private error");
    let error = run(home, &refresh).expect_err("wrapped private failure");
    assert!(error.line().contains("restore 'quoted' path\\name"));
    assert!(!error.line().contains("\\\\name"));
}

/// ´test:crate:refresh-source-unit-and-recorded-proxy-prerequisites´
#[test]
#[allow(clippy::too_many_lines)]
fn refresh_source_unit_and_recorded_proxy_prerequisites() {
    let (fixture, installed) = refresh_fixture();
    let home = fixture.path();
    prepare_refresh_repair(home, &installed);
    run(home, &installed).expect("initial install");
    let refresh = refresh_request(&installed);
    for name in ["vendor-proxy.service.in", "worker.service.in"] {
        let path = installed.data_dir.join(name);
        let original = fs::read(&path).expect("unit source");
        fs::write(&path, "missing template tokens\n").expect("broken unit template");
        assert_eq!(
            run(home, &refresh).expect("refresh does not read unit templates")["changed"],
            0
        );
        let current_path = home.join("private-current.json");
        let original_private = fs::read(&current_path).expect("private state");
        let mut private: serde_json::Value =
            serde_json::from_slice(&original_private).expect("state");
        private["charter_refresh"] = serde_json::json!(true);
        write_json(&current_path, &private);
        let error =
            run(home, &refresh).expect_err("unit source prerequisite before installation advice");
        assert!(
            error
                .detail
                .contains("restore the named unit source template")
        );
        assert!(
            !error
                .detail
                .contains("bytes and executable custody pinned by image-build.json")
        );
        fs::write(&path, original).expect("restore named unit source template");
        let advice = run(home, &refresh).expect_err("install now possible");
        run_full_refresh_remedy(home, &advice.line(), &installed);
        fs::write(current_path, original_private).expect("private state restored");
        run(home, &refresh).expect("unit source restored");
    }
    for path in [
        home.join("codex"),
        home.join("codex-host"),
        installed.data_dir.join("box-init"),
    ] {
        let original = fs::read(&path).expect("source");
        fs::write(&path, "changed source\n").expect("drift");
        let error = run(home, &refresh).expect_err("source prerequisite");
        assert!(error.detail.contains("restore the named source"));
        assert!(!error.detail.contains("run superloop-lane install"));
        fs::write(&path, original).expect("restore named pinned source");
        run(home, &refresh).expect("source restored");
    }
    let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let original = fs::read(&unit).expect("unit");
    fs::write(&unit, "changed unit\n").expect("unit drift");
    executable(
        &installed.proxy_bin,
        "#!/bin/sh\n# refreshed proxy\nexit 0\n",
    );
    assert_eq!(
        run(home, &refresh).expect("unit drift does not block publication")["changed"],
        1
    );
    let current_path = home.join("private-current.json");
    let mut private: serde_json::Value =
        serde_json::from_slice(&fs::read(&current_path).expect("private state")).expect("state");
    private["charter_refresh"] = serde_json::json!(true);
    write_json(&current_path, &private);
    let error = run(home, &refresh).expect_err("unit prerequisite before installation advice");
    assert!(
        error
            .detail
            .contains("differs from its pinned unit or report")
    );
    assert!(error.detail.contains("separate vendor-unit replacement"));
    let line = error.line();
    let command = line
        .split_once("when the loop is idle, run ")
        .expect("repair advice")
        .1
        .split_once(" to restore ")
        .expect("repair explanation")
        .0;
    assert_eq!(command, "superloop-lane repair alpha");
    let words = command
        .split_whitespace()
        .skip(2)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let repair = crate::repair::RepairRequest::parse(&words).expect("printed repair parses");
    crate::repair::run_with_lane_bin(
        home,
        &repair,
        &home.join("lane-fixture"),
        home,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("printed repair succeeds");
    assert_eq!(fs::read(&unit).expect("repaired unit"), original);
    run(home, &refresh).expect("unit restored");
    let mut alternate = refresh;
    alternate.proxy_bin = home.join("alternate-proxy");
    executable(&alternate.proxy_bin, "#!/bin/sh\nexit 0\n");
    fs::remove_file(&installed.proxy_bin).expect("recorded executable absent");
    let error = run(home, &alternate).expect_err("validate recorded proxy before naming it");
    assert!(error.detail.contains("restore the named prerequisite"));
    assert!(!error.detail.contains("; run superloop-lane install"));
    executable(
        &installed.proxy_bin,
        "#!/bin/sh\n# refreshed proxy\nexit 0\n",
    );
    let correction = run(home, &alternate).expect_err("recorded path now usable");
    let printed = correction.line();
    let command = printed
        .split_once("; run ")
        .expect("correction")
        .1
        .split_once(", keeping ")
        .expect("options")
        .0;
    run_named_install_remedy(home, command, &installed);
}

#[allow(clippy::too_many_lines)]
fn assert_refresh_remedy_sequence(home: &Path, installed: &InstallRequest) {
    let custody = home.join(".config/loops/alpha");
    let path = custody.join("install-generation.json");
    let original = fs::read(&path).expect("installed generation");
    let generation: serde_json::Value = serde_json::from_slice(&original).expect("generation");
    let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let unit_bytes = fs::read(&unit).expect("installed unit");
    let mut refresh = installed.clone();
    refresh.scope = crate::install::InstallScope::ProxyRecord;
    let alternate = home.join("alternate-proxy");
    executable(&alternate, "#!/bin/sh\n# alternate proxy\nexit 0\n");
    for keys in [
        vec!["codex_host_sha256"],
        vec!["codex_image_program"],
        vec!["codex_sha256"],
        vec!["image_digest"],
        vec!["init_sha256"],
        vec!["socket_dir"],
        vec!["template_dir"],
        vec!["tools_commit"],
        vec!["unit_dir"],
        vec!["codex_sha256", "socket_dir", "tools_commit"],
    ] {
        for mixed in [false, true] {
            let mut drift = generation.clone();
            for key in &keys {
                drift[*key] = serde_json::json!("stale generation pin");
            }
            fs::write(&path, serde_json::to_vec(&drift).expect("drift JSON"))
                .expect("publish stale generation pins");
            refresh.proxy_bin = if mixed {
                alternate.clone()
            } else {
                installed.proxy_bin.clone()
            };
            let refusal = run(home, &refresh).expect_err("refresh cannot reconcile pins");
            assert_eq!(refusal.kind, "install-proxy-refresh");
            assert!(refusal.detail.starts_with(&format!(
                "{} {} from the installed generation;",
                keys.join(", "),
                if keys.len() == 1 { "differs" } else { "differ" }
            )));
            let first = refusal.detail.split_once(", run ").expect("first remedy").1;
            let first = first
                .split_once(" without --refresh-proxy")
                .expect("full install remedy")
                .0;
            run_named_install_remedy(home, first, installed);
            {
                let second = refusal
                    .detail
                    .split_once("; then run ")
                    .expect("second remedy")
                    .1;
                let second = second
                    .split_once(" with those same options.")
                    .expect("refresh remedy")
                    .0;
                run_named_install_remedy(home, second, installed);
            }
            assert_eq!(fs::read(&unit).expect("unit after remedies"), unit_bytes);
            assert_eq!(
                crate::install::read_generation(&path).expect("reconciled generation"),
                Some(generation.clone())
            );
        }
    }
    // These are input conflicts, not stale generation pins. Restore each prerequisite
    // before executing the same full-install and refresh sequence.
    refresh.proxy_bin = installed.proxy_bin.clone();
    let report_path = custody.join("image-build.json");
    let report_bytes = fs::read(&report_path).expect("build report");
    let report: serde_json::Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    let codex = Path::new(
        report["build_environment"]["codex_bin"]
            .as_str()
            .expect("Codex path"),
    );
    let codex_bytes = fs::read(codex).expect("pinned source");
    fs::write(codex, "changed source bytes\n").expect("source conflict");
    let refusal = run(home, &refresh).expect_err("refresh source prerequisite");
    assert_eq!(refusal.kind, "install-proxy-refresh");
    assert!(
        refusal
            .detail
            .contains("Codex executable differs from image-build.json")
    );
    assert!(refusal.detail.contains("restore the named source"));
    assert!(!refusal.detail.contains("run superloop-lane install"));
    assert_eq!(
        run(home, installed)
            .expect_err("full install cannot repair source hash")
            .kind,
        "install-source"
    );
    fs::write(codex, codex_bytes).expect("restore pinned source prerequisite");
    run(home, installed).expect("full install after source restoration");
    run(home, &refresh).expect("refresh after source restoration");
    let settings_path = custody.join("workers.toml");
    let settings_bytes = fs::read_to_string(&settings_path).expect("settings");
    let conflicting = settings_bytes.replace(
        generation["socket_dir"].as_str().expect("socket path"),
        &home.join("other-sockets").display().to_string(),
    );
    fs::write(&settings_path, conflicting).expect("settings conflict");
    let refusal = run(home, &refresh).expect_err("refresh settings prerequisite");
    assert_eq!(refusal.kind, "install-proxy-refresh");
    assert!(refusal.detail.contains("socket_dir differs from"));
    assert!(refusal.detail.contains("restore the named path"));
    assert!(!refusal.detail.contains("run superloop-lane install"));
    assert_eq!(
        run(home, installed)
            .expect_err("full install cannot repair conflicting settings")
            .kind,
        "install-conflict"
    );
    fs::write(&settings_path, settings_bytes).expect("restore derived settings prerequisite");
    run(home, installed).expect("full install after settings restoration");
    run(home, &refresh).expect("refresh after settings restoration");
    assert_eq!(
        fs::read(&path).expect("generation after prerequisites"),
        original
    );
}

/// ´test:crate:public-install-preflights-and-repeats-without-writing´
#[test]
#[allow(clippy::too_many_lines)]
fn public_install_preflights_and_repeats_without_writing() {
    let fixture = TempDir::new_in("/tmp").expect("fixture root");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("fixture home mode");
    let custody = home.join(".config/loops/alpha");
    make_parent(&custody);
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("config mode");
    fs::set_permissions(
        home.join(".config/loops"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("loops mode");
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n").expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let allocations = home.join(".config/loops/allocations.toml");
    let codex = home.join("codex-fixture");
    let codex_host = home.join("codex-code-mode-host-fixture");
    let entry = home.join("entry-fixture");
    let podman = home.join("podman-fixture");
    let proxy = home.join("proxy-fixture");
    let lane_bin = home.join("lane-fixture");
    executable(&codex, "#!/bin/sh\nexit 0\n");
    executable(&codex_host, "#!/bin/sh\nexit 0\n");
    executable(&entry, "#!/bin/sh\nexit 0\n");
    executable(
        &podman,
        &format!(
            "#!/bin/sh\nprintf 'called\\n' >> '{}'\nprintf '{{\"schema\":1,\"changed\":0,\"source_fingerprint\":\"{}\",\"source_sha256\":{{\"codex\":\"{}\",\"codex_host\":\"{}\",\"init\":\"{}\"}},\"destinations\":[],\"hash_checks\":[1,2,3,4,5,6]}}\\n'\n",
            home.join("podman-calls").display(),
            "a".repeat(64),
            sha256(&codex).expect("codex hash"),
            sha256(&codex_host).expect("host hash"),
            sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init"))
                .expect("init hash")
        ),
    );
    executable(&proxy, "#!/bin/sh\nexit 0\n");
    executable(&lane_bin, "#!/bin/sh\nexit 0\n");
    let image = format!("sha256:{}", "a".repeat(64));
    let settings = custody.join("workers.toml");
    let settings_source = format!(
        "entry_bin = \"{}\"\nimage_digest = \"{image}\"\nvendor_hosts = {{ codex = [] }}\n",
        entry.display()
    );
    fs::write(&settings, &settings_source).expect("settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&serde_json::json!({"image_digest":image,"codex_sha256":sha256(&codex).expect("hash"),"codex_host_sha256":sha256(&codex_host).expect("host hash"),"init_sha256":sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init")).expect("init hash"),"codex_image_program":"/usr/libexec/superloop/codex","tools_commit":"fixture","build_environment":{"codex_bin":codex,"codex_host_bin":codex_host}})).expect("build report")).expect("build report file");
    assert_eq!(
        install_allocation(home, "alpha", true, false).expect("prepare allocation")["allocated"],
        true
    );
    let mut request = InstallRequest {
        loop_name: "alpha".into(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: true,
        repair: false,
        podman_bin: Some(podman),
        data_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("data"),
        proxy_bin: proxy,
        unit_dir: None,
    };
    fs::write(
        &settings,
        format!("entry_bin = \"{}\"\nimage_digest = \"{image}\"\nvendor_hosts = {{ claude = [\"api.example.com\"] }}\n", entry.display()),
    )
    .expect("configured Claude setting without a Claude build");
    let ungranted = run(home, &request).expect_err("Claude payload evidence is absent");
    assert_eq!(ungranted.kind, "build-report");
    assert!(ungranted.detail.contains("claude_bin"));
    fs::write(&settings, &settings_source).expect("restore settings");
    let unsafe_proxy = home.join("proxy;another-command");
    executable(&unsafe_proxy, "#!/bin/sh\nexit 0\n");
    let safe_proxy = std::mem::replace(&mut request.proxy_bin, unsafe_proxy);
    let unsafe_unit = run(home, &request).expect_err("unit path syntax");
    assert_eq!(unsafe_unit.kind, "unit-path");
    request.proxy_bin = safe_proxy;
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&serde_json::json!({"image_digest":image,"codex_sha256":sha256(&codex).expect("hash"),"tools_commit":"fixture","codex_bin":codex})).expect("old report")).expect("old report file");
    let old_form = run(home, &request).expect_err("old report shape");
    assert_eq!(old_form.kind, "build-report");
    assert_eq!(old_form.detail, "codex_image_program is absent");
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&serde_json::json!({"image_digest":image,"codex_sha256":sha256(&codex).expect("hash"),"codex_host_sha256":sha256(&codex_host).expect("host hash"),"init_sha256":sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init")).expect("init hash"),"codex_image_program":"/usr/libexec/superloop/codex","tools_commit":"fixture","build_environment":{"codex_bin":codex,"codex_host_bin":codex_host}})).expect("build report")).expect("restore report");
    fs::remove_file(&lane_bin).expect("remove lane fixture");
    std::os::unix::fs::symlink("/usr/bin/true", &lane_bin).expect("replace lane fixture");
    let unsafe_lane = run(home, &request).expect_err("replaced lane binary refuses install");
    assert_eq!(unsafe_lane.kind, "owner-program");
    assert!(!home.join(".config/systemd/user").exists());
    fs::remove_file(&lane_bin).expect("remove replacement");
    executable(&lane_bin, "#!/bin/sh\nexit 0\n");
    let preview = run(home, &request).expect("dry run");
    assert!(preview["changed"].as_u64().expect("preview count") > 0);
    assert_eq!(
        preview["allocation"],
        serde_json::json!({"base":3000,"count":64,"would_allocate":false,"allocated":false})
    );
    assert!(allocations.exists());
    assert_eq!(preview["private_preflight"]["argv"][0], "unshare");
    assert_eq!(
        preview["private_install"]["argv"][2],
        "lane-install-private"
    );
    assert_eq!(
        preview["private_hash_checks"]
            .as_array()
            .expect("hash probes")
            .len(),
        6
    );
    assert_eq!(
        fs::read_to_string(home.join("podman-calls")).expect("private read-only preflight"),
        "called\n"
    );
    assert!(!home.join(".config/systemd").exists());
    let mut changing = InstallRequest {
        dry_run: false,
        ..request
    };
    let first = run(home, &changing).expect("first install");
    assert!(first["changed"].as_u64().expect("changed") > 0);
    assert_eq!(first["unit_activation_performed"], false);
    assert!(first.get("units_active").is_none());
    assert_eq!(preview["changed"], first["changed"]);
    let generation: serde_json::Value = serde_json::from_slice(
        &fs::read(custody.join("install-generation.json")).expect("generation"),
    )
    .expect("generation JSON");
    assert_eq!(
        generation["unit_dir"],
        home.join(".config/systemd/user").display().to_string()
    );
    assert_eq!(
        first["allocation"],
        serde_json::json!({"base":3000,"count":64,"would_allocate":false,"allocated":false})
    );
    assert_eq!(
        fs::read_to_string(&allocations).expect("allocation ledger"),
        "[alpha]\nuids = { base = 3000, count = 64 }\n"
    );
    let second = run(home, &changing).expect("repeat install");
    assert_eq!(second["changed"], 0);
    let vendor_unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let installed_unit = fs::read(&vendor_unit).expect("genuinely installed vendor unit");
    let moved_proxy = home.join("moved-proxy");
    executable(&moved_proxy, "#!/bin/sh\nexit 0\n");
    let mut old_advice = changing.clone();
    old_advice.proxy_bin = moved_proxy;
    let conflict = run(home, &old_advice).expect_err("old full-install advice cannot move proxy");
    assert_eq!(conflict.kind, "install-conflict");
    assert_eq!(
        conflict.detail,
        format!(
            "{} differs from its pinned unit or report",
            vendor_unit.display()
        )
    );
    assert_eq!(
        fs::read(&vendor_unit).expect("unit after refusal"),
        installed_unit
    );
    let generation_path = custody.join("install-generation.json");
    let private_script = fs::read_to_string(
        changing
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
    )
    .expect("private preflight script");
    executable(
        changing
            .podman_bin
            .as_deref()
            .expect("selected fixture program"),
        &private_script.replace(
            "\"destinations\":[]",
            "\"destinations\":[],\"sign_in\":{\"changes\":[]}",
        ),
    );
    assert_refresh_remedy_sequence(home, &changing);
    let mut older_generation: serde_json::Value = serde_json::from_slice(
        &fs::read(&generation_path).expect("generation before pilot refresh"),
    )
    .expect("generation JSON");
    older_generation
        .as_object_mut()
        .expect("generation object")
        .remove("unit_dir");
    fs::write(
        &generation_path,
        serde_json::to_vec(&older_generation).expect("older generation JSON"),
    )
    .expect("older generation");
    changing.dry_run = true;
    let refresh_preview = run(home, &changing).expect("preview unit directory record");
    assert_eq!(refresh_preview["changed"], 1);
    changing.dry_run = false;
    let refreshed = run(home, &changing).expect("pilot records unit directory");
    assert_eq!(refreshed["changed"], refresh_preview["changed"]);
    let refreshed_generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("refreshed generation"))
            .expect("refreshed JSON");
    assert_eq!(
        refreshed_generation["unit_dir"],
        home.join(".config/systemd/user").display().to_string()
    );
    assert_eq!(run(home, &changing).expect("repeat pilot")["changed"], 0);
    assert_eq!(
        second["allocation"],
        serde_json::json!({"base":3000,"count":64,"would_allocate":false,"allocated":false})
    );
    let vendor_unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    let pinned_unit = fs::read(&vendor_unit).expect("installed vendor unit");
    fs::write(&vendor_unit, b"[Unit]\nDescription=drift\n").expect("drifted vendor unit");
    changing.repair = true;
    changing.dry_run = true;
    let repair_preview = run(home, &changing).expect("repair preview");
    assert_eq!(repair_preview["dry_run"], true);
    assert_eq!(
        fs::read(&vendor_unit).expect("preview did not write"),
        b"[Unit]\nDescription=drift\n"
    );
    changing.dry_run = false;
    let repaired = run(home, &changing).expect("repair unit");
    assert!(repaired["changed"].as_u64().expect("changed count") > 0);
    assert_eq!(fs::read(&vendor_unit).expect("repaired bytes"), pinned_unit);
    assert_eq!(run(home, &changing).expect("repeat repair")["changed"], 0);
    changing.repair = false;
    let installed_settings = fs::read_to_string(&settings).expect("installed settings");
    let drifted_settings =
        installed_settings.replace(&image, &format!("sha256:{}", "b".repeat(64)));
    fs::write(&settings, &drifted_settings).expect("drifted image pin");
    changing.repair = true;
    changing.dry_run = true;
    assert_eq!(
        run(home, &changing).expect("projected pin preview")["dry_run"],
        true
    );
    assert_eq!(
        fs::read_to_string(&settings).expect("preview settings"),
        drifted_settings
    );
    fs::write(&settings, installed_settings).expect("restore image pin");
    changing.repair = false;
    changing.dry_run = false;
    let complete_record = custody.join("install-generation.json");
    executable(
        &home.join("podman-fixture"),
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --dry-run \"*) ;; *) cat '{}' > '{}' ;; esac\nprintf '{{\"schema\":1,\"changed\":0,\"charter_refresh\":true,\"source_fingerprint\":\"{}\",\"source_sha256\":{{\"codex\":\"{}\",\"codex_host\":\"{}\",\"init\":\"{}\"}},\"destinations\":[],\"hash_checks\":[1,2,3,4,5,6]}}\\n'\n",
            complete_record.display(),
            home.join("private-generation-seen.json").display(),
            "a".repeat(64),
            sha256(&codex).expect("codex hash"),
            sha256(&codex_host).expect("host hash"),
            sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init"))
                .expect("init hash"),
        ),
    );
    assert_eq!(
        run(home, &changing).expect("same-generation charter refresh")["changed"],
        0
    );
    let during_private: serde_json::Value = serde_json::from_slice(
        &fs::read(home.join("private-generation-seen.json")).expect("private generation snapshot"),
    )
    .expect("private generation record");
    assert_eq!(during_private["phase"], "preparing");
    let after_private: serde_json::Value =
        serde_json::from_slice(&fs::read(&complete_record).expect("completed refresh record"))
            .expect("completed record");
    assert_eq!(after_private["phase"], "complete");
    assert_eq!(after_private["source_fingerprint"], "a".repeat(64));
    let mut stale_pending = after_private.clone();
    stale_pending["phase"] = serde_json::json!("preparing");
    stale_pending["source_fingerprint"] = serde_json::json!("b".repeat(64));
    let stale_bytes = serde_json::to_vec(&stale_pending).expect("stale pending record");
    fs::write(&complete_record, &stale_bytes).expect("stale pending record file");
    assert_eq!(
        run(home, &changing)
            .expect_err("public install cannot rebind an unfinished source")
            .kind,
        "install-generation"
    );
    assert_eq!(
        fs::read(&complete_record).expect("unchanged pending record"),
        stale_bytes
    );
    fs::write(
        &complete_record,
        serde_json::to_vec(&after_private).expect("complete record"),
    )
    .expect("restore complete record");
    let full = InstallRequest {
        loop_name: "alpha".into(),
        pilot: false,
        scope: crate::install::InstallScope::Full,
        dry_run: false,
        repair: false,
        podman_bin: Some(home.join("podman-fixture")),
        data_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("data"),
        proxy_bin: home.join("proxy-fixture"),
        unit_dir: None,
    };
    assert_eq!(
        run(home, &full).expect("Codex-only full refresh")["changed"],
        0
    );
    let worker_unit = home.join(".config/systemd/user/superloop-lane-worker@alpha.service");
    let previous_unit = include_str!("../../data/worker.service.in")
        .replace("@LANE_BIN@", &lane_bin.display().to_string());
    fs::write(&worker_unit, previous_unit).expect("earlier pilot worker unit");
    fs::set_permissions(&worker_unit, fs::Permissions::from_mode(0o644)).expect("unit mode");
    let retired = run(home, &changing).expect("retire unit without a run and letter");
    assert_eq!(retired["changed"], 1);
    assert!(!worker_unit.exists());
    assert_eq!(
        fs::read_dir(home.join(".config/systemd/user/retired"))
            .expect("retired directory")
            .count(),
        1
    );
    assert_eq!(
        run(home, &changing).expect("repeat after retirement")["changed"],
        0
    );
    let record = custody.join("install-generation.json");
    let mut pending: serde_json::Value =
        serde_json::from_slice(&fs::read(&record).expect("generation")).expect("record");
    assert_eq!(pending["phase"], "complete");
    let installed_settings = fs::read_to_string(&settings).expect("installed settings");
    let without_template = installed_settings
        .lines()
        .filter(|line| !line.starts_with("template_dir = "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&settings, format!("{without_template}\n")).expect("change derived settings");
    let settings_refusal = run(home, &changing).expect_err("derived settings conflict");
    assert_eq!(settings_refusal.status, 2);
    assert_eq!(settings_refusal.kind, "install-conflict");
    assert!(
        settings_refusal
            .detail
            .contains(&settings.display().to_string())
    );
    pending["phase"] = serde_json::json!("preparing");
    fs::write(
        &record,
        serde_json::to_vec(&pending).expect("pending record"),
    )
    .expect("record write");
    let resumed_before_selection =
        run(home, &changing).expect("resume before settings publication");
    assert!(
        resumed_before_selection["changed"]
            .as_u64()
            .expect("changed")
            > 0
    );
    assert!(
        fs::read_to_string(&settings)
            .expect("selected settings")
            .contains("template_dir")
    );
    fs::write(
        &record,
        serde_json::to_vec(&pending).expect("pending record"),
    )
    .expect("record write");
    let resumed = run(home, &changing).expect("resume after publication");
    assert_eq!(resumed["changed"], 0);
    let complete: serde_json::Value =
        serde_json::from_slice(&fs::read(&record).expect("record")).expect("record JSON");
    assert_eq!(complete["phase"], "complete");
    let vendor_unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    fs::remove_file(&vendor_unit).expect("interrupted unit publication");
    fs::write(
        &record,
        serde_json::to_vec(&pending).expect("pending record"),
    )
    .expect("record write");
    let resumed_unit = run(home, &changing).expect("resume after unit publication interruption");
    assert!(resumed_unit["changed"].as_u64().expect("changed") > 0);
    assert!(vendor_unit.is_file());
    assert_eq!(
        run(home, &changing).expect("repeat after unit recovery")["changed"],
        0
    );
    let next_image = format!("sha256:{}", "c".repeat(64));
    let next_settings = fs::read_to_string(&settings)
        .expect("selected settings")
        .replace(&image, &next_image);
    fs::write(&settings, next_settings).expect("rebuilt image setting");
    fs::write(custody.join("image-build.json"), serde_json::to_vec(&serde_json::json!({"image_digest":next_image,"codex_sha256":sha256(&codex).expect("hash"),"codex_host_sha256":sha256(&codex_host).expect("host hash"),"init_sha256":sha256(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data/box-init")).expect("init hash"),"codex_image_program":"/usr/libexec/superloop/codex","tools_commit":"fixture","build_environment":{"codex_bin":codex,"codex_host_bin":codex_host}})).expect("new report")).expect("new report file");
    let rebuilt = run(home, &changing).expect("install after image rebuild");
    assert!(rebuilt["changed"].as_u64().expect("changed") > 0);
    assert!(
        fs::read_to_string(&settings)
            .expect("new selected template")
            .contains(&"c".repeat(64))
    );
    let unit = home.join(".config/systemd/user/superloop-lane-vendor@alpha.service");
    fs::write(&unit, "fixture conflict\n").expect("mutate unit");
    let refusal = run(home, &changing).expect_err("unit conflict");
    assert_eq!(refusal.status, 2);
    assert_eq!(refusal.kind, "install-conflict");
    assert!(refusal.detail.contains(&unit.display().to_string()));
}

/// ´test:crate:public-private-vector-matches-private-parser´
#[test]
fn public_private_vector_matches_private_parser() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let home = fixture.path();
    let request = InstallRequest {
        loop_name: "alpha".into(),
        pilot: true,
        scope: crate::install::InstallScope::Full,
        dry_run: true,
        repair: false,
        podman_bin: Some(home.join("podman")),
        data_dir: home.join("data"),
        proxy_bin: home.join("proxy"),
        unit_dir: None,
    };
    let image = format!("sha256:{}", "a".repeat(64));
    let verified = nix::fcntl::open(
        home,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("verified home descriptor");
    let config = home.join(".config/loops/alpha");
    fs::create_dir_all(&config).expect("config directory");
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        config.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("protected config");
    }
    let guard = lock_loop_config(&config, true).expect("install lock");
    let source = "c".repeat(64);
    for dry_run in [true, false] {
        let spec = private_spec(
            &request,
            request
                .podman_bin
                .as_deref()
                .expect("selected fixture program"),
            home,
            &home.join("entry"),
            &home.join("lane"),
            &home.join("codex"),
            &home.join("codex-code-mode-host"),
            &image,
            &"b".repeat(64),
            "fixture",
            dry_run,
            Some(&source),
        )
        .expect("private spec")
        .with_private_install(&verified, &guard)
        .expect("bound private spec");
        let argv = spec.preview()["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .map(|item| item.as_str().expect("word").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            &argv[..3],
            [
                "unshare",
                home.join("entry").to_str().expect("entry"),
                "lane-install-private"
            ]
        );
        let entry_words = argv[2..]
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();
        let (lane_bin, forwarded) =
            loop_home::app::lane_install_private_dispatch(&entry_words).expect("entry dispatch");
        assert_eq!(lane_bin, home.join("lane"));
        let forwarded = forwarded
            .into_iter()
            .map(|word| word.into_string().expect("UTF-8 word"))
            .collect::<Vec<_>>();
        let parsed = install_private::PrivateRequest::parse(&forwarded).expect("private parser");
        assert_eq!(parsed.loop_name, "alpha");
        assert_eq!(parsed.owner_home, home);
        assert_eq!(parsed.data_dir, request.data_dir);
        assert_eq!(parsed.codex_bin, home.join("codex"));
        assert_eq!(parsed.image_digest, image);
        assert_eq!(parsed.dry_run, dry_run);
        assert_eq!(
            argv[argv.len() - 4..],
            ["--verified-home-fd", "0", "--verified-install-lock-fd", "1"]
        );
        assert_eq!(
            install_private::PrivateRequest::parse(&forwarded[..forwarded.len() - 2])
                .err()
                .expect("missing inherited descriptor")
                .kind,
            "install-lock"
        );
    }
}

/// ´test:crate:private-install-holds-the-transferred-exclusive-lock´
#[test]
fn private_install_holds_the_transferred_exclusive_lock() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let home = fixture.path();
    let config = home.join(".config/loops/alpha");
    let other = home.join(".config/loops/beta");
    fs::create_dir_all(&config).expect("config directory");
    fs::create_dir_all(&other).expect("other directory");
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        config.clone(),
        other.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("protected config");
    }
    let guard = lock_loop_config(&config, false).expect("held install lock");
    let duplicate = nix::unistd::dup(&guard).expect("transfer duplicate");
    let refusal = crate::install::InstallGuard::from_transferred(&other, duplicate)
        .expect_err("descriptor for another loop");
    assert_eq!(refusal.kind, "install-lock");
    let read_guard = lock_loop_config(&other, true).expect("read lock");
    assert_eq!(
        read_guard
            .verify(&other, false)
            .expect_err("read lock cannot write")
            .kind,
        "install-lock"
    );
    drop(read_guard);
    let unlocked: std::os::fd::OwnedFd = fs::File::open(&other)
        .expect("matching unlocked directory")
        .into();
    let acquired = crate::install::InstallGuard::from_transferred(&other, unlocked)
        .expect("matching descriptor acquires the exclusive lock");
    assert_eq!(
        lock_loop_config(&other, true)
            .expect_err("shared contender cannot enter during private mutation")
            .kind,
        "install-busy"
    );
    drop(acquired);
    let confirmed = crate::install::InstallGuard::from_transferred(
        &config,
        nix::unistd::dup(&guard).expect("duplicate exclusive holder"),
    )
    .expect("exclusive handoff");
    assert_eq!(
        lock_loop_config(&config, true)
            .expect_err("shared contender cannot enter during private preflight")
            .kind,
        "install-busy"
    );
    drop(confirmed);
}

/// ´test:crate:proxy-rechecks-shared-settings-grant-before-unshare´
#[test]
fn proxy_rechecks_shared_settings_grant_before_unshare() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let home = fixture.path();
    let custody = home.join(".config/loops/alpha");
    fs::create_dir_all(&custody).expect("custody");
    let config = home.join(".config");
    let loops = config.join("loops");
    for path in [home, config.as_path(), loops.as_path(), custody.as_path()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private path");
    }
    fs::write(home.join(".config/loops/registry.toml"), "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n").expect("registry");
    let settings = custody.join("workers.toml");
    fs::write(&settings, format!("runs_root = \"{}\"\nsocket_dir = \"{}\"\nvendor_hosts = {{ codex = [\"api.example.com\"] }}\n", home.join("other-runs").display(), home.join(".var/loops/alpha/sockets").display())).expect("widened settings");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    let error = run_proxy(
        home,
        &[
            "alpha".into(),
            "--proxy-bin".into(),
            home.join("proxy").display().to_string(),
        ],
    )
    .expect_err("widened proxy grant");
    assert_eq!(error.kind, "settings-grant");
}

/// ´test:crate:private-install-refreshes-intact-prior-charter-and-repeats´
#[test]
#[allow(clippy::too_many_lines)]
fn private_install_refreshes_intact_prior_charter_and_repeats() {
    let fixture = TempDir::new().expect("fixture root");
    let home = fixture.path();
    make_parent(&home.join(".var/loops/alpha/private"));
    make_parent(&home.join(".config/loops/alpha/lanes"));
    for parent in [
        home.to_path_buf(),
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        home.join(".config"),
        home.join(".config/loops"),
        home.join(".config/loops/alpha"),
        home.join(".config/loops/alpha/lanes"),
    ] {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .expect("protected fixture parent");
    }
    let data = home.join("data");
    make_parent(&data);
    fs::write(
        data.join("codex-config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    )
    .expect("config");
    fs::write(data.join("worker-AGENTS.md"), "A worker charter.\n").expect("charter");
    fs::write(data.join("box-init"), "fixed private init\n").expect("private init");
    let codex = home.join("codex-program");
    fs::write(&codex, "pinned fixture program\n").expect("program");
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).expect("program mode");
    let codex_host = home.join("codex-code-mode-host");
    fs::write(&codex_host, "pinned host fixture\n").expect("host");
    fs::set_permissions(&codex_host, fs::Permissions::from_mode(0o700)).expect("host mode");
    let digest = sha256(&codex).expect("digest");
    let uid = nix::unistd::Uid::effective().as_raw();
    let gid = nix::unistd::Gid::effective().as_raw();
    assert_eq!(uid, gid, "fixture requires matching uid and gid");
    let image = format!("sha256:{}", "a".repeat(64));
    let record = home.join(".config/loops/alpha/install-generation.json");
    let invoke = |dry_run| {
        let guard = lock_loop_config(&home.join(".config/loops/alpha"), dry_run)?;
        let source = if dry_run {
            None
        } else {
            let preview = install_private::run(
                home,
                "alpha",
                uid,
                (uid, gid),
                &data,
                &codex,
                &codex_host,
                &image,
                &digest,
                "fixture",
                None,
                true,
                &guard,
            )?;
            Some(
                preview["source_fingerprint"]
                    .as_str()
                    .expect("source fingerprint")
                    .to_owned(),
            )
        };
        install_private::run(
            home,
            "alpha",
            uid,
            (uid, gid),
            &data,
            &codex,
            &codex_host,
            &image,
            &digest,
            "fixture",
            source.as_deref(),
            dry_run,
            &guard,
        )
    };
    let write_pending = |selected_image: &str, template: Option<&std::path::Path>| {
        let guard =
            lock_loop_config(&home.join(".config/loops/alpha"), true).expect("preview lock");
        let preview = install_private::run(
            home,
            "alpha",
            uid,
            (uid, gid),
            &data,
            &codex,
            &codex_host,
            selected_image,
            &digest,
            "fixture",
            None,
            true,
            &guard,
        )
        .expect("source preview");
        fs::write(&record, serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"preparing","image_digest":selected_image,"codex_sha256":digest,"tools_commit":"fixture","template_dir":template,"source_fingerprint":preview["source_fingerprint"]})).expect("pending record"))
            .expect("pending record file");
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
            .expect("pending record mode");
    };
    write_pending(&image, None);
    let preview = invoke(true).expect("dry run");
    assert!(preview["changed"].as_u64().expect("preview count") > 0);
    assert!(!home.join(".var/loops/alpha/runner-templates").exists());
    assert!(
        preview["destinations"]
            .as_array()
            .expect("destinations")
            .len()
            >= 12
    );
    let first = invoke(false).expect("first install");
    assert!(first["changed"].as_u64().expect("changed") > 0);
    assert_eq!(preview["changed"], first["changed"]);
    assert!(!home.join(".var/loops/alpha/sockets/door").exists());
    let second = invoke(false).expect("second install");
    assert_eq!(second["changed"], 0);
    let before_change = invoke(true).expect("measured preflight");
    let old_source = before_change["source_fingerprint"]
        .as_str()
        .expect("source digest");
    write_pending(&image, None);
    fs::write(data.join("worker-AGENTS.md"), "Changed after preflight.\n")
        .expect("replace source before private change");
    let guard = lock_loop_config(&home.join(".config/loops/alpha"), false).expect("install lock");
    let changed_source = install_private::run(
        home,
        "alpha",
        uid,
        (uid, gid),
        &data,
        &codex,
        &codex_host,
        &image,
        &digest,
        "fixture",
        Some(old_source),
        false,
        &guard,
    )
    .expect_err("changed source refuses before mutation");
    assert_eq!(changed_source.kind, "install-source");
    let changed_preview = install_private::run(
        home,
        "alpha",
        uid,
        (uid, gid),
        &data,
        &codex,
        &codex_host,
        &image,
        &digest,
        "fixture",
        None,
        true,
        &guard,
    )
    .expect("changed source preview");
    let stale_pending = install_private::run(
        home,
        "alpha",
        uid,
        (uid, gid),
        &data,
        &codex,
        &codex_host,
        &image,
        &digest,
        "fixture",
        changed_preview["source_fingerprint"].as_str(),
        false,
        &guard,
    )
    .expect_err("pending record names the prior source");
    assert_eq!(stale_pending.kind, "install-generation");
    drop(guard);
    fs::write(data.join("worker-AGENTS.md"), "A worker charter.\n")
        .expect("restore measured source");
    assert_eq!(
        invoke(false).expect("repeat after refused source")["changed"],
        0
    );
    fs::write(
        data.join("worker-AGENTS.md"),
        "A refreshed worker charter.\n",
    )
    .expect("new source charter");
    let refresh_preview = invoke(true).expect("old installed charter is intact");
    assert_eq!(refresh_preview["changed"], 2);
    assert_eq!(
        refresh_preview["destinations"]
            .as_array()
            .expect("destinations")
            .iter()
            .filter(|row| row["complete"] == false)
            .count(),
        2
    );
    write_pending(&image, None);
    let refreshed = invoke(false).expect("refresh charter and manifest");
    assert_eq!(refreshed["changed"], refresh_preview["changed"]);
    assert_eq!(
        invoke(false).expect("repeat refreshed install")["changed"],
        0
    );
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    let manifest_path = template.join("manifest");
    let manifest_bytes = fs::read(&manifest_path).expect("installed manifest");
    let mut conflicting_manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    conflicting_manifest["tools_commit"] = serde_json::json!("another tools commit");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
        .expect("open manifest for fixture");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&conflicting_manifest).expect("conflicting manifest"),
    )
    .expect("publish conflicting payload");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o440))
        .expect("restore manifest mode");
    let conflict = invoke(false).expect_err("full private install cannot overwrite manifest drift");
    assert_eq!(conflict.kind, "install-conflict");
    assert!(conflict.detail.contains("differs beyond its charter hash"));
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
        .expect("open manifest for prerequisite restoration");
    fs::write(&manifest_path, manifest_bytes).expect("restore pinned manifest prerequisite");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o440))
        .expect("restore pinned mode");
    assert_eq!(
        invoke(false).expect("install succeeds after payload restoration")["changed"],
        0
    );
    for (index, checkpoint) in [
        install_private::RefreshCheckpoint::AfterMode,
        install_private::RefreshCheckpoint::AfterCharter,
        install_private::RefreshCheckpoint::AfterManifest,
        install_private::RefreshCheckpoint::AfterModeRestore,
    ]
    .into_iter()
    .enumerate()
    {
        let charter = format!("Recovered charter {index}.\n");
        fs::write(data.join("worker-AGENTS.md"), &charter).expect("new source charter");
        write_pending(&image, Some(&template));
        let snapshot = invoke(true).expect("refresh preview");
        let guard =
            lock_loop_config(&home.join(".config/loops/alpha"), false).expect("install lock");
        let interruption = install_private::run_with_checkpoint(
            home,
            "alpha",
            uid,
            (uid, gid),
            &data,
            &codex,
            &codex_host,
            &image,
            &digest,
            "fixture",
            snapshot["source_fingerprint"].as_str(),
            false,
            &guard,
            checkpoint,
        )
        .expect_err("simulated interruption");
        assert_eq!(interruption.kind, "install-interrupted");
        drop(guard);
        if index == 0 {
            let stale = template.join(format!(".AGENTS.md-refresh-{}-0.tmp", std::process::id()));
            fs::write(&stale, "abandoned temporary\n").expect("stale temporary");
        }
        assert!(
            invoke(false).expect("recover refresh")["changed"]
                .as_u64()
                .expect("changed")
                <= 3
        );
        fs::write(&record, serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":digest,"tools_commit":"fixture","template_dir":template})).expect("complete record")).expect("complete record file");
        assert_eq!(
            invoke(false).expect("repeat recovered refresh")["changed"],
            0
        );
        assert_eq!(
            fs::read_to_string(template.join("AGENTS.md")).expect("installed charter"),
            charter
        );
        assert_eq!(
            fs::metadata(&template)
                .expect("template mode")
                .permissions()
                .mode()
                & 0o777,
            0o550
        );
    }
    fs::write(
        data.join("worker-AGENTS.md"),
        "A refreshed worker charter.\n",
    )
    .expect("restore source charter");
    // Restore the matching prior pair before the conflict checks below.
    write_pending(&image, Some(&template));
    assert_eq!(invoke(false).expect("restore charter")["changed"], 2);
    let installed_charter = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64))
        .join("AGENTS.md");
    fs::set_permissions(&installed_charter, fs::Permissions::from_mode(0o600))
        .expect("open installed charter for fixture");
    fs::write(&installed_charter, "Altered installed charter.\n").expect("alter charter");
    fs::set_permissions(&installed_charter, fs::Permissions::from_mode(0o440))
        .expect("restore charter mode");
    fs::write(data.join("worker-AGENTS.md"), "A later worker charter.\n")
        .expect("later source charter");
    assert_eq!(
        invoke(true)
            .expect_err("altered charter refuses preview")
            .kind,
        "install-conflict"
    );
    assert_eq!(
        invoke(false)
            .expect_err("altered charter refuses change")
            .kind,
        "install-conflict"
    );
    fs::set_permissions(&installed_charter, fs::Permissions::from_mode(0o600))
        .expect("restore installed charter");
    fs::write(&installed_charter, "A refreshed worker charter.\n").expect("restore bytes");
    fs::set_permissions(&installed_charter, fs::Permissions::from_mode(0o440))
        .expect("restore mode");
    fs::write(
        data.join("worker-AGENTS.md"),
        "A refreshed worker charter.\n",
    )
    .expect("restore source");
    let installed_init = template.join("libexec/box-init");
    assert_eq!(
        sha256(&installed_init).expect("installed private init"),
        sha256(&data.join("box-init")).expect("source private init")
    );
    for checkpoint in [
        install_private::RefreshCheckpoint::AfterInitMetadata,
        install_private::RefreshCheckpoint::AfterInitSync,
        install_private::RefreshCheckpoint::AfterLibexecModeRestore,
    ] {
        fs::set_permissions(template.join("libexec"), fs::Permissions::from_mode(0o700))
            .expect("open prior private directory for fixture");
        fs::remove_file(&installed_init).expect("simulate prior template without private init");
        fs::set_permissions(template.join("libexec"), fs::Permissions::from_mode(0o550))
            .expect("restore prior private directory mode");
        write_pending(&image, Some(&template));
        let snapshot = invoke(true).expect("backfill preview");
        let guard =
            lock_loop_config(&home.join(".config/loops/alpha"), false).expect("backfill lock");
        let interruption = install_private::run_with_checkpoint(
            home,
            "alpha",
            uid,
            (uid, gid),
            &data,
            &codex,
            &codex_host,
            &image,
            &digest,
            "fixture",
            snapshot["source_fingerprint"].as_str(),
            false,
            &guard,
            checkpoint,
        )
        .expect_err("backfill interruption");
        assert_eq!(interruption.kind, "install-interrupted");
        drop(guard);
        assert!(
            invoke(false).expect("recover private init")["changed"]
                .as_u64()
                .expect("changed count")
                <= 1
        );
        assert_eq!(invoke(false).expect("repeat private init")["changed"], 0);
        assert_eq!(
            sha256(&installed_init).expect("installed private init"),
            sha256(&data.join("box-init")).expect("source private init")
        );
        assert_eq!(
            fs::metadata(template.join("libexec"))
                .expect("restored private directory")
                .permissions()
                .mode()
                & 0o777,
            0o550
        );
    }
    write_pending(&image, Some(&template));
    let partial = template.join("bin/codex");
    fs::set_permissions(template.join("bin"), fs::Permissions::from_mode(0o700))
        .expect("interrupted directory mode");
    fs::remove_file(&partial).expect("interrupted file removed");
    fs::write(&partial, "partial").expect("interrupted copy");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).expect("creation mode");
    let resumed = invoke(false).expect("recover pinned partial file");
    assert!(resumed["changed"].as_u64().expect("changed") > 0);
    assert_eq!(sha256(&partial).expect("repaired copy"), digest);
    fs::write(&record, serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":digest,"tools_commit":"fixture","template_dir":template})).expect("complete record")).expect("complete record file");
    let next_image = format!("sha256:{}", "c".repeat(64));
    write_pending(&next_image, None);
    let next_guard =
        lock_loop_config(&home.join(".config/loops/alpha"), false).expect("install lock");
    let next_preview = install_private::run(
        home,
        "alpha",
        uid,
        (uid, gid),
        &data,
        &codex,
        &codex_host,
        &next_image,
        &digest,
        "fixture",
        None,
        true,
        &next_guard,
    )
    .expect("next preview");
    install_private::run(
        home,
        "alpha",
        uid,
        (uid, gid),
        &data,
        &codex,
        &codex_host,
        &next_image,
        &digest,
        "fixture",
        next_preview["source_fingerprint"].as_str(),
        false,
        &next_guard,
    )
    .expect("next template");
    drop(next_guard);
    fs::write(&record, serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"complete","image_digest":image,"codex_sha256":digest,"tools_commit":"fixture","template_dir":template})).expect("complete prior record")).expect("complete prior record file");
    assert!(template.exists());
    assert!(
        home.join(".var/loops/alpha/runner-templates/codex")
            .join("c".repeat(64))
            .exists()
    );
    let manifest = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64))
        .join("manifest");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))
        .expect("fixture owner changes manifest");
    fs::write(&manifest, "changed by fixture\n").expect("change manifest");
    let preview_refusal = invoke(true).expect_err("preview sees private conflict");
    assert_eq!(preview_refusal.kind, "install-conflict");
    assert!(
        preview_refusal
            .detail
            .contains(&manifest.display().to_string())
    );
    let refusal = invoke(false).expect_err("conflicting manifest");
    assert_eq!(refusal.status, 2);
    assert_eq!(refusal.kind, "install-conflict");
    assert!(refusal.detail.contains(&manifest.display().to_string()));
}

/// ´test:crate:install-lock-serializes-one-loop´
#[test]
fn install_lock_serializes_one_loop() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let loop_config = fixture.path().join("alpha");
    fs::create_dir(&loop_config).expect("loop config");
    fs::set_permissions(&loop_config, fs::Permissions::from_mode(0o700)).expect("loop config mode");
    let first = lock_loop_config(&loop_config, false).expect("first install lock");
    let second = lock_loop_config(&loop_config, false).expect_err("second install is busy");
    assert_eq!(second.kind, "install-busy");
    assert!(second.detail.contains(&loop_config.display().to_string()));
    let preview = lock_loop_config(&loop_config, true).expect_err("preview is busy too");
    assert_eq!(preview.kind, "install-busy");
    drop(first);
    lock_loop_config(&loop_config, false).expect("lock released");
}
