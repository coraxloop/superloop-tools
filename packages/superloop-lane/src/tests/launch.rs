use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use serde_json::json;
use tempfile::TempDir;

use crate::build::sha256;
use crate::launch::{
    LaunchRequest, RecordHostsRequest, record_hosts_with_lane_bin_from, run_with_host_root,
    run_with_host_root_and_proxy, select_free_uid,
};

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
                    fs::remove_file(path.parent().expect("runs").join(".letter-R.lock"))
                        .expect("remove fixture mailbox lock");
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
    plan.select_container_program(&request.podman_bin)
        .expect("runtime");
    plan.select_launch_model(&selection).expect("model");
    plan.observe_vendor().expect("observing recovery");
    assert_eq!(plan.document["attempt_wall_seconds"], 12);
    let path = plan
        .driver_dir
        .parent()
        .expect("runs")
        .join(".reservation-R.json");
    let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":plan.document,"model_selection":selection,"letter_source":request.letter,"launcher_pid":4_000_000,"launcher_start":1,"driver_entry_pid":4_000_001,"driver_entry_start":1,"helper_pid":4_000_002,"helper_start":1,"helper_parent_pid":4_000_003,"helper_parent_start":1,"observer_state":"running","observer_pid":4_000_004,"observer_start":1});
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

/// ´test:crate:public-preview-reads-dead-preparation-with-unreadable-driver´
#[test]
#[allow(clippy::too_many_lines)]
fn public_preview_reads_dead_preparation_with_unreadable_driver() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
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
    fs::write(&allocations, "[alpha]\nuids = { base = 3000, count = 2 }\n").expect("allocation");
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
        serde_json::to_vec(&json!({"schema":2,"agent":{"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"entry":"/fixture/entry","loop_home":"/fixture/home"},"phase":"complete","loop":"alpha","template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":sha256(&custody.join("door-service")).expect("service digest"),"unit_dir":custody.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw()})).expect("door generation"),
    )
    .expect("door generation file");
    fs::set_permissions(&door_generation, fs::Permissions::from_mode(0o600))
        .expect("door generation mode");
    let mut request = LaunchRequest {
        loop_name: "alpha".into(),
        run: "R".into(),
        letter,
        round: None,
        budget: 3600,
        dry_run: true,
        expect_digest: None,
        observe: false,
        podman_bin: podman,
        proxy_bin: Some(home.join("proxy-fixture")),
        model: Some("gpt-6-sol".into()),
        effort: Some("high".into()),
        door_scope: crate::door::Scope::Work,
        rotation_source: None,
    };
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
        &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":old_plan,"letter_source":request.letter,"launcher_pid":4_000_000,"launcher_start":1,"observer_state":"running","observer_pid":4_000_001,"observer_start":1,"helper_spawn_state":"not-started","reservation_census":preview["plan"]["reservation_census"]}),
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
    assert_eq!(preview["prepare_argv"]["directory_transfer_socket_fd"], 0);
    assert_eq!(
        preview["prepare_argv"]["transferred_directory_descriptors"],
        json!([
            {"index":0,"role":"owner_home"},
            {"index":1,"role":"runs_root"},
            {"index":2,"role":"letter_directory"}
        ])
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
    assert_eq!(
        prepare_words[prepare_words.len() - 2],
        "--verified-letter-fd"
    );
    assert_eq!(
        prepare_words.last().and_then(serde_json::Value::as_str),
        Some("2")
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
            "Read /home/worker/.local/inbox/dispatch.md."
        ))
    );
    assert_eq!(
        preview["selection"]["method"],
        "in-process read-only runs-root snapshot under shared lock"
    );
    assert_eq!(
        fs::read_to_string(home.join("container-calls")).expect("named image probes"),
        "called\n".repeat(21)
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
    let fixture = TempDir::new_in("/tmp").expect("fixture");
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
    fs::write(&allocations, "[alpha]\nuids = { base = 3000, count = 2 }\n").expect("allocation");
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
        serde_json::to_vec(&json!({"schema":2,"agent":{"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"entry":"/fixture/entry","loop_home":"/fixture/home"},"phase":"complete","loop":"alpha","template_dir":template,"socket_dir":sockets,"stub_sha256":stub_digest,"service_sha256":sha256(&custody.join("door-service")).expect("service digest"),"unit_dir":custody.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw()})).expect("door generation"),
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
    let launch = LaunchRequest {
        loop_name: "alpha".into(),
        run: "R".into(),
        letter: letter.clone(),
        round: None,
        budget: 3600,
        dry_run: true,
        expect_digest: None,
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
    let before = crate::container_helper::fixture_pinned_request(home, "R", &podman)
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
    let after = crate::container_helper::fixture_pinned_request(home, "R", &podman)
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
    assert!(crate::container_helper::fixture_pinned_request(home, "S", &podman).is_ok());
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
    assert!(crate::container_helper::fixture_pinned_request(home, "R", &podman).is_ok());
    assert!(crate::container_helper::fixture_pinned_request(home, "S", &podman).is_ok());
    drop(first);
    drop(second);
    fs::remove_file(runs.join(".reservation-R.json")).expect("release R");
    fs::remove_file(runs.join(".reservation-S.json")).expect("release S");
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
        save(f['evidence'], {'runtime_argv': [] if window == 'Primary' else f['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/.local/inbox/dispatch.md', 'operation': 'read'}]}})
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
    if 'SUPERLOOP_MATRIX_STAGE' not in os.environ:
        save(pathlib.Path(f['evidence']), {'runtime_argv': f['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/.local/inbox/dispatch.md', 'operation': 'read'}]}})
    elif f['before'] and os.environ['SUPERLOOP_MATRIX_STAGE'] == 'publish-primary':
        pathlib.Path(f['lane']).chmod(0o600)
    print('{}')
elif '_container-helper' in args:
    socket.socket(fileno=0).recvmsg(1, socket.CMSG_SPACE(8))
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
            saved = resume_pre_spawn_failure(home, &request, lane_bin, &path, &saved);
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
fn resume_pre_spawn_failure(
    home: &std::path::Path,
    request: &LaunchRequest,
    lane_bin: &std::path::Path,
    path: &std::path::Path,
    seed: &serde_json::Value,
) -> serde_json::Value {
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
    let mut final_record = seed.clone();
    for failure in ["inspect-save", "inspect", "spawn"] {
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
        saved["letters"].as_array_mut().expect("letters").push(json!({"step":"next","name":"next.md","state":"placed","in_round":false,"bytes":letter.len(),"sha256":sha256(&inbox.join("next.md")).expect("letter hash"),"stop":false,"placed_at_unix_ns":2}));
        crate::launch::publish_reservation(path, &saved).expect("settled prior round");
        fs::write(
            home.join("resume-window.json"),
            json!({"failure":failure,"lane":lane_bin}).to_string(),
        )
        .expect("resume fixture");
        executable(
            &request.podman_bin,
            r"#!/usr/bin/python3
import json, pathlib, sys
home = pathlib.Path.cwd()
f = json.loads((home / 'resume-window.json').read_text())
if '_inspect-round' in sys.argv:
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
        if failure == "inspect-save" {
            crate::launch::fixture_before_pre_driver_save(pad_pre_driver_save, None);
        }
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
        final_record = crate::launch::read_reservation(path)
            .expect("reader")
            .expect("failed round");
        if failure == "inspect-save" {
            assert!(
                error
                    .detail
                    .contains("failure record save: reservation-size:")
            );
            assert_eq!(final_record["phase"], "preparing");
            assert_eq!(final_record["rounds"][0]["phase"], "settled");
            assert_eq!(
                fs::metadata(path).expect("retained reservation").len(),
                crate::launch::MAX_RESERVATION_BYTES
            );
            continue;
        }
        assert_eq!(final_record["phase"], "failed");
        assert_eq!(final_record["helper_spawn_state"], "not-started");
        assert_eq!(final_record["helper_end"]["state"], "not-started");
        assert_eq!(final_record["driver_end"]["state"], "not-started");
        assert!(final_record["helper_parent_pid"].is_null());
        assert!(final_record["helper_parent_start"].is_null());
        assert_eq!(final_record["rounds"][1]["phase"], "failed");
        assert_eq!(final_record["rounds"][0]["phase"], "settled");
    }
    final_record
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
        loop_name: launch.loop_name.clone(),
        run: "T".into(),
        letter: launch.letter.clone(),
        round: None,
        budget: launch.budget,
        dry_run: true,
        expect_digest: None,
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
    if 'SUPERLOOP_MATRIX_STAGE' not in os.environ:
        save(pathlib.Path(fixture['evidence']), {'runtime_argv': fixture['seed']['plan']['runtime_argv'], 'bound_source_matrix': {'state': 'pending', 'rows': [{'name': 'letter', 'state': 'pending', 'target': '/home/worker/.local/inbox/dispatch.md', 'operation': 'read'}]}})
    print('{}')
elif '_container-helper' in args:
    transfer = socket.socket(fileno=0)
    transfer.recvmsg(1, socket.CMSG_SPACE(8))
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
