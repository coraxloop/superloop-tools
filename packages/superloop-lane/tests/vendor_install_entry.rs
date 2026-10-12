//! Production command admission and the shared protected payload writer.

#[path = "support/entry.rs"]
mod entry;

use entry::retry_busy_entry;

#[path = "support/vendor_fixture.rs"]
mod vendor_fixture;

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use superloop_lane::build::payload::{self, CODEX};
use vendor_fixture::{Fixture, file, successful};

fn command(fixture: &Fixture, args: &[&str]) -> Output {
    let entry = fixture.root.path().join("superloop-lane");
    if !entry.exists() {
        fs::copy(env!("CARGO_BIN_EXE_superloop-lane"), &entry).expect("protected production entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
    }
    retry_busy_entry(|| {
        Command::new(&entry)
            .env("HOME", fixture.root.path())
            .env_remove("ENTER_LOOP_REGISTRY")
            .args(args)
            .output()
    })
    .expect("production lane entry")
}

/// # Panics
/// Panics only if the injected errors or the fixture command violate the retry contract.
/// ´test:integration:fixture-entry-retries-only-text-busy´
#[test]
fn fixture_entry_retries_only_text_busy() {
    let mut attempts = 0;
    let output = retry_busy_entry(|| {
        attempts += 1;
        if attempts < 3 {
            Err(std::io::Error::from_raw_os_error(libc::ETXTBSY))
        } else {
            Command::new("/usr/bin/true").output()
        }
    })
    .expect("busy entry eventually executes");
    assert!(output.status.success());
    assert_eq!(attempts, 3);
    attempts = 0;
    let error = retry_busy_entry(|| {
        attempts += 1;
        Err(std::io::Error::from_raw_os_error(libc::ENOENT))
    })
    .expect_err("non-busy exec error is terminal");
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    assert_eq!(attempts, 1);
}

fn prepare(fixture: &Fixture, worker: u32) {
    let home = fixture.root.path();
    assert_ne!(worker, 41001);
    file(&home.join(".config/loops/registry.toml"), format!("namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{name = 'alpha', uid = 41001, launch = 'src', runs_root = '{}'}}]\n", home.join("runs").display()).as_bytes(), 0o600);
    file(
        &home.join(".config/loops/allocations.toml"),
        format!("[alpha]\nuids = {{ base = {worker}, count = 1 }}\n").as_bytes(),
        0o600,
    );
    for name in ["superloop", "codex-lane", "proxy"] {
        file(&home.join(name), b"#!/bin/sh\nexit 0\n", 0o700);
    }
    let path = home.join(".config/loops/alpha/workers.toml");
    let mut settings: toml::Value =
        toml::from_str(&fs::read_to_string(&path).expect("settings")).expect("TOML");
    settings.as_table_mut().expect("settings table").insert(
        "entry_bin".into(),
        toml::Value::String(home.join("superloop").display().to_string()),
    );
    file(
        &path,
        toml::to_string(&settings)
            .expect("settings TOML")
            .as_bytes(),
        0o600,
    );
    let prepared = successful(&command(fixture, &["prepare", "alpha"]));
    assert_eq!(prepared["allocation"]["base"], worker);
    let current = superloop_lane::settings::Settings::read(&path).expect("prepared settings");
    assert_eq!(current.configures("codex"), fixture.codex);
    assert_eq!(current.configures("claude"), fixture.claude);
}

fn install(fixture: &Fixture, pilot: bool) -> Output {
    let home = fixture.root.path();
    let mut args = vec!["install", "alpha", "--dry-run", "--podman-bin"];
    let podman = home.join("podman");
    args.push(podman.to_str().expect("fixture path"));
    let proxy = home.join("proxy");
    args.extend(["--proxy-bin", proxy.to_str().expect("proxy path")]);
    if pilot {
        args.push("--pilot");
    }
    command(fixture, &args)
}

/// # Panics
/// Panics only if fixture setup or the public entry violates the selected-program contract.
/// ´test:integration:vendor-install-entry-holder-uses-selected-program´
#[test]
fn vendor_install_entry_holder_uses_selected_program() {
    use nix::fcntl::{Flock, FlockArg};

    let fixture = Fixture::new(true, false);
    let home = fixture.root.path();
    let runs = home.join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    file(&home.join(".config/loops/registry.toml"), format!(
        "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{ name = 'alpha', uid = 41001, launch = 'src', runs_root = '{}' }}]\n",
        runs.display()
    ).as_bytes(), 0o600);
    file(
        &runs.join(".reservation-R.json"),
        &serde_json::to_vec(&json!({
            "schema":1,"loop":"alpha","run":"R","phase":"started","worker_uid":3000,
            "launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":["/usr/bin/podman"]}
        }))
        .expect("record JSON"),
        0o600,
    );
    let selected = home.join("selected-holder-program");
    file(
        &selected,
        b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nprintf 'running\\n'\n",
        0o700,
    );
    let directory = fs::File::open(home.join(".config/loops/alpha")).expect("configuration");
    let _holder = Flock::lock(directory, FlockArg::LockSharedNonblock).expect("shared holder");
    for dry_run in [true, false] {
        let mut args = vec![
            "install",
            "alpha",
            "--pilot",
            "--podman-bin",
            selected.to_str().expect("path"),
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let output = command(&fixture, &args);
        let diagnostic = if dry_run {
            let preview = successful(&output);
            assert_eq!(preview["blocked"], true);
            preview.to_string()
        } else {
            assert_eq!(output.status.code(), Some(2));
            String::from_utf8(output.stderr).expect("refusal")
        };
        assert!(
            diagnostic.contains("container alive, launcher gone"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(selected.to_str().expect("selected path")),
            "{diagnostic}"
        );
        assert!(
            !diagnostic.contains("owner-program: /usr/bin/podman"),
            "{diagnostic}"
        );
    }
}

/// # Panics
/// Panics only if fixture setup or the public entry violates the omitted-program contract.
/// ´test:integration:vendor-install-entry-omitted-program-keeps-presence-unknown´
#[test]
fn vendor_install_entry_omitted_program_keeps_presence_unknown() {
    use nix::fcntl::{Flock, FlockArg};

    let fixture = Fixture::new(true, false);
    let home = fixture.root.path();
    let runs = home.join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    file(&home.join(".config/loops/registry.toml"), format!(
        "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{ name = 'alpha', uid = 41001, launch = 'src', runs_root = '{}' }}]\n",
        runs.display()
    ).as_bytes(), 0o600);
    let recorded = home.join("recorded-holder-program");
    file(
        &runs.join(".reservation-R.json"),
        &serde_json::to_vec(&json!({
            "schema":1,"loop":"alpha","run":"R","phase":"started","worker_uid":3000,
            "launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":[recorded]}
        }))
        .expect("record JSON"),
        0o600,
    );
    let directory = fs::File::open(home.join(".config/loops/alpha")).expect("configuration");
    let _holder = Flock::lock(directory, FlockArg::LockSharedNonblock).expect("shared holder");
    for dry_run in [true, false] {
        let mut args = vec!["install", "alpha", "--pilot"];
        if dry_run {
            args.push("--dry-run");
        }
        let output = command(&fixture, &args);
        let diagnostic = if dry_run {
            let preview = successful(&output);
            assert_eq!(preview["blocked"], true);
            preview["busy"].to_string()
        } else {
            assert_eq!(output.status.code(), Some(2));
            String::from_utf8(output.stderr).expect("refusal")
        };
        assert!(
            diagnostic.contains("run R (started; container unknown, launcher gone"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(recorded.to_str().expect("recorded path")),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("differs from default /usr/bin/podman"),
            "{diagnostic}"
        );
    }
}

/// # Panics
/// Panics only if fixture setup or repair violates the recorded-program contract.
/// ´test:integration:vendor-repair-entry-keeps-mismatched-presence-unknown´
#[test]
fn vendor_repair_entry_keeps_mismatched_presence_unknown() {
    use nix::fcntl::{Flock, FlockArg};

    let fixture = Fixture::new(false, true);
    successful(&fixture.call());
    let home = fixture.root.path();
    let report = build_record(&fixture);
    let program = report["build_environment"]["podman_bin"]
        .as_str()
        .expect("build program");
    let runs = home.join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    file(&home.join(".config/loops/registry.toml"), format!(
        "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{ name = 'alpha', uid = 41001, launch = 'src', runs_root = '{}' }}]\n",
        runs.display()
    ).as_bytes(), 0o600);
    file(
        &home.join(".config/loops/alpha/install-generation.json"),
        &serde_json::to_vec(&json!({"schema":1,"phase":"complete",
            "proxy_bin":home.join("proxy"),"unit_dir":home.join("units")}))
        .expect("generation JSON"),
        0o600,
    );
    for recorded in ["/usr/bin/podman", "/missing/launch-podman"] {
        assert_ne!(recorded, program);
        file(
            &runs.join(".reservation-R.json"),
            &serde_json::to_vec(&json!({
                "schema":1,"loop":"alpha","run":"R","phase":"started","worker_uid":3000,
                "launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":[recorded]}
            }))
            .expect("record JSON"),
            0o600,
        );
        let directory = fs::File::open(home.join(".config/loops/alpha")).expect("configuration");
        let _holder = Flock::lock(directory, FlockArg::LockSharedNonblock).expect("shared holder");
        let preview = successful(&command(&fixture, &["repair", "alpha", "--dry-run"]));
        assert_eq!(preview["blocked"], true);
        let diagnostic = preview["busy"].to_string();
        assert!(
            diagnostic.contains("container unknown, launcher gone"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains(recorded), "{diagnostic}");
        assert!(diagnostic.contains(program), "{diagnostic}");
        assert!(!diagnostic.contains("--podman-bin"), "{diagnostic}");
    }
}

/// # Panics
/// Panics only if fixture setup fails or an empty pinned program reaches the install preflight.
/// ´test:integration:vendor-repair-entry-refuses-empty-pinned-program-before-preflight´
#[test]
fn vendor_repair_entry_refuses_empty_pinned_program_before_preflight() {
    use nix::fcntl::{Flock, FlockArg};

    let fixture = Fixture::new(false, true);
    successful(&fixture.call());
    let home = fixture.root.path();
    let config = home.join(".config/loops/alpha");
    file(
        &config.join("install-generation.json"),
        &serde_json::to_vec(&json!({"schema":1,"phase":"complete",
            "proxy_bin":home.join("proxy"),"unit_dir":home.join("units")}))
        .expect("generation JSON"),
        0o600,
    );
    let mut report = build_record(&fixture);
    report["build_environment"]["podman_bin"] = json!("");
    let report_bytes = serde_json::to_vec(&report).expect("build JSON");
    file(&config.join("image-build.json"), &report_bytes, 0o600);
    let calls = fs::read(home.join("calls")).expect("build calls");
    let generation = fs::read(config.join("install-generation.json")).expect("generation");
    for busy in [true, false] {
        let _holder = busy.then(|| {
            Flock::lock(
                fs::File::open(&config).expect("configuration"),
                FlockArg::LockSharedNonblock,
            )
            .expect("shared holder")
        });
        let result = command(&fixture, &["repair", "alpha", "--dry-run"]);
        assert!(!result.status.success());
        let diagnostic = String::from_utf8_lossy(&result.stderr);
        assert!(diagnostic.contains("repair-build-report"), "{diagnostic}");
        assert!(
            diagnostic.contains("build environment podman_bin is absent"),
            "{diagnostic}"
        );
        assert_eq!(result.stdout, Vec::<u8>::new());
        assert_eq!(
            fs::read(home.join("calls")).expect("unchanged calls"),
            calls
        );
        assert_eq!(
            fs::read(config.join("image-build.json")).expect("unchanged report"),
            report_bytes
        );
        assert_eq!(
            fs::read(config.join("install-generation.json")).expect("unchanged generation"),
            generation
        );
    }
}

fn build_record(fixture: &Fixture) -> Value {
    serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .path()
                .join(".config/loops/alpha/image-build.json"),
        )
        .expect("build record"),
    )
    .expect("record JSON")
}

fn write_record(fixture: &Fixture, record: &Value) {
    file(
        &fixture
            .root
            .path()
            .join(".config/loops/alpha/image-build.json"),
        &serde_json::to_vec(record).expect("record JSON"),
        0o600,
    );
}

/// ´test:integration:vendor-install-entry-admits-configurations-before-host-custody´
#[test]
fn vendor_install_entry_admits_configurations_before_host_custody() {
    for worker in [3000, 3001] {
        for (codex, claude) in [(true, false), (false, true), (true, true)] {
            let fixture = Fixture::new(codex, claude);
            successful(&fixture.call());
            prepare(&fixture, worker);
            for pilot in [false, true] {
                let output = install(&fixture, pilot);
                let error = String::from_utf8_lossy(&output.stderr);
                // A disposable /tmp fixture deliberately cannot satisfy the host's
                // root-owned, non-writable ancestor contract. This is admission
                // evidence, not a successful namespace installation.
                assert!(!output.status.success());
                assert!(error.contains("host ancestor"), "{error}");
                assert!(!error.contains("Claude needs"), "{error}");
            }
        }
    }
}

/// ´test:integration:vendor-install-entry-refuses-partial-or-changed-claude-evidence´
#[test]
fn vendor_install_entry_refuses_partial_or_changed_claude_evidence() {
    for worker in [3000, 3001] {
        let fixture = Fixture::new(true, true);
        successful(&fixture.call());
        prepare(&fixture, worker);
        let original = build_record(&fixture);
        for key in [
            "claude_version",
            "claude_sha256",
            "claude_source",
            "claude_image_program",
            "claude_exec_probe",
            "claude_runtime",
        ] {
            let mut record = original.clone();
            record.as_object_mut().expect("object").remove(key);
            write_record(&fixture, &record);
            for pilot in [false, true] {
                let output = install(&fixture, pilot);
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success());
                assert!(
                    error.contains(key)
                        || (key == "claude_exec_probe" && error.contains("claude-exec-help"))
                        || (key == "claude_runtime" && error.contains("claude-runtime")),
                    "wrong refusal for {key}: {error}"
                );
                assert!(
                    !error.contains("host ancestor"),
                    "partial {key} reached custody: {error}"
                );
            }
        }
        write_record(&fixture, &original);
        file(
            &fixture.root.path().join("claude"),
            b"changed after build",
            0o700,
        );
        let output = install(&fixture, false);
        assert!(String::from_utf8_lossy(&output.stderr).contains("Claude executable differs"));
    }
}

fn restore_directories(path: &Path) {
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("cleanup mode");
        for entry in fs::read_dir(path).expect("cleanup directory") {
            restore_directories(&entry.expect("entry").path());
        }
    }
}

/// ´test:integration:vendor-private-writer-snapshots-all-payloads-and-repeats´
#[test]
#[allow(clippy::too_many_lines)]
fn vendor_private_writer_snapshots_all_payloads_and_repeats() {
    let owner = nix::unistd::Uid::effective().as_raw();
    let group = nix::unistd::Gid::effective().as_raw();
    for worker in [3000, 3001] {
        assert_ne!(
            group, worker,
            "fixture loop group is distinct from either worker"
        );
        for (codex, claude) in [(true, false), (false, true), (true, true)] {
            let fixture = Fixture::new(codex, claude);
            let built = successful(&fixture.call());
            prepare(&fixture, worker);
            let home = fixture.root.path();
            for relative in [
                ".var",
                ".var/loops",
                ".var/loops/alpha",
                ".config/loops/alpha/lanes",
            ] {
                fs::create_dir(home.join(relative)).expect("private parent");
                fs::set_permissions(home.join(relative), fs::Permissions::from_mode(0o700))
                    .expect("parent mode");
            }
            let config = home.join(".config/loops/alpha");
            let settings = superloop_lane::settings::Settings::read(&config.join("workers.toml"))
                .expect("settings");
            let payloads =
                payload::install_payloads(&built, &settings).expect("selected build inputs");
            let guard = superloop_lane::install::InstallGuard::from_handed(
                &config,
                home,
                owner,
                fs::File::open(&config)
                    .expect("configuration descriptor")
                    .into(),
            )
            .expect("private writer guard");
            let data = home.join("data");
            fs::create_dir(&data).expect("fixture data");
            for name in [
                "codex-config.toml",
                "claude-settings.json",
                "worker-AGENTS.md",
                "box-init",
            ] {
                fs::copy(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("data")
                        .join(name),
                    data.join(name),
                )
                .expect("fixture source");
            }
            let image = built["image_digest"].as_str().expect("image");
            let commit = built["tools_commit"].as_str().expect("commit");
            let run = |expected: Option<&str>, dry: bool| {
                superloop_lane::install_private::run_payloads(
                    home,
                    "alpha",
                    group,
                    (owner, group),
                    &data,
                    &payloads,
                    image,
                    commit,
                    expected,
                    dry,
                    false,
                    &guard,
                )
            };
            let preview = run(None, true).expect("private snapshot preview");
            let fingerprint = preview["source_fingerprint"]
                .as_str()
                .expect("source fingerprint");
            let mut generation = json!({"schema":1,"phase":"preparing","image_digest":image,"tools_commit":commit,"source_fingerprint":fingerprint});
            for input in &payloads {
                generation[input.vendor.hash_key] = json!(input.sha256);
                generation[input.vendor.program_key] = json!(input.image_program);
                if input.vendor != CODEX {
                    generation["claude_template_dir"] = json!(input.template(
                        &home.join(".var/loops/alpha"),
                        image.strip_prefix("sha256:").expect("hash")
                    ));
                }
            }
            file(
                &config.join("install-generation.json"),
                &serde_json::to_vec(&generation).expect("generation"),
                0o600,
            );
            let wrong_fingerprint = "f".repeat(64);
            assert!(
                run(Some(&wrong_fingerprint), false).is_err(),
                "changed public snapshot refused"
            );
            let changed_config = payloads[0].config_source(&data);
            let original_config = fs::read(&changed_config).expect("configuration bytes");
            let mut changed = original_config.clone();
            changed.push(b'\n');
            file(&changed_config, &changed, 0o600);
            let error = run(Some(fingerprint), false).expect_err("source changed after preflight");
            assert!(
                error.detail.contains("public preflight snapshot"),
                "{error:?}"
            );
            file(&changed_config, &original_config, 0o600);
            let installed = run(Some(fingerprint), false).expect("shared private row writer");
            assert_eq!(installed["source_sha256"], preview["source_sha256"]);
            for input in &payloads {
                let template = input.template(
                    &home.join(".var/loops/alpha"),
                    image.strip_prefix("sha256:").expect("hash"),
                );
                let meta = fs::metadata(&template).expect("template");
                assert_eq!(
                    (meta.uid(), meta.gid(), meta.mode() & 0o7777),
                    (owner, group, 0o550)
                );
                assert_ne!(meta.gid(), worker);
                let manifest: Value =
                    serde_json::from_slice(&fs::read(template.join("manifest")).expect("manifest"))
                        .expect("JSON");
                assert_eq!(manifest[input.vendor.hash_key], input.sha256);
                assert_eq!(
                    fs::read(template.join("libexec/box-init")).expect("init"),
                    fs::read(data.join("box-init")).expect("source init")
                );
            }
            assert_eq!(run(Some(fingerprint), false).expect("repeat")["changed"], 0);
            restore_directories(&home.join(".var"));
        }
    }
}

/// ´test:integration:vendor-generation-refuses-partial-and-wrong-vendor-directory´
#[test]
fn vendor_generation_refuses_partial_and_wrong_vendor_directory() {
    payload::check_claude_generation(
        &json!({"schema":1,"phase":"complete","codex_sha256":"a".repeat(64)}),
    )
    .expect("old Codex generation");
    let fixture = Fixture::new(false, true);
    fixture.mutate_probe(|probe| probe["version"] = json!("0.1.0 (Claude Code)\n"));
    let built = successful(&fixture.call());
    let mut generation = json!({"image_digest":built["image_digest"],"claude_sha256":built["claude_sha256"],"claude_image_program":built["claude_image_program"],"claude_template_dir":fixture.root.path().join("runner-templates/claude").join("b".repeat(64))});
    payload::check_claude_generation(&generation).expect("complete vendor group");
    for key in [
        "claude_sha256",
        "claude_image_program",
        "claude_template_dir",
    ] {
        let mut partial = generation.clone();
        partial.as_object_mut().expect("object").remove(key);
        assert!(payload::check_claude_generation(&partial).is_err());
    }
    generation["claude_template_dir"] = json!(
        fixture
            .root
            .path()
            .join("runner-templates/codex")
            .join("b".repeat(64))
    );
    assert!(payload::check_claude_generation(&generation).is_err());
}

fn private_entry(fixture: &Fixture, expected: Option<&str>) -> Output {
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    let home = fixture.root.path();
    let built = build_record(fixture);
    let (sender, receiver) = UnixStream::pair().expect("descriptor channel");
    let receiver: OwnedFd = receiver.into();
    let home_fd = fs::File::open(home).expect("home descriptor");
    let config_fd =
        fs::File::open(home.join(".config/loops/alpha")).expect("configuration descriptor");
    let codex = if fixture.codex {
        home.join("codex")
    } else {
        PathBuf::default()
    };
    let host = if fixture.codex {
        home.join("codex-code-mode-host")
    } else {
        PathBuf::default()
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    command
        .env("HOME", home)
        .env_remove("ENTER_LOOP_REGISTRY")
        .arg("_install-private")
        .arg("alpha")
        .arg(home)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("data"))
        .arg(codex)
        .arg(host)
        .arg(built["image_digest"].as_str().expect("image"))
        .arg(built["codex_sha256"].as_str().unwrap_or_default())
        .arg(built["tools_commit"].as_str().expect("commit"));
    if let Some(expected) = expected {
        command.args(["--expected-source-sha256", expected]);
    } else {
        command.arg("--dry-run");
    }
    command
        .args(["--verified-home-fd", "0", "--verified-install-lock-fd", "1"])
        .stdin(Stdio::from(receiver))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("production private entry");
    let fds = [home_fd.as_raw_fd(), config_fd.as_raw_fd()];
    let mut byte = [1_u8];
    let mut data = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 16];
    // The fixture sends the same two held descriptors as the public entry.
    #[allow(unsafe_code)]
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut data;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        let bytes = u32::try_from(std::mem::size_of_val(&fds)).expect("two descriptors");
        message.msg_controllen = libc::CMSG_SPACE(bytes) as usize;
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(bytes) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        assert_eq!(
            libc::sendmsg(sender.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL),
            1,
            "descriptor transfer"
        );
    }
    drop(sender);
    child.wait_with_output().expect("private entry result")
}

/// ´test:integration:vendor-private-entry-installs-configured-payloads-for-two-workers´
#[test]
#[ignore = "node account: unshare refused, no podman or newuidmap; run with --ignored in a provisioned namespace root with loop uid 41001 and worker uids 3000/3001 mapped"]
fn vendor_private_entry_installs_configured_payloads_for_two_workers() {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "provisioned namespace root is required"
    );
    for worker in [3000, 3001] {
        for (codex, claude) in [(true, false), (false, true), (true, true)] {
            let fixture = Fixture::new(codex, claude);
            let built = successful(&fixture.call());
            prepare(&fixture, worker);
            let home = fixture.root.path();
            for relative in [
                ".var",
                ".var/loops",
                ".var/loops/alpha",
                ".config/loops/alpha/lanes",
            ] {
                fs::create_dir(home.join(relative)).expect("private parent");
                fs::set_permissions(home.join(relative), fs::Permissions::from_mode(0o700))
                    .expect("parent mode");
            }
            let preview = successful(&private_entry(&fixture, None));
            let fingerprint = preview["source_fingerprint"].as_str().expect("fingerprint");
            let settings = superloop_lane::settings::Settings::read(
                &home.join(".config/loops/alpha/workers.toml"),
            )
            .expect("settings");
            let payloads = payload::install_payloads(&built, &settings).expect("payloads");
            let image = built["image_digest"].as_str().expect("image");
            let hash = image.strip_prefix("sha256:").expect("hash");
            let mut generation = json!({"schema":1,"phase":"preparing","image_digest":image,"tools_commit":built["tools_commit"],"source_fingerprint":fingerprint});
            for input in &payloads {
                generation[input.vendor.hash_key] = json!(input.sha256);
                generation[input.vendor.program_key] = json!(input.image_program);
                if input.vendor != CODEX {
                    generation["claude_template_dir"] =
                        json!(input.template(&home.join(".var/loops/alpha"), hash));
                }
            }
            file(
                &home.join(".config/loops/alpha/install-generation.json"),
                &serde_json::to_vec(&generation).expect("generation"),
                0o600,
            );
            let installed = successful(&private_entry(&fixture, Some(fingerprint)));
            assert_eq!(
                installed["changed"], preview["changed"],
                "private entry preview/act parity"
            );
            for input in &payloads {
                let program = input
                    .template(&home.join(".var/loops/alpha"), hash)
                    .join("bin")
                    .join(input.vendor.name);
                let meta = fs::metadata(program).expect("installed program");
                assert_eq!(
                    (meta.uid(), meta.gid(), meta.mode() & 0o7777),
                    (0, 41001, 0o550)
                );
                assert_ne!(meta.uid(), worker);
                assert_ne!(meta.gid(), worker);
            }
            assert_eq!(
                successful(&private_entry(&fixture, Some(fingerprint)))["changed"],
                0
            );
            if codex {
                private_entry_counts_sign_in_repairs(&fixture);
            }
            if claude {
                let original = fs::read(home.join("claude")).expect("source");
                file(
                    &home.join("claude"),
                    b"source changed after preflight",
                    0o700,
                );
                let refused = private_entry(&fixture, Some(fingerprint));
                assert!(
                    String::from_utf8_lossy(&refused.stderr).contains("private program differs")
                );
                file(&home.join("claude"), &original, 0o700);
            }
            restore_directories(&home.join(".var"));
        }
    }
}

fn private_entry_counts_sign_in_repairs(fixture: &Fixture) {
    let sign_in = fixture.root.path().join(".config/loops/alpha/lanes/codex");
    assert_eq!(nix::unistd::Gid::effective().as_raw(), 0);
    assert_ne!(nix::unistd::Gid::effective().as_raw(), 41001);
    // Drift the canonical root back to the namespace owner's group. Only the
    // production private installation may restore the distinct loop group.
    nix::unistd::chown(&sign_in, None, Some(nix::unistd::Gid::from_raw(0)))
        .expect("owner group drift");
    fs::create_dir_all(sign_in.join("sessions")).expect("sessions");
    fs::set_permissions(sign_in.join("sessions"), fs::Permissions::from_mode(0o755))
        .expect("directory drift");
    for name in ["auth.json", "sessions/one.json", "sessions/two.json"] {
        file(&sign_in.join(name), b"synthetic fixture state", 0o644);
    }
    // main parses _install-private, binds both handed descriptors, runs the real
    // template writer and sign-in convergence, then combines their operation counts.
    let preview = successful(&private_entry(fixture, None));
    assert_eq!(preview["changed"], 5);
    for path in [&sign_in, &sign_in.join("auth.json")] {
        assert_eq!(fs::metadata(path).expect("preview group").gid(), 0);
    }
    assert_eq!(
        fs::metadata(sign_in.join("auth.json"))
            .expect("metadata")
            .mode()
            & 0o777,
        0o644,
        "preview preserves metadata"
    );
    let fingerprint = preview["source_fingerprint"]
        .as_str()
        .expect("source fingerprint");
    let acted = successful(&private_entry(fixture, Some(fingerprint)));
    assert_eq!(acted["changed"], preview["changed"]);
    assert_eq!(acted["sign_in"]["changes"], preview["sign_in"]["changes"]);
    for (path, group) in [(&sign_in, 41001), (&sign_in.join("auth.json"), 0)] {
        let metadata = fs::metadata(path).expect("converged custody");
        assert_eq!((metadata.uid(), metadata.gid()), (0, group));
    }
    assert_eq!(
        fs::metadata(sign_in.join("auth.json"))
            .expect("converged metadata")
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(successful(&private_entry(fixture, None))["changed"], 0);
    assert_eq!(
        successful(&private_entry(fixture, Some(fingerprint)))["changed"],
        0
    );
}
