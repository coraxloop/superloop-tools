//! Test-only mapped transaction. The native stand-in establishes no vendor behavior.
use super::*;
use crate::runtime_admission::fixture::{self, Declaration, FixtureRoot};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::sync::Arc;

struct Host {
    root: Option<tempfile::TempDir>,
    held: fs::File,
    identity: (u64, u64),
    sources: Option<[(u64, u64); 2]>,
    child: Option<ClaudeNamespaceChild>,
}
impl Host {
    fn cleanup(&mut self) {
        // Disarm path-recursive TempDir drop before any fallible stop or mapped cleanup.
        let path = self.root.take().expect("retained enclosing root").keep();
        if let Some(mut child) = self.child.take() {
            assert!(child.stop(), "transaction namespace did not stop");
        }
        self.check_sources()
            .expect("enclosing source custody before removal");
        claude_cleanup_contents_at(&self.held, true).expect("whole enclosing mapped cleanup");
        let same = fs::symlink_metadata(&path)
            .is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == self.identity);
        if same {
            fs::remove_dir(path).expect("remove unchanged emptied enclosure");
        }
    }
    fn check_sources(&self) -> Result<(), &'static str> {
        let Some(expected) = self.sources else {
            return Ok(());
        };
        let enclosing = PathBuf::from(format!("/proc/self/fd/{}", self.held.as_raw_fd()));
        let mut parents = vec![enclosing.clone()];
        for entry in fs::read_dir(&enclosing).map_err(|_| "enclosing directory")? {
            let entry = entry.map_err(|_| "enclosing entry")?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("lane-claude-admission-")
            {
                if !entry.file_type().map_err(|_| "root kind")?.is_dir() {
                    return Err("factory root kind");
                }
                parents.push(entry.path());
            }
        }
        for parent in parents {
            for (name, identity) in ["owner", "runs"].into_iter().zip(expected) {
                match fs::symlink_metadata(parent.join(name)) {
                    Ok(m) if m.is_dir() && (m.dev(), m.ino()) == identity => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err("moved directory identity differs"),
                }
            }
        }
        Ok(())
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if self.root.is_none() {
            return;
        }
        if std::thread::panicking() {
            // A panic escaping this drop during an unwind would abort every test in the binary.
            let _reported =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        } else {
            self.cleanup();
        }
    }
}

fn fixture_builder_scripts(owner: &Path) {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let mut digest = String::new();
    for byte in Sha256::digest(fs::read("/usr/bin/true").expect("stand-in bytes")) {
        write!(&mut digest, "{byte:02x}").expect("digest");
    }
    let mut help = String::new();
    for option in crate::build::payload::CLAUDE_EXEC_OPTIONS {
        writeln!(&mut help, "  {option}").expect("synthetic help");
    }
    help.push_str("  stream-json bypassPermissions acceptEdits plan\n");
    let probe = json!({
        "sha256":digest,"version":"0.1.0 (Claude Code)","help":help,
        "interpreter":{"path":"/usr/bin/node","sha256":"a".repeat(64)},
        "libraries":[{"path":"/usr/lib/libc.so","sha256":"a".repeat(64)}]
    });
    for (name, source) in [
        ("build", "exit 0\n".to_owned()),
        (
            "image",
            format!(
                "case \"$1\" in exists) exit 0 ;; inspect) printf '%s\\n' '{}' ;; *) exit 99 ;; esac\n",
                "b".repeat(64)
            ),
        ),
        (
            "run",
            format!(
                "case \"$1\" in ps) exit 0 ;; esac\ncase \" $* \" in *python3*) printf '%s\\n' '{probe}' ;; *--name=*) cat >/dev/null; printf 'fixture-attempt\\n'; exit 7 ;; *) printf 'git 2\\n' ;; esac\n"
            ),
        ),
    ] {
        fs::write(owner.join(name), source).expect("builder command source");
    }
}

fn launch(name: &str) -> Host {
    launch_with_builder(name, false)
}

fn launch_with_builder(name: &str, builder: bool) -> Host {
    use std::os::unix::process::CommandExt as _;
    let enclosing = tempfile::Builder::new()
        .prefix("lane-claude-transaction-")
        .tempdir()
        .expect("host-created enclosure");
    let program = builder.then(|| PathBuf::from("/usr/bin/bash"));
    let (root, bundle) = claude_standin_host_with_root(enclosing, program.as_deref());
    if name.starts_with("claude_fixture_service_round_")
        || name.starts_with("claude_fixture_service_attempt_")
    {
        fs::write(
            root.path().join("owner/.config/loops/allocations.toml"),
            "mail_uid=64001\n[alpha]\nuids={base=3000,count=2}\nmail_gids={base=64020,count=3}\n",
        )
        .expect("service fixture allocation before transfer");
    }
    if builder {
        fixture_builder_scripts(&root.path().join("owner"));
    }
    fs::create_dir(root.path().join("live")).expect("modeled live runs");
    let held = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root.path())
        .expect("held E");
    let m = held.metadata().expect("E identity");
    let sources = ["owner", "runs"].map(|name| {
        let m = fs::symlink_metadata(root.path().join(name)).expect("host-created source");
        (m.dev(), m.ino())
    });
    let mut host = Host {
        root: Some(root),
        held,
        identity: (m.dev(), m.ino()),
        sources: Some(sources),
        child: None,
    };
    let enclosing = host.root.as_ref().expect("E").path();
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights channel");
    let account = nix::unistd::User::from_uid(Uid::effective())
        .expect("passwd")
        .expect("account");
    let child = Command::new("/usr/bin/podman")
        .args(["unshare"])
        .arg(std::env::current_exe().expect("test image"))
        .args([
            "--exact",
            &format!("credential::tests::transaction::{name}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .env("SUPERLOOP_CLAUDE_NAMESPACE_PROOF", "1")
        .env("CLAUDE_TRANSACTION_ROOT", enclosing)
        .env("CLAUDE_TRANSACTION_ACCOUNT", account.dir)
        .env("CLAUDE_STANDIN_MANIFEST", &bundle.manifest)
        .envs(program.iter().map(|path| ("CLAUDE_FIXTURE_BUILDER", path)))
        .env(
            "CLAUDE_NAMESPACE_IDENTITY",
            enclosing.join("namespace-init"),
        )
        .env("TMPDIR", enclosing)
        .stdin(Stdio::from(OwnedFd::from(input)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("transaction namespace");
    host.child = Some(ClaudeNamespaceChild {
        child: Some(child),
        root: None,
        identity: Some(enclosing.join("namespace-init")),
        stopped: None,
    });
    loop_home::anchor::transport::send(&sender, &bundle.descriptors).expect("held bundle");
    host
}

fn enter(name: &str, body: fn(&Path)) -> bool {
    if std::env::var_os("SUPERLOOP_CLAUDE_NAMESPACE_PROOF").is_none() {
        return false;
    }
    if std::env::var_os("CLAUDE_NAMESPACE_INIT").is_none() {
        claude_pid_namespace(&format!("transaction::{name}"));
        return true;
    }
    assert_eq!(owner_identity(), (0, 0));
    claude_record_namespace_init();
    // No proof is captured; a host killed without unwinding cannot leave an endless case.
    std::thread::spawn(namespace_deadline);
    let enclosing = PathBuf::from(std::env::var_os("CLAUDE_TRANSACTION_ROOT").expect("E"));
    body(&enclosing);
    true
}

fn mount_service_procfs(parent: Option<&std::ffi::OsStr>) -> Result<(), LaneError> {
    use nix::mount::{MsFlags, mount};
    let parent = parent.ok_or_else(|| {
        LaneError::input(
            "fixture-mount-namespace",
            "parent mount namespace is absent",
        )
    })?;
    // SAFETY: the fixed mount-namespace flag contains no pointers. The mount
    // below is unreachable unless this thread has entered its own namespace.
    #[allow(unsafe_code)]
    let unshare_result = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if unshare_result != 0 {
        return Err(LaneError::operation(
            "fixture-mount-namespace",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|error| LaneError::operation("fixture-mount-propagation", error.to_string()))?;
    let current = fs::read_link("/proc/self/ns/mnt")
        .map_err(|error| LaneError::input("fixture-mount-namespace", error.to_string()))?;
    if current == Path::new(parent) {
        return Err(LaneError::input(
            "fixture-mount-namespace",
            "service fixture still shares its parent's mount namespace",
        ));
    }
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|error| LaneError::operation("fixture-procfs", error.to_string()))?;
    Ok(())
}

/// # Panics
/// Panics if a missing parent identity reaches the namespace or mount calls.
/// ´test:unit:claude-fixture-service-refuses-unproved-mount-namespace´
#[test]
fn claude_fixture_service_refuses_unproved_mount_namespace() {
    let before = fs::read_link("/proc/self/ns/mnt").expect("current mount namespace");
    let error = mount_service_procfs(None).expect_err("unproved namespace refuses");
    assert_eq!(error.kind, "fixture-mount-namespace", "{error:?}");
    assert_eq!(
        fs::read_link("/proc/self/ns/mnt").expect("mount namespace after refusal"),
        before,
        "unproved fixture must not enter a mount namespace"
    );
}

// The namespace init ignores a signal it sends itself; its exit ends every member. The
// deadline follows the host's 180-second watchdog, so a living host reports first.
#[allow(clippy::exit)]
fn namespace_deadline() {
    std::thread::sleep(Duration::from_secs(240));
    std::process::exit(124);
}

fn wait_event(host: &mut Host, name: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let root = host.root.as_ref().expect("E").path();
        if root.join(name).exists() {
            return;
        }
        if host
            .child
            .as_mut()
            .expect("child")
            .try_wait()
            .expect("status")
            .is_some()
        {
            fail_with_output(host, &format!("transaction exited before event {name}"));
        }
        if std::time::Instant::now() >= deadline {
            fail_with_output(host, &format!("transaction event {name} timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn fail_with_output(host: &mut Host, event: &str) -> ! {
    let readiness = host
        .root
        .as_ref()
        .and_then(|root| fs::read_to_string(root.path().join("service-readiness-missing")).ok());
    let mut child = host.child.take().expect("diagnostic child");
    let stopped = child.stop();
    if !stopped && let Some(root) = host.root.take() {
        // Consuming the child for diagnostics must not authorize cleanup after an unproved stop.
        let _retained = root.keep();
    }
    let output = child.wait_with_output().expect("failed child output");
    panic!(
        "{event}; namespace stopped={stopped}; readiness missing={}\nstdout:\n{}\nstderr:\n{}",
        readiness.as_deref().unwrap_or("unmeasured"),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn finish(host: &mut Host, success: bool) {
    finish_until(
        host,
        success,
        std::time::Instant::now() + Duration::from_secs(180),
    );
}

fn finish_until(host: &mut Host, success: bool, deadline: std::time::Instant) {
    while host
        .child
        .as_mut()
        .expect("child")
        .try_wait()
        .expect("status")
        .is_none()
    {
        if std::time::Instant::now() >= deadline {
            fail_with_output(host, "transaction outer watchdog");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = host
        .child
        .take()
        .expect("child")
        .wait_with_output()
        .expect("output");
    assert_eq!(
        output.status.success(),
        success,
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if success {
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    } else {
        assert!(String::from_utf8_lossy(&output.stderr).contains("injected child unwind"));
    }
}

fn moved_root(enclosing: &Path) -> (Arc<FixtureRoot>, Vec<loop_home::anchor::Anchor>) {
    moved_root_after(enclosing, || {})
}

fn moved_root_after(
    enclosing: &Path,
    before_move: impl FnOnce(),
) -> (Arc<FixtureRoot>, Vec<loop_home::anchor::Anchor>) {
    let manifest = std::env::var("CLAUDE_STANDIN_MANIFEST").expect("manifest");
    let (_, anchors) = crate::container_entry::receive_for(
        &manifest,
        &std::io::stdin(),
        "container-helper",
        Some("alpha"),
    )
    .expect("receive held identities before moving storage");
    loop_home::anchor::transport::replace_stdin("container-helper").expect("close setup");
    // A pathname supplied alone never gives this test permission to move and later remove it.
    for (name, anchor) in ["owner", "runs"].into_iter().zip(&anchors) {
        let named = fs::symlink_metadata(enclosing.join(name)).expect("source directory");
        let held = nix::sys::stat::fstat(anchor).expect("held source identity");
        assert!(named.is_dir());
        assert_eq!((named.dev(), named.ino()), (held.st_dev, held.st_ino));
    }
    let root = FixtureRoot::create(&enclosing.join("live")).expect("child-created root");
    before_move();
    let moved = move_sources(enclosing, &root, &anchors);
    if let Err(error) = moved {
        // No recursive drop is authorized for an unverified directory moved into the root.
        // The host checks the retained source identities after stopping the namespace, too.
        std::mem::forget(root);
        panic!("injected child unwind: {error}");
    }
    (root, anchors)
}
fn move_sources(
    enclosing: &Path,
    root: &FixtureRoot,
    anchors: &[loop_home::anchor::Anchor],
) -> Result<(), &'static str> {
    for (name, anchor) in ["owner", "runs"].into_iter().zip(anchors) {
        let destination = root.path().join(name);
        fs::rename(enclosing.join(name), &destination).map_err(|_| "source rename")?;
        let named = fs::symlink_metadata(destination).map_err(|_| "moved directory metadata")?;
        let held = nix::sys::stat::fstat(anchor).map_err(|_| "held source metadata")?;
        if !named.is_dir() || (named.dev(), named.ino()) != (held.st_dev, held.st_ino) {
            return Err("moved directory identity differs");
        }
    }
    Ok(())
}

fn mapped_storage(root: &FixtureRoot) -> PathBuf {
    let old = claude_standin_worker(&root.path().join("runs"));
    let parent = root.path().join("owner/.cache/tmp");
    fs::create_dir_all(&parent).expect("worker parent");
    let worker = parent.join("lane-alpha-R");
    fs::rename(old, &worker).expect("mapped worker at plan home");
    let path = worker.join(".claude/synthetic");
    fs::write(&path, b"synthetic").expect("mapped file");
    nix::unistd::chown(&path, Some(Uid::from_raw(3000)), Some(Gid::from_raw(3000)))
        .expect("mapped uid");
    worker
}

/// # Panics
/// Panics if the admitted round fails its mapped custody or projection contract.
/// ´test:unit:claude-fixture-admitted-round´
#[test]
fn claude_fixture_admitted_round() {
    if enter("claude_fixture_admitted_round", round_body) {
        return;
    }
    let mut host = launch("claude_fixture_admitted_round");
    let path = host.root.as_ref().expect("E").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

fn service_procfs_body(enclosing: &Path) {
    transaction_body(enclosing, |_, _, _, _, record, admission, _| {
        let enclosing =
            PathBuf::from(std::env::var_os("CLAUDE_TRANSACTION_ROOT").expect("enclosing root"));
        let handed: Value = serde_json::from_slice(
            &fs::read(enclosing.join("namespace-init")).expect("host-view identity handoff"),
        )
        .expect("host-view identity JSON");
        assert_eq!(handed["pid"], record["helper_pid"]);
        assert_eq!(handed["start"], record["helper_start"]);
        let parent = std::env::var_os("CLAUDE_PARENT_MOUNT_NAMESPACE");
        mount_service_procfs(parent.as_deref()).expect("isolated procfs mount");
        let namespace_pid: u32 = fs::read_link("/proc/self")
            .expect("namespace proc identity")
            .to_str()
            .expect("numeric proc identity")
            .parse()
            .expect("namespace PID");
        assert_eq!(namespace_pid, std::process::id());
        assert_ne!(
            u64::from(namespace_pid),
            handed["pid"].as_u64().expect("host PID")
        );
        let local_start = crate::container_helper::process_start(namespace_pid)
            .expect("namespace-local start tick");
        assert!(crate::container_helper::process_alive(
            namespace_pid,
            local_start
        ));
        let mut foreign = record.clone();
        foreign["plan"]["run"] = json!("foreign");
        let error = admission
            .scope_record(&foreign)
            .expect_err("foreign fixture run");
        assert_eq!(error.kind, "fixture-scope", "{error:?}");
    });
}

#[allow(clippy::too_many_lines)]
fn install_service_template(
    root: &FixtureRoot,
    owner: &Path,
    payload: &crate::build::payload::InstallPayload,
    image: &str,
) -> PathBuf {
    let data = root.path().join("install-inputs");
    fs::create_dir(&data).expect("install source directory");
    for (name, bytes, mode) in [
        ("claude-settings.json", b"{}\n".as_slice(), 0o600),
        (
            "worker-AGENTS.md",
            b"synthetic fixture charter\n".as_slice(),
            0o600,
        ),
        ("box-init", b"#!/bin/sh\nexit 0\n".as_slice(), 0o700),
    ] {
        let path = data.join(name);
        fs::write(&path, bytes).expect("install source");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("source mode");
    }
    fs::copy(
        crate::build::default_template_dir().join("box-init"),
        data.join("box-init"),
    )
    .expect("production init source");
    let loop_root = owner.join(".var/loops/alpha");
    fs::create_dir_all(&loop_root).expect("loop install root");
    let config = owner.join(".config/loops/alpha");
    let settings = config.join("workers.toml");
    let mut document: toml::Table =
        toml::from_str(&fs::read_to_string(&settings).expect("fixture settings"))
            .expect("fixture settings TOML");
    let (template, socket_dir) = crate::install::install_paths(
        &loop_root,
        payload,
        image.strip_prefix("sha256:").expect("image digest"),
    );
    document["template_dir"] = toml::Value::String(template.display().to_string());
    document["socket_dir"] = toml::Value::String(socket_dir.display().to_string());
    fs::write(
        &settings,
        toml::to_string(&document).expect("fixture settings text"),
    )
    .expect("fixture installed settings");
    fs::remove_file(config.join("install-generation.json"))
        .expect("replace staged transaction generation with installer generation");
    let held = fs::File::open(&config).expect("install directory");
    let guard = crate::install::InstallGuard::from_transferred(&config, held.into())
        .expect("fixture install lock");
    let payloads = std::slice::from_ref(payload);
    let preview = crate::install_private::run_payloads(
        owner,
        "alpha",
        64000,
        (0, 0),
        &data,
        payloads,
        image,
        "fixture",
        None,
        true,
        false,
        &guard,
    )
    .expect("installer preview");
    let source = preview["source_fingerprint"]
        .as_str()
        .expect("measured sources");
    let init_digest = crate::build::sha256_bytes(
        &fs::read(data.join("box-init")).expect("init source"),
        &data,
    )
    .expect("init digest");
    let generation_path = config.join("install-generation.json");
    let mut generation = crate::install::fixture_publish_claude_generation(
        &generation_path,
        owner,
        "alpha",
        payload,
        image,
        source,
        &init_digest,
    )
    .expect("installer pending generation");
    crate::install_private::run_payloads(
        owner,
        "alpha",
        64000,
        (0, 0),
        &data,
        payloads,
        image,
        "fixture",
        Some(source),
        false,
        false,
        &guard,
    )
    .expect("installer act");
    crate::install::fixture_complete_claude_generation(&generation_path, &mut generation)
        .expect("installer complete generation");
    let manifest: Value =
        serde_json::from_slice(&fs::read(template.join("manifest")).expect("installed manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["image_digest"], image);
    assert_eq!(manifest["claude_sha256"], payload.sha256);
    let generation: Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("complete generation"))
            .expect("generation JSON");
    assert_eq!(generation["phase"], "complete");
    assert_eq!(
        generation["claude_template_dir"],
        template.display().to_string()
    );
    assert_eq!(generation["claude_sha256"], manifest["claude_sha256"]);
    assert_eq!(generation["template_dir"], template.display().to_string());
    assert_eq!(generation["socket_dir"], socket_dir.display().to_string());
    assert_eq!(
        generation["unit_dir"],
        owner.join(".config/systemd/user").display().to_string()
    );
    let proxy = owner.join("proxy-fixture");
    assert_eq!(generation["proxy_bin"], proxy.display().to_string());
    assert_eq!(
        generation["proxy_sha256"],
        crate::build::sha256(&proxy).expect("proxy digest")
    );
    template
}

/// # Panics
/// Panics if the private installer does not materialize the Claude template and measured manifest.
/// ´test:unit:claude-fixture-service-installer-materializes-template´
#[test]
fn claude_fixture_service_installer_materializes_template() {
    if enter(
        "claude_fixture_service_installer_materializes_template",
        |enclosing| {
            transaction_body(enclosing, |root, owner, _, _, _, _, _| {
                use sha2::{Digest as _, Sha256};
                use std::fmt::Write as _;
                let mut digest = String::new();
                for byte in Sha256::digest(fs::read("/usr/bin/true").expect("stand-in bytes")) {
                    write!(&mut digest, "{byte:02x}").expect("digest");
                }
                let payload = crate::build::payload::InstallPayload {
                    vendor: crate::build::payload::CLAUDE,
                    bin: PathBuf::from("/usr/bin/true"),
                    sha256: digest,
                    image_program: crate::build::payload::CLAUDE_IMAGE_PROGRAM.into(),
                    companion: None,
                };
                let image = format!("sha256:{}", "a".repeat(64));
                let template = install_service_template(root, owner, &payload, &image);
                assert!(template.join("bin/claude").is_file());
                assert!(template.join("libexec/box-init").is_file());
            });
        },
    ) {
        return;
    }
    let mut host = launch("claude_fixture_service_installer_materializes_template");
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

fn service_installed_inputs(root: &FixtureRoot, owner: &Path) -> PathBuf {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let mut digest = String::new();
    for byte in Sha256::digest(fs::read("/usr/bin/true").expect("stand-in bytes")) {
        write!(&mut digest, "{byte:02x}").expect("digest");
    }
    let settings = owner.join(".config/loops/alpha/workers.toml");
    let mut source = fs::read_to_string(&settings).expect("settings");
    source.push_str("backend_argv = { claude = ['/usr/libexec/superloop/claude'] }\n");
    fs::write(&settings, source).expect("configured Claude");
    let request = crate::build::BuildRequest {
        loop_name: "alpha".into(),
        claude: Some(crate::build::payload::ProgramInput {
            bin: PathBuf::from("/usr/bin/true"),
            version: "0.1.0".into(),
            sha256: digest.clone(),
            source: "https://example.invalid/claude".into(),
        }),
        base_image: format!("registry.invalid/base@sha256:{}", "a".repeat(64)),
        codex_bin: PathBuf::new(),
        codex_host_bin: PathBuf::new(),
        codex_version: String::new(),
        codex_sha256: String::new(),
        codex_host_sha256: String::new(),
        codex_source: String::new(),
        podman_bin: PathBuf::from(
            std::env::var_os("CLAUDE_FIXTURE_BUILDER").expect("held builder path"),
        ),
        template_dir: crate::build::default_template_dir(),
        dry_run: false,
    };
    let result = crate::build::run(owner, &request).expect("production image build");
    let report: Value = serde_json::from_slice(
        &fs::read(owner.join(".config/loops/alpha/image-build.json")).expect("image report"),
    )
    .expect("image report JSON");
    assert_eq!(result["image_digest"], format!("sha256:{}", "b".repeat(64)));
    assert_eq!(report["image_digest"], result["image_digest"]);
    assert_eq!(report["claude_sha256"], digest);
    assert_eq!(
        report["claude_image_program"],
        "/usr/libexec/superloop/claude"
    );
    let installed = crate::settings::Settings::read(&settings).expect("builder-updated settings");
    let payloads = crate::build::payload::install_payloads(&report, &installed)
        .expect("builder-produced install payload");
    assert_eq!(payloads.len(), 1);
    let template = install_service_template(
        root,
        owner,
        &payloads[0],
        result["image_digest"].as_str().expect("built image"),
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(template.join("manifest")).expect("installed manifest"))
            .expect("manifest JSON");
    let generation: Value = serde_json::from_slice(
        &fs::read(owner.join(".config/loops/alpha/install-generation.json"))
            .expect("installed generation"),
    )
    .expect("generation JSON");
    crate::launch::check_backend_pin_records(
        BoxBackend::Claude,
        &manifest,
        &report,
        &generation,
        &template,
    )
    .expect("selected build and install pins agree");
    assert_eq!(generation["init_sha256"], report["init_sha256"]);
    template
}

/// # Panics
/// Panics if the held builder cannot publish the selected image report.
/// ´test:unit:claude-fixture-service-builder-publishes-image-report´
#[test]
fn claude_fixture_service_builder_publishes_image_report() {
    if enter(
        "claude_fixture_service_builder_publishes_image_report",
        |enclosing| {
            transaction_body(enclosing, |root, owner, _, _, _, _, _| {
                let _template = service_installed_inputs(root, owner);
            });
        },
    ) {
        return;
    }
    let mut host = launch_with_builder(
        "claude_fixture_service_builder_publishes_image_report",
        true,
    );
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServiceCase {
    NoClient,
    Due,
    Attempt,
    OutsideSession,
}

#[allow(clippy::too_many_lines)]
fn service_client_or_driver_entry() -> bool {
    use std::io::{Read as _, Write as _};
    let Some(run) = std::env::var_os("CLAUDE_FIXTURE_CLIENT_RUN") else {
        return false;
    };
    let run = PathBuf::from(run);
    if std::env::var_os("CLAUDE_FIXTURE_DRIVER_ENTRY").is_some() {
        let mut start = [0_u8];
        if std::io::stdin().read_exact(&mut start).is_err() {
            return true;
        }
        assert_eq!(start, *b"G");
        let mut client = Command::new(std::env::current_exe().expect("client test image"))
            .args([
                "--exact",
                std::env::var("CLAUDE_FIXTURE_ENTRY_NAME")
                    .expect("entry selector")
                    .as_str(),
                "--nocapture",
                "--test-threads=1",
            ])
            .env_remove("CLAUDE_FIXTURE_DRIVER_ENTRY")
            .env("CLAUDE_FIXTURE_CLIENT_ENTRY", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("driver starts client");
        client
            .stdin
            .take()
            .expect("client prompt")
            .write_all(crate::FIRST_DISPATCH_PROMPT.as_bytes())
            .expect("client prompt frame input");
        let output = client.wait_with_output().expect("client result");
        assert!(
            output.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = String::from_utf8_lossy(&output.stdout);
        assert!(
            result.contains("fixture-attempt"),
            "client output: {result}"
        );
        assert!(
            result.contains("CLIENT-STATUS=7"),
            "client status: {result}"
        );
        writeln!(std::io::stdout().lock(), "DRIVER-CLIENT-RESULT={result}")
            .expect("driver client record");
        return true;
    }
    assert!(std::env::var_os("CLAUDE_FIXTURE_CLIENT_ENTRY").is_some());
    nix::unistd::setgid(Gid::from_raw(64000)).expect("loop group");
    nix::unistd::setuid(Uid::from_raw(64000)).expect("loop uid");
    assert_eq!(owner_identity(), (64000, 64000));
    let result = crate::container_helper::client(&run);
    if std::env::var_os("CLAUDE_FIXTURE_OUTSIDE_SESSION").is_some() {
        let error = result.expect_err("foreign client is refused");
        writeln!(std::io::stdout().lock(), "CLIENT-REFUSAL={}", error.kind)
            .expect("client refusal record");
    } else {
        let status = result.expect("production client attempt");
        writeln!(std::io::stdout().lock(), "CLIENT-STATUS={status}").expect("client status record");
    }
    true
}

#[allow(clippy::too_many_lines)]
fn service_round_body(enclosing: &Path, scenario: ServiceCase) {
    use std::io::Write as _;
    transaction_body(
        enclosing,
        |root, owner, runs, worker, _, admission, document| {
            let _template = service_installed_inputs(root, owner);
            let identity = runs.join(".launch-R");
            for (name, bytes) in [
                ("passwd", "worker:x:3000:3000::/home/worker:/bin/sh\n"),
                ("group", "worker:x:3000:\nloop:x:64000:worker\n"),
            ] {
                let path = identity.join(name);
                fs::write(&path, bytes).expect("fixture home identity");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o440))
                    .expect("identity mode");
                nix::unistd::chown(&path, Some(Uid::from_raw(0)), Some(Gid::from_raw(64000)))
                    .expect("identity group");
            }
            let (mut plan, _) = crate::load_launch_plan_admitted(
                owner,
                "alpha",
                "R",
                (0, 0),
                Some(BoxBackend::Claude),
                admission,
            )
            .expect("admitted service plan after production install");
            plan.select_worker_uid(3000).expect("selected worker");
            plan.select_container_program(Path::new("/usr/bin/bash"))
                .expect("held runtime program");
            let selection = json!({
                "model":"claude-sonnet-4-5","effort":"high",
                "model_source":"letter","effort_source":"letter"
            });
            plan.select_launch_model(&selection)
                .expect("selected letter model");
            let mail_name = plan.document["mail"]["identity"]["name"]
                .as_str()
                .expect("selected mail identity");
            let mail = owner
                .join(".var/loops/alpha/workers")
                .join(mail_name)
                .join("mail");
            fs::create_dir_all(&mail).expect("fixture mail endpoint");
            fs::set_permissions(&mail, fs::Permissions::from_mode(0o700)).expect("mail mode");
            let socket = owner.join(".var/loops/alpha/sockets/vendor/proxy.sock");
            fs::create_dir_all(socket.parent().expect("vendor socket directory"))
                .expect("vendor socket parent");
            let prior_cwd = std::env::current_dir().expect("fixture cwd");
            std::env::set_current_dir(owner.join(".var/loops/alpha"))
                .expect("short vendor socket address");
            let _vendor = std::os::unix::net::UnixListener::bind("sockets/vendor/proxy.sock")
                .expect("fixture vendor socket");
            std::env::set_current_dir(prior_cwd).expect("restore fixture cwd");
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))
                .expect("vendor socket mode");
            let letter = owner.join("service-letter.txt");
            fs::write(&letter, b"Model: claude-sonnet-4-5\nEffort: high\n")
                .expect("fixture service letter");

            let home = claude_sign_in_dir(owner, "alpha");
            fs::write(home.join(".fixture-refresh-sentinel-arm"), b"armed")
                .expect("owner program sentinel arm");
            let source_path = home.join(".credentials.json");
            if scenario == ServiceCase::Due {
                let expiry = now_seconds().expect("clock") + 300;
                fs::write(&source_path, claude_document(expiry * 1000).to_string())
                    .expect("due source");
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600))
                    .expect("source mode");
            }
            let source_bytes = fs::read(&source_path).expect("owner source before service");
            let source_meta = fs::metadata(&source_path).expect("owner source metadata");

            let parent = std::env::var_os("CLAUDE_PARENT_MOUNT_NAMESPACE");
            mount_service_procfs(parent.as_deref()).expect("isolated service procfs");
            let client_runs =
                if matches!(scenario, ServiceCase::Attempt | ServiceCase::OutsideSession) {
                    let alias = tempfile::Builder::new()
                        .prefix("lane-claude-client-runs-")
                        .tempdir_in("/tmp")
                        .expect("client runs mountpoint");
                    fs::set_permissions(alias.path(), fs::Permissions::from_mode(0o711))
                        .expect("client runs traversal");
                    Some(alias)
                } else {
                    None
                };
            assert_eq!(
                fs::read_link("/proc/self")
                    .expect("namespace proc identity")
                    .to_str()
                    .expect("numeric proc identity")
                    .parse::<u32>()
                    .expect("PID"),
                std::process::id(),
                "service caller uses the fresh procfs"
            );
            let mut launcher = Command::new("/bin/sh")
                .args(["-c", "read -r ignored"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("namespace-local launcher");
            let launcher_pid = launcher.id();
            let launcher_start = crate::container_helper::process_start(launcher_pid)
                .expect("namespace-local launcher start");
            let reservation = runs.join(".reservation-R.json");
            let record = json!({
                "schema":1,"phase":"preparing","loop":"alpha","run":"R",
                "worker_uid":3000,"launcher_pid":launcher_pid,"launcher_start":launcher_start,
                "active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}],
                "plan":plan.document,"model_selection":selection,"letter_source":letter
            });
            crate::launch::publish_reservation(&reservation, &record)
                .expect("preparing service reservation");
            let before = fs::read(&reservation).expect("reservation before service");
            let worker_file = worker.join(".claude/.credentials.json");
            let prior_worker = fs::read(&worker_file).ok();
            let (projected_tx, projected_rx) = std::sync::mpsc::sync_channel(1);
            let request_socket =
                crate::container_helper::socket_path(&runs.join("R")).expect("request socket path");
            let control_socket = crate::container_helper::control_socket_path(&runs.join("R"))
                .expect("control socket path");
            let evidence_path = runs.join(".launch-R/credential-refresh.json");
            let threads_before = fs::read_dir("/proc/self/task")
                .expect("service caller threads before entry")
                .count();
            let service_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let release = if scenario == ServiceCase::Due {
                None
            } else {
                let input = launcher.stdin.take().expect("launcher input");
                let evidence = evidence_path.clone();
                let request = request_socket.clone();
                let control = control_socket.clone();
                let diagnostic = enclosing.join("service-readiness-missing");
                let run_dir = client_runs
                    .as_ref()
                    .map_or(runs, tempfile::TempDir::path)
                    .join("R");
                let reservation = reservation.clone();
                let root_meta =
                    fs::metadata(client_runs.as_ref().map_or(runs, tempfile::TempDir::path))
                        .expect("client runs root identity");
                let client_socket = client_runs
                    .as_ref()
                    .map(|root| root.path().join(".container-R.sock"));
                let selector = match scenario {
                    ServiceCase::Attempt => {
                        "credential::tests::transaction::claude_fixture_service_attempt_admits_driver_client"
                    }
                    ServiceCase::OutsideSession => {
                        "credential::tests::transaction::claude_fixture_service_attempt_refuses_outside_session"
                    }
                    _ => "",
                };
                let done = Arc::clone(&service_done);
                let live_worker_file = worker_file.clone();
                Some(std::thread::spawn(move || {
                    while !(evidence.exists() && request.exists() && control.exists()) {
                        if done.load(std::sync::atomic::Ordering::Acquire) {
                            return "service returned before readiness".to_owned();
                        }
                        let missing = [
                            (!evidence.exists()).then_some("first periodic evidence"),
                            (!request.exists()).then_some("request socket"),
                            (!control.exists()).then_some("control socket"),
                        ]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(", ");
                        fs::write(&diagnostic, missing).expect("readiness diagnostic");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    projected_tx
                        .send((
                            fs::metadata(&live_worker_file)
                                .expect("live worker projection metadata"),
                            fs::read(&live_worker_file).expect("live worker projection"),
                        ))
                        .expect("live publication observation");
                    let mut result = String::new();
                    if matches!(scenario, ServiceCase::Attempt | ServiceCase::OutsideSession) {
                        let alias_socket = client_socket.as_ref().expect("client socket alias");
                        fs::write(alias_socket, b"").expect("client socket mountpoint");
                        nix::mount::mount(
                            Some(request.as_path()),
                            alias_socket,
                            None::<&str>,
                            nix::mount::MsFlags::MS_BIND,
                            None::<&str>,
                        )
                        .expect("private bind of admitted request socket");
                        let original = fs::metadata(&request).expect("service request socket");
                        let bound = fs::metadata(alias_socket).expect("bound request socket");
                        assert_eq!(
                            (bound.dev(), bound.ino()),
                            (original.dev(), original.ino()),
                            "client reaches the service's socket inode"
                        );
                        let mut driver =
                            Command::new(std::env::current_exe().expect("driver image"))
                                .args(["--exact", selector, "--nocapture", "--test-threads=1"])
                                .env("CLAUDE_FIXTURE_CLIENT_RUN", &run_dir)
                                .env("CLAUDE_FIXTURE_ENTRY_NAME", selector)
                                .env("CLAUDE_FIXTURE_DRIVER_ENTRY", "1")
                                .env("SUPERLOOP_CLIENT_ROOT_DEV", root_meta.dev().to_string())
                                .env("SUPERLOOP_CLIENT_ROOT_INO", root_meta.ino().to_string())
                                .env("SUPERLOOP_CLIENT_SOCKET_NAME", ".container-R.sock")
                                .stdin(Stdio::piped())
                                .stdout(Stdio::piped())
                                .stderr(Stdio::piped())
                                .spawn()
                                .expect("dedicated driver entry");
                        let mut saved: Value = serde_json::from_slice(
                            &fs::read(&reservation).expect("reservation for driver entry"),
                        )
                        .expect("reservation JSON");
                        saved["driver_entry_pid"] = json!(driver.id());
                        saved["driver_entry_start"] = json!(
                            crate::container_helper::process_start(driver.id())
                                .expect("driver entry start")
                        );
                        crate::launch::publish_reservation(&reservation, &saved)
                            .expect("record driver entry before client");
                        if scenario == ServiceCase::Attempt {
                            driver
                                .stdin
                                .take()
                                .expect("driver start input")
                                .write_all(b"G")
                                .expect("start driver client");
                        } else {
                            let mut foreign = Command::new(
                                std::env::current_exe().expect("outside client image"),
                            )
                            .args(["--exact", selector, "--nocapture", "--test-threads=1"])
                            .env("CLAUDE_FIXTURE_CLIENT_RUN", &run_dir)
                            .env("CLAUDE_FIXTURE_ENTRY_NAME", selector)
                            .env("CLAUDE_FIXTURE_CLIENT_ENTRY", "1")
                            .env("CLAUDE_FIXTURE_OUTSIDE_SESSION", "1")
                            .env("SUPERLOOP_CLIENT_ROOT_DEV", root_meta.dev().to_string())
                            .env("SUPERLOOP_CLIENT_ROOT_INO", root_meta.ino().to_string())
                            .env("SUPERLOOP_CLIENT_SOCKET_NAME", ".container-R.sock")
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .spawn()
                            .expect("outside driver-session client");
                            foreign
                                .stdin
                                .take()
                                .expect("foreign prompt")
                                .write_all(crate::FIRST_DISPATCH_PROMPT.as_bytes())
                                .expect("foreign prompt input");
                            let output = foreign.wait_with_output().expect("foreign client exit");
                            assert!(
                                output.status.success(),
                                "foreign client: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                            result = String::from_utf8_lossy(&output.stdout).into_owned();
                        }
                        drop(driver.stdin.take());
                        let output = driver.wait_with_output().expect("driver entry exit");
                        assert!(
                            output.status.success(),
                            "driver entry: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        result.push_str(&String::from_utf8_lossy(&output.stdout));
                        nix::mount::umount(alias_socket).expect("unmount client socket alias");
                        fs::remove_file(alias_socket).expect("remove client socket mountpoint");
                    }
                    drop(input);
                    result
                }))
            };
            let outcome = crate::container_helper::fixture_serve_admitted_at(
                owner,
                &runs.join("R"),
                admission,
            );
            service_done.store(true, std::sync::atomic::Ordering::Release);
            if let Some(release) = release {
                let result = release.join().expect("readiness release");
                assert_ne!(result, "service returned before readiness", "{outcome:?}");
                if scenario == ServiceCase::OutsideSession {
                    let error = outcome.expect_err("outside-session peer refuses");
                    assert_eq!(error.kind, "helper-peer", "{error:?}");
                    assert_eq!(
                        error.detail,
                        "request is outside the launched driver session"
                    );
                    assert!(result.contains("CLIENT-REFUSAL="), "{result}");
                } else {
                    outcome.expect("service ends after launcher exit");
                }
                if scenario == ServiceCase::Attempt {
                    assert!(result.contains("CLIENT-STATUS=7"), "{result}");
                    assert!(result.contains("fixture-attempt"), "{result}");
                    let evidence: Value = serde_json::from_slice(
                        &fs::read(runs.join("R/container-attempt-1.status.json"))
                            .expect("service attempt status"),
                    )
                    .expect("attempt status JSON");
                    assert_eq!(evidence["status"], 7, "{evidence}");
                    assert_eq!(evidence["bounded"], true, "{evidence}");
                    assert_eq!(evidence["attempt"], 1, "{evidence}");
                }
            } else {
                let error = outcome.expect_err("due owner source refuses at service entry");
                assert_eq!(error.kind, "credential-read-due", "{error:?}");
                assert_eq!(
                    fs::read(&reservation).expect("reservation after refusal"),
                    before
                );
                assert_eq!(fs::read(&worker_file).ok(), prior_worker);
                assert!(
                    !evidence_path.exists(),
                    "no periodic thread starts after refusal"
                );
            }
            drop(launcher.stdin.take());
            assert!(launcher.wait().expect("launcher exit").code().is_some());
            assert!(!request_socket.exists(), "request socket removed");
            assert!(!control_socket.exists(), "control socket removed");
            // A joined thread can remain listed until the kernel finishes its
            // teardown. The fixture watchdog bounds this event wait, so a
            // leaked service thread remains a named fixture failure.
            let mut pending_reported = false;
            loop {
                let observed = fs::read_dir("/proc/self/task")
                    .expect("service caller threads after return")
                    .count();
                if observed == threads_before {
                    break;
                }
                if !pending_reported {
                    writeln!(
                        std::io::stderr().lock(),
                        "service thread count pending: baseline={threads_before} observed={observed}"
                    )
                    .expect("thread count diagnostic");
                    pending_reported = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(client_runs);
            assert_eq!(
                fs::read(&source_path).expect("owner source after service"),
                source_bytes
            );
            let after = fs::metadata(&source_path).expect("owner source after metadata");
            assert_eq!(
                after.ino(),
                source_meta.ino(),
                "owner source inode is unchanged"
            );
            assert_eq!(
                after.modified().expect("mtime"),
                source_meta.modified().expect("mtime")
            );
            assert!(
                !home.join(".fixture-refresh-sentinel").exists(),
                "read-mode service never runs the owner program"
            );
            if scenario != ServiceCase::Due {
                let (metadata, projected_bytes) = projected_rx
                    .recv()
                    .expect("publication observed before launcher exit");
                let saved: Value =
                    serde_json::from_slice(&fs::read(&reservation).expect("published reservation"))
                        .expect("reservation JSON");
                let receipt = saved["rounds"][0]["credential_publication"]
                    .as_object()
                    .expect("round receipt");
                assert_eq!(receipt.len(), 2, "report reader accepts exactly two keys");
                assert_eq!(receipt["source_inode"], source_meta.ino());
                assert!(receipt["published_unix_ns"].as_u64().is_some());
                assert_eq!(
                    (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
                    (3000, 3000, 0o600)
                );
                assert!(!worker_file.exists(), "service withdrew worker projection");
                let projected: Value =
                    serde_json::from_slice(&projected_bytes).expect("worker JSON");
                assert_eq!(projected.as_object().expect("worker object").len(), 1);
                let fields = projected["claudeAiOauth"]
                    .as_object()
                    .expect("OAuth fields");
                assert_eq!(fields.len(), 6);
                for field in [
                    "accessToken",
                    "expiresAt",
                    "scopes",
                    "subscriptionType",
                    "subscriptionTypeSource",
                    "rateLimitTier",
                ] {
                    assert_eq!(fields.get(field), document["claudeAiOauth"].get(field));
                }
                let evidence: Value = serde_json::from_slice(
                    &fs::read(&evidence_path).expect("first periodic evidence"),
                )
                .expect("evidence JSON");
                assert_eq!(evidence["state"], "current", "{evidence}");
                assert_eq!(evidence["backend"], "claude", "{evidence}");
                if scenario == ServiceCase::NoClient {
                    let mut next = saved;
                    next["active_round"] = json!("review");
                    next["rounds"]
                        .as_array_mut()
                        .expect("rounds")
                        .push(json!({"step":"review"}));
                    crate::container_helper::publish_round_credential_admitted(
                        owner, "alpha", &mut next, admission,
                    )
                    .expect("next round republishes after withdrawal");
                    assert!(worker_file.exists(), "next round projection is present");
                }
            }
        },
    );
}

/// # Panics
/// Panics if no-client service fails to publish its read-mode round or leave clean resources.
/// ´test:unit:claude-fixture-service-round-publishes-read-mode´
#[test]
fn claude_fixture_service_round_publishes_read_mode() {
    if enter(
        "claude_fixture_service_round_publishes_read_mode",
        |enclosing| {
            service_round_body(enclosing, ServiceCase::NoClient);
        },
    ) {
        return;
    }
    let mut host = launch_with_builder("claude_fixture_service_round_publishes_read_mode", true);
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

/// # Panics
/// Panics if a due read leaves an altered reservation, worker file or service resources.
/// ´test:unit:claude-fixture-service-round-due-refuses-without-publication´
#[test]
fn claude_fixture_service_round_due_refuses_without_publication() {
    if enter(
        "claude_fixture_service_round_due_refuses_without_publication",
        |enclosing| {
            service_round_body(enclosing, ServiceCase::Due);
        },
    ) {
        return;
    }
    let mut host = launch_with_builder(
        "claude_fixture_service_round_due_refuses_without_publication",
        true,
    );
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

/// # Panics
/// Panics if the loop-uid production client cannot receive the bounded attempt result.
/// ´test:unit:claude-fixture-service-attempt-admits-driver-client´
#[test]
fn claude_fixture_service_attempt_admits_driver_client() {
    if service_client_or_driver_entry() {
        return;
    }
    if enter(
        "claude_fixture_service_attempt_admits_driver_client",
        |enclosing| service_round_body(enclosing, ServiceCase::Attempt),
    ) {
        return;
    }
    let mut host = launch_with_builder("claude_fixture_service_attempt_admits_driver_client", true);
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

/// # Panics
/// Panics if a loop-uid client outside the recorded driver session is admitted.
/// ´test:unit:claude-fixture-service-attempt-refuses-outside-session´
#[test]
fn claude_fixture_service_attempt_refuses_outside_session() {
    if service_client_or_driver_entry() {
        return;
    }
    if enter(
        "claude_fixture_service_attempt_refuses_outside_session",
        |enclosing| service_round_body(enclosing, ServiceCase::OutsideSession),
    ) {
        return;
    }
    let mut host = launch_with_builder(
        "claude_fixture_service_attempt_refuses_outside_session",
        true,
    );
    let path = host.root.as_ref().expect("enclosure").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

/// # Panics
/// Panics if private procfs disagrees with the namespace or loses the host identity handoff.
/// ´test:unit:claude-fixture-service-procfs-keeps-host-handoff´
#[test]
fn claude_fixture_service_procfs_keeps_host_handoff() {
    if enter(
        "claude_fixture_service_procfs_keeps_host_handoff",
        service_procfs_body,
    ) {
        return;
    }
    let mut host = launch("claude_fixture_service_procfs_keeps_host_handoff");
    let path = host.root.as_ref().expect("E").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists());
}

fn round_body(enclosing: &Path) {
    transaction_body(
        enclosing,
        |_, owner, _, worker, record, admission, document| {
            round_contract(owner, worker, record, admission, document);
        },
    );
}

/// # Panics
/// Panics if a mapped round bypasses the closed cutover gate or changes its prior worker file.
/// ´test:unit:claude-fixture-cutover-refuses-at-round-entry´
#[test]
fn claude_fixture_cutover_refuses_at_round_entry() {
    if enter(
        "claude_fixture_cutover_refuses_at_round_entry",
        |enclosing| {
            transaction_body(enclosing, |_, owner, _, worker, record, admission, _| {
                let home = claude_sign_in_dir(owner, "alpha");
                let marker = home.join(".boxed-refresh-mode");
                fs::write(&marker, b"refresh\n").expect("cutover request");
                fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
                    .expect("marker mode");
                assert_round_refusal_preserves_worker(
                    owner,
                    worker,
                    record,
                    admission,
                    "credential-cutover-gate",
                );
            });
        },
    ) {
        return;
    }
    let mut host = launch("claude_fixture_cutover_refuses_at_round_entry");
    finish(&mut host, true);
    host.cleanup();
}

/// # Panics
/// Panics if due authority reaches a mapped worker or invokes the owner program.
/// ´test:unit:claude-fixture-due-refuses-at-round-entry´
#[test]
fn claude_fixture_due_refuses_at_round_entry() {
    if enter("claude_fixture_due_refuses_at_round_entry", |enclosing| {
        transaction_body(enclosing, |_, owner, _, worker, record, admission, _| {
            let home = claude_sign_in_dir(owner, "alpha");
            let expiry = now_seconds().expect("clock") + 300;
            let source = home.join(".credentials.json");
            fs::write(&source, claude_document(expiry * 1000).to_string()).expect("due source");
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
            assert_round_refusal_preserves_worker(
                owner,
                worker,
                record,
                admission,
                "credential-read-due",
            );
        });
    }) {
        return;
    }
    let mut host = launch("claude_fixture_due_refuses_at_round_entry");
    finish(&mut host, true);
    host.cleanup();
}

fn assert_round_refusal_preserves_worker(
    owner: &Path,
    worker: &Path,
    record: &mut Value,
    admission: &crate::runtime_admission::RuntimeAdmission,
    expected: &str,
) {
    let home = claude_sign_in_dir(owner, "alpha");
    fs::write(home.join(".fixture-refresh-sentinel-arm"), b"armed").expect("fixture program arm");
    let path = worker.join(".claude/.credentials.json");
    fs::write(&path, b"prior synthetic projection").expect("prior worker file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("prior mode");
    nix::unistd::chown(&path, Some(Uid::from_raw(3000)), Some(Gid::from_raw(3000)))
        .expect("prior worker ownership");
    let prior = fs::metadata(&path).expect("prior inode").ino();
    let before = record.clone();
    let error = crate::container_helper::publish_round_credential_admitted(
        owner, "alpha", record, admission,
    )
    .expect_err("round must refuse");
    assert_eq!(error.kind, expected, "{error:?}");
    assert_eq!(*record, before, "reservation remains unchanged");
    assert_eq!(
        fs::read(&path).expect("prior bytes"),
        b"prior synthetic projection"
    );
    assert_eq!(fs::metadata(&path).expect("prior metadata").ino(), prior);
    assert!(
        !home.join(".fixture-refresh-sentinel").exists(),
        "owner program entered"
    );
}

fn transaction_body(
    enclosing: &Path,
    action: impl FnOnce(
        &FixtureRoot,
        &Path,
        &Path,
        &Path,
        &mut Value,
        &crate::runtime_admission::RuntimeAdmission,
        &Value,
    ),
) {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let _endpoint = fixture_service_endpoint("http://127.0.0.1:1/unused".into());
    let (root, mut anchors) = moved_root(enclosing);
    let owner = root.path().join("owner");
    let runs = root.path().join("runs");
    census_settings(&owner, &runs);
    let _configuration = crate::container_entry::configuration(
        &owner,
        "alpha",
        "container-helper",
        anchors.pop().expect("configuration"),
    )
    .expect("moved configuration");
    let (runtime, mut programs) =
        crate::container_entry::take_support_programs(&mut anchors, BoxBackend::Claude)
            .expect("program roles");
    if let Some(program) = std::env::var_os("CLAUDE_FIXTURE_BUILDER") {
        programs.insert(PathBuf::from(program), Arc::new(runtime));
    }
    let _home =
        crate::home::activate_private_launch(&owner, &anchors[0], &runs, &anchors[1], None, 0)
            .expect("moved anchors");
    let _programs = crate::container_entry::activate_program_map("container-helper", programs);
    let worker = mapped_storage(&root);
    let mut digest = String::new();
    for byte in Sha256::digest(fs::read("/usr/bin/true").expect("public program")) {
        write!(&mut digest, "{byte:02x}").expect("digest");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    // The mapped transaction exercises publication and custody, not refresh.
    // Keep its source outside the default reader's 600-second due margin.
    let document = claude_document((now + 900) * 1000);
    fixture_claude(&owner, &document);
    let install = owner.join(".config/loops/alpha/install-generation.json");
    fs::write(
        &install,
        json!({"schema":1,"phase":"complete", "claude_sha256":digest,
            "image_digest":format!("sha256:{}", "b".repeat(64)),
            "claude_image_program":"/opt/claude/bin/claude",
            "claude_template_dir":format!("/fixture/runner-templates/claude/{}", "b".repeat(64))})
        .to_string(),
    )
    .expect("install");
    fs::set_permissions(&install, fs::Permissions::from_mode(0o600)).expect("install mode");
    let declaration = || Declaration {
        owner_home: owner.clone(),
        runs: runs.clone(),
        plan_home: worker.clone(),
        loop_name: "alpha".into(),
        run: "R".into(),
        worker_uid: 3000,
        backend: BoxBackend::Claude,
        stand_in: "/usr/bin/true".into(),
        digest: digest.clone(),
    };
    let mut foreign = declaration();
    foreign.owner_home =
        PathBuf::from(std::env::var_os("CLAUDE_TRANSACTION_ACCOUNT").expect("host account"));
    let error = fixture::construct(&root, foreign)
        .err()
        .expect("real home outside root");
    assert_eq!(
        error.detail,
        format!("{}: refuses outside root", fixture::SENTINEL)
    );
    let admission = fixture::construct(&root, declaration()).expect("fixture admission");
    let (pid, start) = claude_host_identity();
    assert!(matches!(
        crate::container_helper::process_presence(pid, start),
        crate::container_helper::ProcessPresence::Present
    ));
    for path in [runs.join("R"), runs.join(".launch-R")] {
        fs::create_dir(&path).expect("driver directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("driver mode");
    }
    let mut record = staged_record(&owner, &runs, pid, start);
    action(
        &root,
        &owner,
        &runs,
        &worker,
        &mut record,
        &admission,
        &document,
    );
    drop(admission);
    let removed = root.path().to_path_buf();
    drop(root);
    assert!(
        !removed.exists(),
        "factory root is really removed after the transaction"
    );
}

fn staged_record(owner: &Path, runs: &Path, pid: u32, start: u64) -> Value {
    let mut settings = crate::tests::fixture_settings(Path::new("/usr/bin/true"));
    settings.runs_root = Some(runs.to_path_buf());
    settings.backend_argv =
        std::collections::BTreeMap::from([("claude".into(), vec!["/fixture/claude".into()])]);
    let row = json!({"name":"alpha", "uid":64000, "runs_root":runs});
    let mut plan = crate::plan::Plan::build_with_door(
        owner,
        "alpha",
        "R",
        &settings,
        &row,
        loop_home::registry::WorkerBlock {
            base: 3000,
            count: 4,
        },
        (0, 0),
        false,
        Some(BoxBackend::Claude),
    )
    .expect("synthetic protected plan");
    plan.document["box_gate"] = crate::plan::box_gate(&plan.document).expect("recomputed gate");
    json!({"loop":"alpha", "run":"R", "phase":"started", "worker_uid":3000,
        "helper_pid":pid, "helper_start":start, "active_round":"start", "rounds":[{"step":"start"}],
        "plan":plan.document})
}

fn round_contract(
    owner: &Path,
    worker: &Path,
    record: &mut Value,
    admission: &crate::runtime_admission::RuntimeAdmission,
    document: &Value,
) {
    {
        let error = crate::container_helper::publish_round_credential_admitted(
            owner, "alpha", record, &Gate,
        )
        .expect_err("public refusal before");
        assert_eq!((error.status, error.kind), (2, "backend-unavailable"));
    }
    let path = worker.join(".claude/.credentials.json");
    fs::write(&path, b"prior synthetic projection").expect("prior worker file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("prior mode");
    nix::unistd::chown(&path, Some(Uid::from_raw(3000)), Some(Gid::from_raw(3000)))
        .expect("prior worker ownership");
    let prior = fs::metadata(&path).expect("prior identity");
    crate::container_helper::publish_round_credential_admitted(owner, "alpha", record, admission)
        .expect("admitted round bound program pin");
    assert!(record["rounds"][0]["credential_publication"].is_object());
    assert_eq!(
        record["rounds"][0]["credential_publication"]
            .as_object()
            .expect("round receipt")
            .len(),
        2,
        "launch report accepts only the two receipt keys"
    );
    let path = worker.join(".claude/.credentials.json");
    let metadata = fs::metadata(&path).expect("published worker");
    assert_ne!(metadata.ino(), prior.ino(), "publication replaces the leaf");
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
        (3000, 3000, 0o600)
    );
    let bytes = fs::read(&path).expect("synthetic projection");
    let projected: Value = serde_json::from_slice(&bytes).expect("projection shape");
    assert_eq!(projected.as_object().expect("object").len(), 1);
    let fields = projected["claudeAiOauth"]
        .as_object()
        .expect("OAuth projection");
    assert_eq!(fields.len(), 6);
    for field in [
        "accessToken",
        "expiresAt",
        "scopes",
        "subscriptionType",
        "subscriptionTypeSource",
        "rateLimitTier",
    ] {
        assert_eq!(fields.get(field), document["claudeAiOauth"].get(field));
    }
    let source = ClaudeSource::parse(document).expect("synthetic source");
    assert_eq!(bytes, source.worker_file());
    let error =
        crate::container_helper::publish_round_credential_admitted(owner, "alpha", record, &Gate)
            .expect_err("public refusal after");
    assert_eq!((error.status, error.kind), (2, "backend-unavailable"));
    assert_eq!(fs::read(path).expect("retained bytes"), bytes);
}

fn cleanup_body(enclosing: &Path, panic: bool) {
    let (root, _anchors) = moved_root(enclosing);
    let _worker = mapped_storage(&root);
    fs::write(enclosing.join("ready"), b"ready").expect("ready");
    assert!(!panic, "injected child unwind");
    std::thread::sleep(Duration::from_secs(120));
    panic!("case exceeded absolute deadline");
}

/// # Panics
/// Panics if killing the child leaves mapped storage beneath the held enclosure.
/// ´test:unit:claude-fixture-cleanup-child-killed´
#[test]
fn claude_fixture_cleanup_child_killed() {
    if enter("claude_fixture_cleanup_child_killed", |e| {
        cleanup_body(e, false);
    }) {
        return;
    }
    let mut host = launch("claude_fixture_cleanup_child_killed");
    let path = host.root.as_ref().expect("E").path().to_owned();
    wait_event(&mut host, "ready");
    host.cleanup();
    assert!(!path.exists());
}
/// # Panics
/// Panics if host unwind leaves mapped storage or a namespace descendant.
/// ´test:unit:claude-fixture-cleanup-host-unwind´
#[test]
fn claude_fixture_cleanup_host_unwind() {
    if enter("claude_fixture_cleanup_host_unwind", |e| {
        cleanup_body(e, false);
    }) {
        return;
    }
    let mut host = launch("claude_fixture_cleanup_host_unwind");
    let path = host.root.as_ref().expect("E").path().to_owned();
    wait_event(&mut host, "ready");
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = host;
        panic!("injected host unwind");
    }))
    .expect_err("host unwind");
    assert_eq!(error.downcast_ref::<&str>(), Some(&"injected host unwind"));
    assert!(!path.exists());
}
/// # Panics
/// Panics if child unwind leaves mapped storage beneath the enclosure.
/// ´test:unit:claude-fixture-cleanup-child-unwind´
#[test]
fn claude_fixture_cleanup_child_unwind() {
    if enter("claude_fixture_cleanup_child_unwind", |e| {
        cleanup_body(e, true);
    }) {
        return;
    }
    let mut host = launch("claude_fixture_cleanup_child_unwind");
    let path = host.root.as_ref().expect("E").path().to_owned();
    wait_event(&mut host, "ready");
    finish(&mut host, false);
    assert!(
        fs::read_dir(&path)
            .expect("E after child unwind")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("lane-claude-admission-"))
    );
    host.cleanup();
    assert!(!path.exists());
}
/// # Panics
/// Panics if cleanup follows a replacement enclosing path instead of its held identity.
/// ´test:unit:claude-fixture-cleanup-replaced-enclosure´
#[test]
fn claude_fixture_cleanup_replaced_enclosure() {
    if enter("claude_fixture_cleanup_replaced_enclosure", |e| {
        cleanup_body(e, false);
    }) {
        return;
    }
    let mut host = launch("claude_fixture_cleanup_replaced_enclosure");
    wait_event(&mut host, "ready");
    assert!(host.child.as_mut().expect("child").stop());
    let path = host.root.as_ref().expect("E").path().to_owned();
    let displaced = path.with_extension("displaced");
    fs::rename(&path, &displaced).expect("move E");
    fs::create_dir(&path).expect("replacement E");
    fs::write(path.join("sentinel"), b"outside retained E").expect("sentinel");
    host.cleanup();
    assert_eq!(
        fs::read(path.join("sentinel")).expect("sentinel retained"),
        b"outside retained E"
    );
    assert_eq!(fs::read_dir(&displaced).expect("held E").count(), 0);
    fs::remove_dir(&displaced).expect("empty displaced E");
    fs::remove_file(path.join("sentinel")).expect("own sentinel");
    fs::remove_dir(path).expect("own replacement E");
}

/// # Panics
/// Panics if a failed mapped cleanup invokes pathname-recursive removal during unwind.
/// ´test:unit:claude-fixture-cleanup-failure-keeps-replacement´
#[test]
fn claude_fixture_cleanup_failure_keeps_replacement() {
    let parent = tempfile::tempdir().expect("test-owned parent");
    let root = tempfile::tempdir_in(parent.path()).expect("enclosure");
    let path = root.path().to_path_buf();
    let metadata = fs::metadata(&path).expect("original identity");
    let displaced = parent.path().join("retained-enclosure");
    fs::rename(&path, &displaced).expect("move enclosure");
    fs::create_dir(&path).expect("replacement");
    let sentinel = path.join("sentinel");
    fs::write(&sentinel, b"outside held enclosure").expect("sentinel");
    let inode = fs::metadata(&sentinel).expect("sentinel identity").ino();
    let invalid = parent.path().join("not-a-directory");
    fs::write(&invalid, b"synthetic invalid descriptor").expect("force mapped cleanup refusal");
    let host = Host {
        root: Some(root),
        held: fs::File::open(invalid).expect("non-directory descriptor"),
        identity: (metadata.dev(), metadata.ino()),
        sources: None,
        child: None,
    };
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(host)))
        .expect_err("mapped cleanup failure");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .expect("panic text");
    assert!(
        message.starts_with("whole enclosing mapped cleanup"),
        "{message}"
    );
    assert_eq!(
        fs::read(&sentinel).expect("sentinel retained"),
        b"outside held enclosure"
    );
    assert_eq!(fs::metadata(&sentinel).expect("same inode").ino(), inode);
    assert!(
        displaced.is_dir(),
        "cleanup failure retains the original enclosure"
    );
}

struct PeriodicThread {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    done: Option<std::sync::mpsc::Receiver<std::thread::Result<Result<(), LaneError>>>>,
    release: Option<std::sync::mpsc::Sender<()>>,
}
impl PeriodicThread {
    fn observe(
        cancelled: Arc<std::sync::atomic::AtomicBool>,
        thread: std::thread::JoinHandle<Result<(), LaneError>>,
    ) -> Self {
        let (send, done) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _received = send.send(thread.join());
        });
        Self {
            cancelled,
            done: Some(done),
            release: None,
        }
    }
    #[allow(clippy::exit)]
    fn finish(&mut self) -> Result<(), LaneError> {
        drop(self.release.take());
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        let result = self
            .done
            .take()
            .expect("one authority join")
            .recv_timeout(Duration::from_secs(30));
        let Ok(result) = result else {
            // End this fixture's PID namespace before the root can drop under a live thread.
            let _reported = writeln!(
                std::io::stderr(),
                "periodic authority join event failed: {result:?}"
            );
            std::process::exit(125);
        };
        result.unwrap_or_else(|_| {
            Err(LaneError::operation(
                "fixture-thread",
                "authority thread panicked",
            ))
        })
    }
}
impl Drop for PeriodicThread {
    fn drop(&mut self) {
        if self.done.is_some() {
            let _result = self.finish();
        }
    }
}

fn periodic_case(name: &str, body: fn(&Path)) {
    if enter(name, body) {
        return;
    }
    let mut host = launch(name);
    let path = host.root.as_ref().expect("E").path().to_owned();
    finish(&mut host, true);
    host.cleanup();
    assert!(!path.exists(), "periodic enclosure removed");
}

/// # Panics
/// Panics if the production spawner fails to publish the live fixture's projection.
/// ´test:unit:claude-fixture-periodic-publication´
#[test]
fn claude_fixture_periodic_publication() {
    periodic_case("claude_fixture_periodic_publication", |enclosing| {
        transaction_body(
            enclosing,
            |root, owner, runs, worker, record, admission, source| {
                periodic_success(root, owner, runs, worker, record, admission, source);
            },
        );
    });
}

/// # Panics
/// Panics if the periodic production entry bypasses the closed Claude cutover gate.
/// ´test:unit:claude-fixture-periodic-cutover-refuses-before-publication´
#[test]
fn claude_fixture_periodic_cutover_refuses_before_publication() {
    periodic_case(
        "claude_fixture_periodic_cutover_refuses_before_publication",
        |enclosing| {
            transaction_body(enclosing, |_, owner, runs, worker, record, admission, _| {
                periodic_stage(owner, runs, record);
                let home = claude_sign_in_dir(owner, "alpha");
                let marker = home.join(".boxed-refresh-mode");
                fs::write(&marker, b"refresh\n").expect("cutover request");
                fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
                    .expect("marker mode");
                fs::write(home.join(".fixture-refresh-sentinel-arm"), b"armed")
                    .expect("sentinel arm");
                let worker_file = worker.join(".claude/.credentials.json");
                fs::write(&worker_file, b"prior worker authority").expect("prior file");
                fs::set_permissions(&worker_file, fs::Permissions::from_mode(0o600))
                    .expect("prior mode");
                nix::unistd::chown(
                    &worker_file,
                    Some(Uid::from_raw(3000)),
                    Some(Gid::from_raw(3000)),
                )
                .expect("prior owner");
                let prior = fs::metadata(&worker_file).expect("prior inode").ino();
                let reservation = fs::read(crate::launch::reservation_path(runs, "R"))
                    .expect("prior reservation");
                let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let thread = crate::container_helper::spawn_credential_authority_admitted(
                    owner.to_path_buf(),
                    "alpha".into(),
                    runs.to_path_buf(),
                    runs.join("R"),
                    BoxBackend::Claude,
                    Arc::clone(&cancelled),
                    admission,
                )
                .expect("production periodic spawner");
                let mut thread = PeriodicThread::observe(cancelled, thread);
                let evidence = runs.join(".launch-R/credential-refresh.json");
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !evidence.exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "periodic evidence event"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                thread.finish().expect("clean authority cancellation");
                let value: Value = serde_json::from_slice(&fs::read(evidence).expect("evidence"))
                    .expect("evidence JSON");
                assert_eq!(value["state"], "refused", "{value}");
                assert_eq!(value["kind"], "credential-cutover-gate", "{value}");
                assert_eq!(
                    fs::read(&worker_file).expect("prior bytes"),
                    b"prior worker authority"
                );
                assert_eq!(
                    fs::metadata(&worker_file).expect("prior inode").ino(),
                    prior
                );
                assert_eq!(
                    fs::read(crate::launch::reservation_path(runs, "R")).expect("reservation"),
                    reservation
                );
                assert!(!home.join(".fixture-refresh-sentinel").exists());
            });
        },
    );
}

/// # Panics
/// Panics if an evidence destination escaping the fixture permits a second envelope.
/// ´test:unit:claude-fixture-periodic-evidence-escape´
#[test]
fn claude_fixture_periodic_evidence_escape() {
    periodic_case("claude_fixture_periodic_evidence_escape", |enclosing| {
        transaction_body(
            enclosing,
            |root, owner, runs, worker, record, admission, source| {
                periodic_scope_loss(
                    (root, owner, runs, worker),
                    record,
                    admission,
                    source,
                    false,
                );
            },
        );
    });
}

/// # Panics
/// Panics if a replaced configuration permits refused evidence after scope is lost.
/// ´test:unit:claude-fixture-periodic-configuration-replacement´
#[test]
fn claude_fixture_periodic_configuration_replacement() {
    periodic_case(
        "claude_fixture_periodic_configuration_replacement",
        |enclosing| {
            transaction_body(
                enclosing,
                |root, owner, runs, worker, record, admission, source| {
                    periodic_scope_loss(
                        (root, owner, runs, worker),
                        record,
                        admission,
                        source,
                        true,
                    );
                },
            );
        },
    );
}

fn periodic_stage(owner: &Path, runs: &Path, record: &mut Value) {
    let error =
        crate::container_helper::publish_round_credential_admitted(owner, "alpha", record, &Gate)
            .expect_err("public refusal before periodic transaction");
    assert_eq!((error.status, error.kind), (2, "backend-unavailable"));
    record["schema"] = json!(1);
    crate::launch::publish_reservation(&crate::launch::reservation_path(runs, "R"), record)
        .expect("live started reservation");
}

fn periodic_leaf(worker: &Path, source: &Value, prior: u64) -> u64 {
    let path = worker.join(".claude/.credentials.json");
    let metadata = fs::metadata(&path).expect("periodic worker leaf");
    assert_ne!(
        metadata.ino(),
        prior,
        "periodic publication replaces the leaf"
    );
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
        (3000, 3000, 0o600)
    );
    let bytes = fs::read(path).expect("periodic projection");
    let projected: Value = serde_json::from_slice(&bytes).expect("projection shape");
    assert_eq!(projected.as_object().expect("object").len(), 1);
    assert_eq!(
        projected["claudeAiOauth"].as_object().expect("OAuth").len(),
        6
    );
    assert_eq!(
        bytes,
        ClaudeSource::parse(source).expect("source").worker_file()
    );
    metadata.ino()
}

fn periodic_prior(worker: &Path) -> u64 {
    let path = worker.join(".claude/.credentials.json");
    fs::write(&path, b"prior synthetic projection").expect("prior leaf");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("prior mode");
    nix::unistd::chown(&path, Some(Uid::from_raw(3000)), Some(Gid::from_raw(3000)))
        .expect("prior ownership");
    fs::metadata(path).expect("prior inode").ino()
}

fn periodic_evidence(
    owner: &Path,
    runs: &Path,
    admission: &crate::runtime_admission::RuntimeAdmission,
    state: &str,
) -> (Vec<u8>, u64) {
    let path = runs.join(".launch-R/credential-refresh.json");
    let bytes = fs::read(&path).expect("actual periodic evidence");
    let value: Value = serde_json::from_slice(&bytes).expect("evidence JSON");
    assert_eq!(value["state"], state, "first periodic evidence: {value}");
    let binding = admission
        .round_binding(owner, "alpha", &owner.join(".cache/tmp/lane-alpha-R"), 3000)
        .expect("scoped evidence binding");
    assert_eq!(
        value["provider"]["required_sha256"],
        binding.required_sha256(),
        "published evidence carries the fixture binding"
    );
    validate_evidence(&value, binding).expect("actual bytes accepted by bound validator");
    let held = crate::home::pin_parent(runs, 0).expect("held runs for production reader");
    let error = read_evidence(&held, "R", 0).expect_err("production reader refuses fixture digest");
    evidence_refusal(&error);
    let error = crate::launch::census::run(owner, "alpha")
        .expect_err("production census refuses fixture digest");
    evidence_refusal(&error);
    (bytes, fs::metadata(path).expect("evidence inode").ino())
}

fn evidence_refusal(error: &LaneError) {
    assert_eq!(
        (error.status, error.kind),
        (2, "credential-evidence"),
        "{error:?}"
    );
    assert_eq!(error.detail, "credential evidence envelope is invalid");
}

fn census_settings(owner: &Path, runs: &Path) {
    let config = owner.join(".config/loops/alpha");
    let settings = format!(
        concat!(
            "runs_root = {:?}\nentry_bin = '/usr/bin/true'\ndriver_argv = ['/usr/bin/true']\n",
            "image_digest = 'sha256:{}'\ntemplate_dir = {:?}\nsocket_dir = {:?}\n",
            "resources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n"
        ),
        runs,
        "a".repeat(64),
        owner.join("template"),
        owner.join("sockets")
    );
    let registry = format!(
        concat!(
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\n",
            "loops=[{{name='alpha',uid=64000,launch='dev/alpha',runs_root={:?}}}]\n"
        ),
        runs
    );
    for (path, text) in [
        (config.join("workers.toml"), settings),
        (
            config.parent().expect("loops").join("registry.toml"),
            registry,
        ),
    ] {
        fs::write(&path, text).expect("synthetic census inputs");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("census mode");
    }
}

fn periodic_success(
    root: &FixtureRoot,
    owner: &Path,
    runs: &Path,
    worker: &Path,
    record: &mut Value,
    admission: &crate::runtime_admission::RuntimeAdmission,
    source: &Value,
) {
    periodic_first(
        (root, owner, runs, worker),
        record,
        admission,
        source,
        false,
    );
}

fn periodic_first(
    paths: (&FixtureRoot, &Path, &Path, &Path),
    record: &mut Value,
    admission: &crate::runtime_admission::RuntimeAdmission,
    source: &Value,
    dead: bool,
) {
    let (root, owner, runs, worker) = paths;
    if dead {
        record["helper_pid"] = json!(crate::dead_pid::DEAD_LOCK_PID);
    }
    periodic_stage(owner, runs, record);
    let prior = periodic_prior(worker);
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread = crate::container_helper::spawn_credential_authority_admitted(
        owner.to_path_buf(),
        "alpha".into(),
        runs.to_path_buf(),
        runs.join("R"),
        BoxBackend::Claude,
        Arc::clone(&cancelled),
        admission,
    )
    .expect("production spawner with uncancelled fixture admission");
    let mut thread = PeriodicThread::observe(cancelled, thread);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !runs.join(".launch-R/credential-refresh.json").exists() {
        assert!(
            !thread.cancelled.load(std::sync::atomic::Ordering::Acquire),
            "authority ended before first publication"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "first evidence publication event timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    thread
        .finish()
        .expect("clean authority cancellation and join");
    periodic_evidence(
        owner,
        runs,
        admission,
        if dead { "current" } else { "published" },
    );
    if dead {
        let leaf = worker.join(".claude/.credentials.json");
        assert_eq!(
            fs::read(&leaf).expect("dead helper prior bytes"),
            b"prior synthetic projection"
        );
        assert_eq!(
            fs::metadata(leaf).expect("dead helper prior inode").ino(),
            prior
        );
    } else {
        periodic_leaf(worker, source, prior);
    }
    let error =
        crate::container_helper::publish_round_credential_admitted(owner, "alpha", record, &Gate)
            .expect_err("public refusal after periodic transaction");
    assert_eq!((error.status, error.kind), (2, "backend-unavailable"));
    periodic_inventory(root, "success");
}

fn periodic_scope_loss(
    paths: (&FixtureRoot, &Path, &Path, &Path),
    record: &mut Value,
    admission: &crate::runtime_admission::RuntimeAdmission,
    source: &Value,
    configuration: bool,
) {
    let (root, owner, runs, worker) = paths;
    periodic_stage(owner, runs, record);
    let prior = periodic_prior(worker);
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (pass, observed) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let thread = crate::container_helper::fixture_authority_with_wait(
        (owner, runs, &runs.join("R")),
        Arc::clone(&cancelled),
        admission,
        crate::settings::BoxBackend::Claude,
        move |cancelled: &std::sync::atomic::AtomicBool| {
            pass.send(()).expect("pass-complete event");
            match resume.recv_timeout(Duration::from_secs(30)) {
                Ok(()) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                }
                Err(error) => panic!("pass-release event: {error}"),
            }
        },
    )
    .expect("event-driven fixture authority");
    let mut thread = PeriodicThread::observe(Arc::clone(&cancelled), thread);
    thread.release = Some(release);
    observed
        .recv_timeout(Duration::from_secs(30))
        .expect("first periodic pass event");
    assert!(
        !cancelled.load(std::sync::atomic::Ordering::Acquire),
        "first pass remains live"
    );
    let (evidence, inode) = periodic_evidence(owner, runs, admission, "published");
    let worker_inode = periodic_leaf(worker, source, prior);
    let retained = periodic_replace(root, owner, runs, source, configuration);
    thread
        .release
        .as_ref()
        .expect("release sender")
        .send(())
        .expect("release second periodic pass");
    scope_exit(&observed, &retained, &evidence);
    assert!(
        cancelled.load(std::sync::atomic::Ordering::Acquire),
        "in-loop refusal cancels service"
    );
    let error = thread.finish().expect_err("in-loop scope refusal");
    scope_result(
        (root, owner, runs, worker),
        record,
        source,
        configuration,
        (error, retained, evidence, inode, worker_inode),
    );
}

fn scope_exit(observed: &std::sync::mpsc::Receiver<()>, retained: &Path, evidence: &[u8]) {
    match observed.recv_timeout(Duration::from_secs(30)) {
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        Ok(()) => {
            assert_eq!(
                fs::read(retained.join("credential-refresh.json")).expect("retained evidence"),
                evidence,
                "scope loss retains evidence before any second envelope"
            );
            panic!("scope loss must end before a second pass-complete event");
        }
        Err(error) => panic!("scope-exit event: {error}"),
    }
}

fn scope_result(
    paths: (&FixtureRoot, &Path, &Path, &Path),
    record: &mut Value,
    source: &Value,
    configuration: bool,
    result: (LaneError, PathBuf, Vec<u8>, u64, u64),
) {
    let (root, owner, _runs, worker) = paths;
    let (error, retained, evidence, inode, worker_inode) = result;
    assert_eq!((error.status, error.kind), (2, "fixture-scope"));
    assert_eq!(
        error.detail,
        format!(
            "{}: refuses {}",
            fixture::SENTINEL,
            if configuration {
                "anchor identity"
            } else {
                "directory containment"
            }
        )
    );
    let path = retained.join("credential-refresh.json");
    assert_eq!(fs::read(&path).expect("retained evidence"), evidence);
    assert_eq!(
        fs::metadata(path).expect("retained evidence inode").ino(),
        inode
    );
    if configuration {
        assert_eq!(
            fs::metadata(worker.join(".claude/.credentials.json"))
                .expect("prior leaf")
                .ino(),
            worker_inode,
            "scope loss precedes worker publication"
        );
    } else {
        let mut next = source.clone();
        next["claudeAiOauth"]["accessToken"] = json!("C".repeat(108));
        periodic_leaf(worker, &next, worker_inode);
        let outside = root.path().parent().expect("E").join("outside");
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("outside sentinel"),
            b"outside root"
        );
        assert!(!outside.join("credential-refresh.json").exists());
    }
    let error =
        crate::container_helper::publish_round_credential_admitted(owner, "alpha", record, &Gate)
            .expect_err("public refusal after scope-loss transaction");
    assert_eq!((error.status, error.kind), (2, "backend-unavailable"));
    periodic_inventory(
        root,
        if configuration {
            "configuration"
        } else {
            "destination"
        },
    );
}

fn periodic_replace(
    root: &FixtureRoot,
    owner: &Path,
    runs: &Path,
    source: &Value,
    configuration: bool,
) -> PathBuf {
    let mut changed = source.clone();
    changed["claudeAiOauth"]["accessToken"] = json!("C".repeat(108));
    fixture_claude(owner, &changed);
    if configuration {
        let config = owner.join(".config/loops");
        fs::rename(&config, owner.join(".config/loops-retained")).expect("replace configuration");
        fs::create_dir(&config).expect("replacement configuration");
        fs::set_permissions(config, fs::Permissions::from_mode(0o700)).expect("configuration mode");
        runs.join(".launch-R")
    } else {
        let protected = runs.join(".launch-R");
        let retained = runs.join(".launch-R-retained");
        fs::rename(&protected, &retained).expect("retain prior evidence");
        let outside = root.path().parent().expect("E").join("outside");
        fs::create_dir(&outside).expect("outside target");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).expect("outside mode");
        fs::write(outside.join("sentinel"), b"outside root").expect("outside sentinel");
        std::os::unix::fs::symlink(&outside, protected).expect("escaping evidence destination");
        retained
    }
}

fn periodic_inventory(root: &FixtureRoot, variant: &str) {
    fn walk(path: &Path, base: &Path, entries: &mut Vec<String>) {
        for entry in fs::read_dir(path).expect("whole enclosure inventory") {
            let entry = entry.expect("entry");
            let metadata = fs::symlink_metadata(entry.path()).expect("entry kind");
            let kind = if metadata.is_symlink() {
                "link"
            } else if metadata.is_dir() {
                "dir"
            } else {
                "file"
            };
            entries.push(format!(
                "{kind} {}",
                entry.path().strip_prefix(base).expect("relative").display()
            ));
            if metadata.is_dir() {
                walk(&entry.path(), base, entries);
            }
        }
    }
    let enclosing = root.path().parent().expect("E");
    let name = root
        .path()
        .file_name()
        .expect("root name")
        .to_str()
        .expect("UTF8");
    let mut entries = Vec::new();
    walk(enclosing, enclosing, &mut entries);
    for entry in &mut entries {
        *entry = entry.replace(name, "fixture");
    }
    entries.sort();
    let mut expected: Vec<String> = [
        "dir fixture",
        "dir fixture/owner",
        "dir fixture/owner/.cache",
        "dir fixture/owner/.cache/tmp",
        "dir fixture/owner/.cache/tmp/lane-alpha-R",
        "dir fixture/owner/.cache/tmp/lane-alpha-R/.claude",
        "dir fixture/owner/.config",
        "dir fixture/owner/.config/loops",
        "dir fixture/owner/.config/loops/alpha",
        "dir fixture/owner/.config/loops/alpha/claude",
        "dir fixture/owner/.config/loops/alpha/lanes",
        "dir fixture/owner/.config/loops/alpha/lanes/codex",
        "dir fixture/runs",
        "dir fixture/runs/.launch-R",
        "dir fixture/runs/R",
        "dir live",
        "file fixture/owner/.cache/tmp/lane-alpha-R/.claude/.credentials.json",
        "file fixture/owner/.cache/tmp/lane-alpha-R/.claude/synthetic",
        "file fixture/owner/.config/loops/allocations.toml",
        "file fixture/owner/.config/loops/alpha/claude/.credentials.json",
        "file fixture/owner/.config/loops/alpha/claude/.refresh.lock",
        "file fixture/owner/.config/loops/alpha/install-generation.json",
        "file fixture/owner/.config/loops/alpha/workers.toml",
        "file fixture/owner/.config/loops/alpha/lanes/codex/auth.json",
        "file fixture/owner/.config/loops/registry.toml",
        "file fixture/runs/.launch-R/credential-refresh.json",
        "file fixture/runs/.reservation-R.json",
        "file namespace-init",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    match variant {
        "success" => {}
        "configuration" => {
            for entry in &mut expected {
                *entry = entry.replace("/owner/.config/loops", "/owner/.config/loops-retained");
            }
            expected.push("dir fixture/owner/.config/loops".into());
        }
        "destination" => {
            for entry in &mut expected {
                *entry = entry.replace("/runs/.launch-R", "/runs/.launch-R-retained");
            }
            expected.extend(
                [
                    "link fixture/runs/.launch-R",
                    "dir outside",
                    "file outside/sentinel",
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        _ => panic!("unknown inventory case"),
    }
    expected.sort();
    assert_eq!(
        entries, expected,
        "exact whole-enclosure inventory {variant}"
    );
}

/// # Panics
/// Panics if a dead host-view helper receives a periodic worker projection.
/// ´test:unit:claude-fixture-periodic-dead-helper´
#[test]
fn claude_fixture_periodic_dead_helper() {
    periodic_case("claude_fixture_periodic_dead_helper", |enclosing| {
        transaction_body(
            enclosing,
            |root, owner, runs, worker, record, admission, source| {
                periodic_first((root, owner, runs, worker), record, admission, source, true);
            },
        );
    });
}

/// # Panics
/// Panics if a source replaced after comparison is recursively removed during unwind.
/// ´test:unit:claude-fixture-move-rechecks-custody-before-drop´
#[test]
fn claude_fixture_move_rechecks_custody_before_drop() {
    if enter(
        "claude_fixture_move_rechecks_custody_before_drop",
        |enclosing| {
            let _root = moved_root_after(enclosing, || {
                fs::rename(enclosing.join("owner"), enclosing.join("owner-retained"))
                    .expect("replace after comparison");
                fs::create_dir(enclosing.join("owner")).expect("foreign directory");
                fs::write(enclosing.join("owner/sentinel"), b"not in received custody")
                    .expect("foreign sentinel");
            });
            panic!("injected child unwind after unchecked move");
        },
    ) {
        return;
    }
    let mut host = launch("claude_fixture_move_rechecks_custody_before_drop");
    let enclosing = host.root.as_ref().expect("E").path().to_path_buf();
    finish(&mut host, false);
    let factory = fs::read_dir(&enclosing)
        .expect("retained E")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with("lane-claude-admission-")
        })
        .expect("retained uncertain root");
    let sentinel = factory.join("owner/sentinel");
    let inode = fs::metadata(&sentinel).expect("retained sentinel").ino();
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.cleanup()))
        .expect_err("host also refuses unreceived source");
    let message = error.downcast_ref::<String>().expect("panic text");
    assert!(
        message.contains("moved directory identity differs"),
        "{message}"
    );
    assert_eq!(
        fs::read(&sentinel).expect("foreign bytes"),
        b"not in received custody"
    );
    assert_eq!(fs::metadata(&sentinel).expect("foreign inode").ino(), inode);
    // Dispose only this test's synthetic replacement; restore the host-created source.
    fs::remove_file(&sentinel).expect("own synthetic sentinel");
    fs::remove_dir(factory.join("owner")).expect("own empty replacement");
    fs::rename(enclosing.join("owner-retained"), factory.join("owner"))
        .expect("restore host-created source");
    host.check_sources().expect("restored custody");
    claude_cleanup_contents_at(&host.held, true).expect("cleanup restored fixture");
    let named = fs::symlink_metadata(&enclosing).expect("same E");
    assert_eq!((named.dev(), named.ino()), host.identity);
    fs::remove_dir(&enclosing).expect("empty E");
}

/// # Panics
/// Panics if a watchdog diagnostic discards the namespace child's output.
/// ´test:unit:claude-fixture-watchdog-retains-child-output´
#[test]
fn claude_fixture_watchdog_retains_child_output() {
    if enter(
        "claude_fixture_watchdog_retains_child_output",
        watchdog_body,
    ) {
        return;
    }
    let mut host = launch("claude_fixture_watchdog_retains_child_output");
    let enclosing = host.root.as_ref().expect("E").path().to_path_buf();
    wait_event(&mut host, "ready");
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finish_until(&mut host, true, std::time::Instant::now());
    }))
    .expect_err("watchdog refusal");
    let message = error.downcast_ref::<String>().expect("diagnostic text");
    for marker in [
        "transaction outer watchdog",
        "fixture-watchdog-stdout",
        "fixture-watchdog-stderr",
    ] {
        assert!(message.contains(marker), "missing {marker}: {message}");
    }
    host.cleanup();
    assert!(!enclosing.exists(), "watchdog cleanup removes real root");
}

fn watchdog_body(enclosing: &Path) {
    let (root, _anchors) = moved_root(enclosing);
    writeln!(std::io::stdout(), "fixture-watchdog-stdout").expect("stdout");
    writeln!(std::io::stderr(), "fixture-watchdog-stderr").expect("stderr");
    fs::write(enclosing.join("ready"), b"ready").expect("ready");
    std::thread::sleep(Duration::from_secs(120));
    drop(root);
    panic!("watchdog fixture exceeded bound");
}

/// # Panics
/// Panics if collecting failure output authorizes removal after an unconfirmed stop.
/// ´test:unit:claude-fixture-unconfirmed-stop-retains-enclosure´
#[test]
fn claude_fixture_unconfirmed_stop_retains_enclosure() {
    if enter(
        "claude_fixture_unconfirmed_stop_retains_enclosure",
        watchdog_body,
    ) {
        return;
    }
    let mut host = launch("claude_fixture_unconfirmed_stop_retains_enclosure");
    let enclosing = host.root.as_ref().expect("E").path().to_path_buf();
    wait_event(&mut host, "ready");
    // First stop the real namespace, so this refusal-path control leaves no live child.
    assert!(
        host.child.as_mut().expect("child").stop(),
        "real namespace stopped"
    );
    host.child.as_mut().expect("child").stopped = Some(false);
    let sentinel = enclosing.join("unconfirmed-stop-sentinel");
    fs::write(&sentinel, b"retained until stop is proved").expect("sentinel");
    let inode = fs::metadata(&sentinel).expect("sentinel identity").ino();
    let held = host.held.try_clone().expect("retain cleanup identity");
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        fail_with_output(&mut host, "injected unconfirmed stop");
    }))
    .expect_err("stop refusal diagnostic");
    let message = error.downcast_ref::<String>().expect("panic text");
    assert!(message.contains("namespace stopped=false"), "{message}");
    assert_eq!(
        fs::read(&sentinel).expect("unconfirmed stop retains enclosure"),
        b"retained until stop is proved"
    );
    assert_eq!(
        fs::metadata(&sentinel).expect("retained inode").ino(),
        inode
    );
    // Only this control knows the real namespace was stopped before the injected refusal.
    claude_cleanup_contents_at(&held, true).expect("cleanup confirmed-dead fixture");
    let expected = held.metadata().expect("held E");
    let named = fs::symlink_metadata(&enclosing).expect("same E");
    assert_eq!((named.dev(), named.ino()), (expected.dev(), expected.ino()));
    fs::remove_dir(enclosing).expect("empty own enclosure");
}
