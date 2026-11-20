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

fn launch(name: &str) -> Host {
    use std::os::unix::process::CommandExt as _;
    let enclosing = tempfile::Builder::new()
        .prefix("lane-claude-transaction-")
        .tempdir()
        .expect("host-created enclosure");
    let (root, bundle) = claude_standin_host_with_root(enclosing);
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
    let mut child = host.child.take().expect("diagnostic child");
    let stopped = child.stop();
    if !stopped && let Some(root) = host.root.take() {
        // Consuming the child for diagnostics must not authorize cleanup after an unproved stop.
        let _retained = root.keep();
    }
    let output = child.wait_with_output().expect("failed child output");
    panic!(
        "{event}; namespace stopped={stopped}\nstdout:\n{}\nstderr:\n{}",
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
fn install_service_template(root: &FixtureRoot, owner: &Path, digest: &str) -> PathBuf {
    use crate::build::payload::{CLAUDE, CLAUDE_IMAGE_PROGRAM, InstallPayload};
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
    let loop_root = owner.join(".var/loops/alpha");
    fs::create_dir_all(&loop_root).expect("loop install root");
    let image = format!("sha256:{}", "a".repeat(64));
    let payload = InstallPayload {
        vendor: CLAUDE,
        bin: PathBuf::from("/usr/bin/true"),
        sha256: digest.to_owned(),
        image_program: CLAUDE_IMAGE_PROGRAM.into(),
        companion: None,
    };
    let config = owner.join(".config/loops/alpha");
    fs::remove_file(config.join("install-generation.json"))
        .expect("replace staged transaction generation with installer generation");
    let held = fs::File::open(&config).expect("install directory");
    let guard = crate::install::InstallGuard::from_transferred(&config, held.into())
        .expect("fixture install lock");
    let payloads = std::slice::from_ref(&payload);
    let preview = crate::install_private::run_payloads(
        owner,
        "alpha",
        64000,
        (0, 0),
        &data,
        payloads,
        &image,
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
        &payload,
        &image,
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
        &image,
        "fixture",
        Some(source),
        false,
        false,
        &guard,
    )
    .expect("installer act");
    crate::install::fixture_complete_claude_generation(&generation_path, &mut generation)
        .expect("installer complete generation");
    let template = payload.template(&loop_root, &"a".repeat(64));
    let manifest: Value =
        serde_json::from_slice(&fs::read(template.join("manifest")).expect("installed manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["image_digest"], image);
    assert_eq!(manifest["claude_sha256"], digest);
    let generation: Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("complete generation"))
            .expect("generation JSON");
    assert_eq!(generation["phase"], "complete");
    assert_eq!(
        generation["claude_template_dir"],
        template.display().to_string()
    );
    assert_eq!(generation["claude_sha256"], manifest["claude_sha256"]);
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
                let template = install_service_template(root, owner, &digest);
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

type TransactionAction = fn(
    &FixtureRoot,
    &Path,
    &Path,
    &Path,
    &mut Value,
    &crate::runtime_admission::RuntimeAdmission,
    &Value,
);

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

fn transaction_body(enclosing: &Path, action: TransactionAction) {
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
    let (_runtime, programs) =
        crate::container_entry::take_support_programs(&mut anchors, BoxBackend::Claude)
            .expect("program roles");
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
