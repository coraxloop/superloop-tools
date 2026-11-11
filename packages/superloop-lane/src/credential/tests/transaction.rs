//! Test-only mapped transaction. The native stand-in establishes no vendor behavior.
use super::*;
use crate::runtime_admission::fixture::{self, Declaration, FixtureRoot};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::sync::Arc;

struct Host {
    root: Option<tempfile::TempDir>,
    held: fs::File,
    identity: (u64, u64),
    child: Option<ClaudeNamespaceChild>,
}
impl Host {
    fn cleanup(&mut self) {
        // Disarm path-recursive TempDir drop before any fallible stop or mapped cleanup.
        let path = self.root.take().expect("retained enclosing root").keep();
        if let Some(mut child) = self.child.take() {
            assert!(child.stop(), "transaction namespace did not stop");
        }
        claude_cleanup_contents_at(&self.held, true).expect("whole enclosing mapped cleanup");
        let same = fs::symlink_metadata(&path)
            .is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == self.identity);
        if same {
            fs::remove_dir(path).expect("remove unchanged emptied enclosure");
        }
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
    let mut host = Host {
        root: Some(root),
        held,
        identity: (m.dev(), m.ino()),
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
        assert!(
            host.child
                .as_mut()
                .expect("child")
                .try_wait()
                .expect("status")
                .is_none(),
            "transaction exited before event {name}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "transaction event {name} timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn finish(host: &mut Host, success: bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while host
        .child
        .as_mut()
        .expect("child")
        .try_wait()
        .expect("status")
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "transaction outer watchdog"
        );
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
    for name in ["owner", "runs"] {
        fs::rename(enclosing.join(name), root.path().join(name)).expect("move held directory");
    }
    (root, anchors)
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

fn transaction_body(enclosing: &Path, action: TransactionAction) {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let _endpoint = fixture_service_endpoint("http://127.0.0.1:1/unused".into());
    let (root, mut anchors) = moved_root(enclosing);
    let owner = root.path().join("owner");
    let runs = root.path().join("runs");
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
    let document = claude_document((now + 590) * 1000);
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
    assert_eq!(Arc::strong_count(&root), 1);
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
        }
    }
    #[allow(clippy::exit)]
    fn finish(&mut self) -> Result<(), LaneError> {
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

fn periodic_evidence(runs: &Path) -> (Vec<u8>, u64) {
    let path = runs.join(".launch-R/credential-refresh.json");
    let bytes = fs::read(&path).expect("actual periodic evidence");
    let value: Value = serde_json::from_slice(&bytes).expect("evidence JSON");
    assert_eq!(value["state"], "published", "first live publication");
    assert_eq!(value["schema"], 2);
    (bytes, fs::metadata(path).expect("evidence inode").ino())
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
    periodic_evidence(runs);
    periodic_leaf(worker, source, prior);
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
        move |_: &std::sync::atomic::AtomicBool| {
            pass.send(()).expect("pass-complete event");
            resume
                .recv_timeout(Duration::from_secs(30))
                .expect("pass-release event");
        },
    )
    .expect("event-driven fixture authority");
    let mut thread = PeriodicThread::observe(Arc::clone(&cancelled), thread);
    observed
        .recv_timeout(Duration::from_secs(30))
        .expect("first periodic pass event");
    assert!(
        !cancelled.load(std::sync::atomic::Ordering::Acquire),
        "first pass remains live"
    );
    let (evidence, inode) = periodic_evidence(runs);
    let worker_inode = periodic_leaf(worker, source, prior);
    let retained = periodic_replace(root, owner, runs, source, configuration);
    release.send(()).expect("release second periodic pass");
    assert!(
        matches!(
            observed.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        ),
        "scope loss must end before a second pass-complete event"
    );
    assert!(
        cancelled.load(std::sync::atomic::Ordering::Acquire),
        "in-loop refusal cancels service"
    );
    let error = thread.finish().expect_err("in-loop scope refusal");
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
