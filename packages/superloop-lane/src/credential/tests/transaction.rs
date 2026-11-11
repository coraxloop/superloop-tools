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

fn round_body(enclosing: &Path) {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
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
    let mut record = staged_record(&owner, &runs, pid, start);
    round_contract(&owner, &worker, &mut record, &admission, &document);
    drop(admission);
    let removed = root.path().to_path_buf();
    drop(root);
    assert!(
        !removed.exists(),
        "factory root is really removed after the round"
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
