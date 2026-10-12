use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::hook::{EscalationRecord, EscalationSink, HookTiming, ModelStage};
use crate::journal::{
    DispositionDetail, DispositionOutcome, Journal, JournalError, MAX_JOURNAL_RECORD_BYTES,
    RootShape, RoutedJournal, StealOutcome, lock_budget, read_journal_bytes, request_digest,
    serialized_order_fixture, steal_stale_lock, test_lock_guard_restored_after,
    test_owner_probe_path, write_outbox_file,
};
use crate::request::Scope;
use crate::review::load_review;
use crate::role::{
    Registry, RegistryError, open_directory_no_follow, open_public_root, parse_registry,
    resolve_role,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn annotated_worker_entry(text: &str) -> String {
    format!(
        "{text}LOOP_ALLOCATIONS_SHA256={}\nLOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z\n",
        "a".repeat(64)
    )
}

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "permission-triage-journal-unit-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique fixture parent is created");
        Self(path)
    }

    fn state_root(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

struct OutboxFixture {
    _directory: FixtureDirectory,
    registry: Registry,
    registry_path: PathBuf,
    outbox: PathBuf,
    run_root: PathBuf,
    loop_root: PathBuf,
    estate_root: PathBuf,
    estate_checkout: PathBuf,
    worker_base: u32,
}

impl OutboxFixture {
    fn new(name: &str, owner_offset: u32, mode: Option<u32>) -> Self {
        let directory = FixtureDirectory::new(name);
        let uid = crate::role::effective_uid().expect("process uid");
        let worker_base = uid.checked_add(10).expect("worker fixture uid range");
        let loop_root = directory.0.join("journals/loop");
        let estate_root = directory.0.join("journals/estate");
        for root in [&loop_root, &estate_root] {
            fs::create_dir_all(root).expect("registered root");
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .expect("registered private mode");
        }
        let home = directory.0.join("home/loop");
        let run_root = home.join("runs").join(uid.to_string());
        fs::create_dir_all(&run_root).expect("worker run root");
        fs::set_permissions(&run_root, fs::Permissions::from_mode(0o755)).expect("worker run mode");
        let registry_path = directory.0.join("estate/registry");
        fs::create_dir_all(&registry_path).expect("registry directory");
        let outbox = directory.0.join("estate/outboxes/loop");
        fs::create_dir_all(outbox.parent().expect("outbox parent"))
            .expect("outbox parent directory");
        if let Some(mode) = mode {
            fs::create_dir(&outbox).expect("outbox directory");
            fs::set_permissions(&outbox, fs::Permissions::from_mode(mode)).expect("outbox mode");
        }
        let estate_checkout = directory.0.join("launch/estate");
        let loop_entry = annotated_worker_entry(&format!(
            "LOOP_NAME=loop\nLOOP_SID=loop-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\nLOOP_HOME={}\nLOOP_UID={}\nLOOP_WORKER_UIDS={worker_base}:4\n",
            directory.0.join("launch/loop").display(),
            loop_root.display(),
            home.display(),
            uid + owner_offset
        ));
        let estate_entry = format!(
            "LOOP_NAME=estate\nLOOP_SID=estate-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            estate_checkout.display(),
            estate_root.display()
        );
        let mut texts = std::collections::BTreeMap::new();
        texts.insert("loop.env".to_owned(), loop_entry.into_bytes());
        texts.insert("estate.env".to_owned(), estate_entry.into_bytes());
        let registry = parse_registry(b"loop.env\nestate.env\n", &texts);
        Self {
            _directory: directory,
            registry,
            registry_path,
            outbox,
            run_root,
            loop_root,
            estate_root,
            estate_checkout,
            worker_base,
        }
    }

    fn worker_sink(&self, offset: u32) -> RoutedJournal {
        let role = resolve_role(
            Some(&self.registry),
            self.worker_base + offset,
            "",
            "/unregistered",
            None,
            false,
        );
        let mut sink = RoutedJournal::from_environment();
        sink.test_set_registry_path(self.registry_path.clone());
        sink.test_set_estate_root(self.estate_root.clone());
        assert!(
            sink.configure(Some(&self.registry), &role),
            "worker configures"
        );
        sink
    }

    fn deployment_sink(&self) -> RoutedJournal {
        let uid = crate::role::effective_uid().expect("process uid");
        let role = resolve_role(
            Some(&self.registry),
            uid,
            "estate-sid",
            self.estate_checkout.to_str().expect("checkout path"),
            None,
            false,
        );
        let mut sink = RoutedJournal::from_environment();
        sink.test_set_registry_path(self.registry_path.clone());
        sink.test_set_estate_root(self.estate_root.clone());
        assert!(
            sink.configure(Some(&self.registry), &role),
            "deployment configures"
        );
        sink
    }
}

fn estate_record(label: &str) -> EscalationRecord {
    let input = serde_json::to_vec(&json!({"session_id":"test","cwd":"/unregistered","permission_mode":"manual","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":label,"tool_input":{"command":"printf estate"}})).expect("request JSON");
    let decoded = crate::decode_request(&input);
    let verdict = crate::adapt_hook(&decoded, None, ModelStage::NotRun, HookTiming::default());
    assert_eq!(verdict.record().scope(), "estate");
    verdict.record().clone()
}

fn lines(path: &Path) -> Vec<Value> {
    let bytes = fs::read(path.join("escalations.jsonl")).expect("journal is readable");
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("journal line is JSON"))
        .collect()
}

fn fixture_with_escalation(name: &str) -> (FixtureDirectory, Journal, String) {
    let directory = FixtureDirectory::new(name);
    let root = directory.state_root();
    let journal = Journal::from_state_root(&root);
    journal
        .append_test_escalation("printf fixture", "fixture reason")
        .expect("escalation is appended");
    let event_id = lines(&root)[0]["event_id"]
        .as_str()
        .expect("event id is a string")
        .to_owned();
    (directory, journal, event_id)
}

/// ´test:crate:journal-creates-and-verifies-private-modes´
#[test]
fn journal_creates_and_verifies_private_modes() {
    let directory = FixtureDirectory::new("private-modes");
    let root = directory.state_root();
    let journal = Journal::from_state_root(&root);
    journal
        .append_test_escalation("printf fixture", "fixture reason")
        .expect("journal append succeeds");
    assert_eq!(journal.test_directory_syncs(), 2);
    assert_eq!(
        fs::metadata(&root)
            .expect("state-root metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("escalations.jsonl"))
            .expect("private file metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    let entries = fs::read_dir(&root)
        .expect("state root is readable")
        .map(|entry| entry.expect("state-root entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from("escalations.jsonl")]);
}

/// ´test:crate:public-journal-appends-and-rereads-at-0755´
#[test]
fn public_journal_appends_and_rereads_at_0755() {
    let fixture = FixtureDirectory::new("public-root");
    let root = fixture.state_root();
    fs::create_dir(&root).expect("public root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("public mode");
    let uid = fs::metadata(&root).expect("root metadata").uid();
    let directory = open_public_root(&root, uid).expect("public root opens");
    let journal =
        Journal::from_registered_descriptor(directory, &root, Scope::Loop, RootShape::Public)
            .expect("public descriptor binds");
    journal
        .append_test_escalation("printf public", "public verdict")
        .expect("public append");
    assert_eq!(
        fs::metadata(root.join("escalations.jsonl"))
            .expect("journal metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        journal.read().expect("public reread"),
        fs::read(root.join("escalations.jsonl")).expect("journal bytes")
    );
    assert_eq!(lines(&root).len(), 1);
}

/// ´test:crate:public-journal-refuses-writable-roots-and-file´
#[test]
fn public_journal_refuses_writable_roots_and_file() {
    for mode in [0o775, 0o777] {
        let fixture = FixtureDirectory::new("writable-public-root");
        let root = fixture.state_root();
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(mode)).expect("root mode");
        let uid = fs::metadata(&root).expect("root metadata").uid();
        assert!(
            matches!(open_public_root(&root, uid), Err(RegistryError::PublicRootWritable(observed)) if observed == mode)
        );
        let journal = Journal::from_registered_descriptor(
            File::open(&root).expect("root descriptor"),
            &root,
            Scope::Loop,
            RootShape::Public,
        )
        .expect("descriptor binds");
        assert!(
            matches!(journal.append_test_escalation("x", "y"), Err(JournalError::PublicRootWritable(observed)) if observed == mode)
        );
    }
    let fixture = FixtureDirectory::new("writable-public-file");
    let root = fixture.state_root();
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("root mode");
    let file = root.join("escalations.jsonl");
    fs::write(&file, []).expect("journal file");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("file mode");
    let uid = fs::metadata(&root).expect("root metadata").uid();
    let journal = Journal::from_registered_descriptor(
        open_public_root(&root, uid).expect("root opens"),
        &root,
        Scope::Loop,
        RootShape::Public,
    )
    .expect("descriptor binds");
    assert!(matches!(
        journal.append_test_escalation("x", "y"),
        Err(JournalError::PublicFileWritable(0o664))
    ));
    assert!(matches!(
        journal.read(),
        Err(JournalError::PublicFileWritable(0o664))
    ));
}

/// The route is reached with the test process's uid inside the loop's worker block.
/// ´test:crate:worker-routing-reaches-run-directory-from-own-uid´
#[test]
fn worker_routing_reaches_run_directory_from_own_uid() {
    let fixture = FixtureDirectory::new("worker-routing");
    let private_root = fixture.0.join("journals/loop");
    fs::create_dir_all(&private_root).expect("loop root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).expect("private mode");
    let home = fixture.0.join("home/loop");
    let uid = fs::metadata(&private_root).expect("root metadata").uid();
    let run_root = home.join("runs").join(uid.to_string());
    fs::create_dir_all(&run_root).expect("run root");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o111)).expect("search-only home");
    fs::set_permissions(&run_root, fs::Permissions::from_mode(0o755)).expect("public mode");
    let entry = annotated_worker_entry(&format!(
        "LOOP_NAME=loop\nLOOP_SID=loop-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\nLOOP_HOME={}\nLOOP_WORKER_UIDS={uid}:1\n",
        fixture.0.join("launch").display(),
        private_root.display(),
        home.display()
    ));
    let mut texts = std::collections::BTreeMap::new();
    texts.insert("loop.env".to_owned(), entry.into_bytes());
    let registry = parse_registry(b"loop.env\n", &texts);
    let role = resolve_role(Some(&registry), uid, "", "/unregistered", None, false);
    let mut sink = RoutedJournal::from_environment();
    assert!(
        sink.configure(Some(&registry), &role),
        "worker run root configures"
    );
    assert_eq!(sink.destination(Scope::Loop), Some("caller-loop-journal"));
    assert_eq!(sink.destination(Scope::Estate), None);
    assert_eq!(sink.record_failure_detail(Scope::Estate), None);
    assert_eq!(
        sink.classifier_root()
            .expect("classifier descriptor")
            .metadata()
            .expect("descriptor metadata")
            .ino(),
        fs::metadata(&run_root).expect("run metadata").ino()
    );
    sink.test_loop_journal()
        .expect("worker loop journal")
        .append_test_escalation("printf worker", "loop verdict")
        .expect("loop append");
    assert_eq!(lines(&run_root).len(), 1);
    assert!(!private_root.join("escalations.jsonl").exists());

    let input = serde_json::to_vec(&json!({"session_id":"test","cwd":"/unregistered","permission_mode":"manual","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"use-worker","tool_input":{"command":"printf estate"}})).expect("request JSON");
    let decoded = crate::decode_request(&input);
    let verdict = crate::adapt_hook(&decoded, None, ModelStage::NotRun, HookTiming::default());
    assert_eq!(verdict.record().scope(), "estate");
    assert!(matches!(
        sink.record(verdict.record()),
        Err(JournalError::OutboxUnavailable { .. })
    ));
    assert!(!run_root.join("estate-escalations.jsonl").exists());
    assert!(!private_root.join("estate-escalations.jsonl").exists());
    assert_eq!(lines(&run_root).len(), 1);
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).expect("fixture cleanup mode");
}

/// ´test:crate:worker-configuration-skips-deployment-root-access´
#[test]
fn worker_configuration_skips_deployment_root_access() {
    let fixture = FixtureDirectory::new("worker-skips-private-root");
    let uid = crate::role::effective_uid().expect("process uid");
    let journals = fixture.0.join("journals");
    let private_root = journals.join("loop");
    fs::create_dir_all(&private_root).expect("private root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    let home = fixture.0.join("home/loop");
    let run_root = home.join("runs").join(uid.to_string());
    fs::create_dir_all(&run_root).expect("worker run root");
    fs::set_permissions(&run_root, fs::Permissions::from_mode(0o755)).expect("worker root mode");
    let entry = annotated_worker_entry(&format!(
        "LOOP_NAME=loop\nLOOP_SID=loop-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\nLOOP_HOME={}\nLOOP_WORKER_UIDS={uid}:1\n",
        fixture.0.join("launch").display(),
        private_root.display(),
        home.display()
    ));
    let parse = |text: String| {
        let mut texts = std::collections::BTreeMap::new();
        texts.insert("loop.env".to_owned(), text.into_bytes());
        parse_registry(b"loop.env\n", &texts)
    };
    let registry = parse(entry.clone());
    assert!(registry.validate_deployment_structure(None).is_ok());
    assert!(
        matches!(registry.validate_deployment_structure(Some(uid)), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("deployment uid"))
    );
    fs::set_permissions(&journals, fs::Permissions::from_mode(0o000))
        .expect("deny private-root traversal");
    let worker = resolve_role(Some(&registry), uid, "", "/unregistered", None, false);
    let mut sink = RoutedJournal::from_environment();
    assert!(sink.configure(Some(&registry), &worker));
    assert!(sink.test_loop_journal().is_some());
    assert_eq!(sink.destination(Scope::Estate), None);

    let deployment_registry = parse(entry.replace(&format!("LOOP_WORKER_UIDS={uid}:1\n"), ""));
    let deployment_role = resolve_role(
        Some(&deployment_registry),
        uid,
        "",
        "/unregistered",
        None,
        false,
    );
    let mut deployment_sink = RoutedJournal::from_environment();
    assert!(!deployment_sink.configure(Some(&deployment_registry), &deployment_role));
    assert!(deployment_sink.configuration_error().is_some());
    fs::set_permissions(&journals, fs::Permissions::from_mode(0o700))
        .expect("restore fixture traversal");
}

/// ´test:crate:worker-estate-verdict-creates-one-outbox-file´
#[test]
fn worker_estate_verdict_creates_one_outbox_file() {
    let fixture = OutboxFixture::new("worker-outbox", 0, Some(0o1775));
    let mut sink = fixture.worker_sink(0);
    assert_eq!(sink.destination(Scope::Estate), Some("loop-outbox"));
    let record = estate_record("outbox-one");
    sink.record(&record).expect("outbox write");
    let files = fs::read_dir(&fixture.outbox)
        .expect("outbox entries")
        .map(|entry| entry.expect("outbox entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(files, [std::ffi::OsString::from(record.event_id())]);
    let file = fixture.outbox.join(record.event_id());
    let metadata = fs::metadata(&file).expect("event metadata");
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o644);
    assert_eq!(
        metadata.uid(),
        crate::role::effective_uid().expect("process uid")
    );
    let bytes = fs::read(&file).expect("event bytes");
    let line = bytes.strip_suffix(b"\n").expect("terminated JSON line");
    assert!(!line.contains(&b'\n'));
    let value: Value = serde_json::from_slice(line).expect("one JSON line");
    assert_eq!(value["event_id"], record.event_id());
    assert_eq!(value["scope"], "estate");
    assert!(!fixture.run_root.join("escalations.jsonl").exists());
    assert!(!fixture.loop_root.join("escalations.jsonl").exists());
    assert!(
        !fixture
            .estate_root
            .join("estate-escalations.jsonl")
            .exists()
    );
}

/// ´test:crate:failed-outbox-write-removes-partial-event-file´
#[test]
fn failed_outbox_write_removes_partial_event_file() {
    let fixture = OutboxFixture::new("outbox-partial", 0, Some(0o1775));
    let directory = open_directory_no_follow(&fixture.outbox).expect("outbox descriptor");
    let id = "a".repeat(64);
    let line = b"partial event\n";
    let result = write_outbox_file(&directory, &fixture.outbox, &id, line, |file, bytes| {
        file.write_all(&bytes[..7])?;
        Err(io::Error::other("injected write failure"))
    });
    assert!(matches!(result, Err(JournalError::OutboxWrite(_))));
    assert!(!fixture.outbox.join(&id).exists());
    assert_eq!(
        fs::read_dir(&fixture.outbox)
            .expect("outbox entries")
            .count(),
        0
    );
}

/// ´test:crate:peer-workers-publish-distinct-sticky-outbox-files´
#[test]
fn peer_workers_publish_distinct_sticky_outbox_files() {
    let fixture = OutboxFixture::new("peer-outbox", 0, Some(0o1775));
    let first = estate_record("peer-one");
    let second = estate_record("peer-two");
    fixture
        .worker_sink(0)
        .record(&first)
        .expect("first peer write");
    fixture
        .worker_sink(1)
        .record(&second)
        .expect("second peer write");
    assert_ne!(first.event_id(), second.event_id());
    assert_eq!(
        fs::read_dir(&fixture.outbox)
            .expect("outbox entries")
            .count(),
        2
    );
    assert_eq!(
        fs::metadata(&fixture.outbox)
            .expect("outbox metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o1775
    );
    let owner = crate::role::effective_uid().expect("process uid");
    for id in [first.event_id(), second.event_id()] {
        assert_eq!(
            fs::metadata(fixture.outbox.join(id))
                .expect("peer file")
                .uid(),
            owner
        );
    }
}

/// ´test:crate:deployment-estate-verdict-stays-in-estate-stream´
#[test]
fn deployment_estate_verdict_stays_in_estate_stream() {
    let fixture = OutboxFixture::new("deployment-estate", 0, Some(0o1775));
    let mut sink = fixture.deployment_sink();
    assert_eq!(sink.destination(Scope::Estate), Some("estate-journal"));
    let record = estate_record("deployment-estate");
    sink.record(&record).expect("estate journal append");
    let bytes =
        fs::read(fixture.estate_root.join("estate-escalations.jsonl")).expect("estate stream");
    let records = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    assert_eq!(records, 1);
    assert_eq!(
        fs::read_dir(&fixture.outbox)
            .expect("outbox entries")
            .count(),
        0
    );
}

/// ´test:crate:outbox-shape-owner-and-absence-fail-the-verdict´
#[test]
fn outbox_shape_owner_and_absence_fail_the_verdict() {
    let wrong_mode = OutboxFixture::new("outbox-mode", 0, Some(0o775));
    assert!(matches!(
        wrong_mode
            .worker_sink(0)
            .record(&estate_record("wrong-mode")),
        Err(JournalError::OutboxShape { mode: 0o775 })
    ));
    assert_eq!(
        fs::read_dir(&wrong_mode.outbox)
            .expect("wrong-mode entries")
            .count(),
        0
    );

    let wrong_owner = OutboxFixture::new("outbox-owner", 1, Some(0o1775));
    let actual = crate::role::effective_uid().expect("process uid");
    assert!(matches!(
        wrong_owner.worker_sink(0).record(&estate_record("wrong-owner")),
        Err(JournalError::OutboxOwner { actual: observed, expected }) if observed == actual && expected == actual + 1
    ));
    assert_eq!(
        fs::read_dir(&wrong_owner.outbox)
            .expect("wrong-owner entries")
            .count(),
        0
    );

    let missing = OutboxFixture::new("outbox-missing", 0, None);
    assert!(matches!(
        missing
            .worker_sink(0)
            .record(&estate_record("missing-outbox")),
        Err(JournalError::OutboxUnavailable { .. })
    ));
    assert!(!missing.outbox.exists());
}

/// ´test:crate:outbox-collision-preserves-existing-event´
#[test]
fn outbox_collision_preserves_existing_event() {
    let fixture = OutboxFixture::new("outbox-collision", 0, Some(0o1775));
    let record = estate_record("collision");
    let mut sink = fixture.worker_sink(0);
    sink.record(&record).expect("first write");
    let path = fixture.outbox.join(record.event_id());
    let before = fs::read(&path).expect("first event bytes");
    assert!(matches!(
        sink.record(&record),
        Err(JournalError::OutboxCollision { event_id }) if event_id == record.event_id()
    ));
    assert_eq!(fs::read(&path).expect("existing event bytes"), before);
    assert_eq!(
        fs::read_dir(&fixture.outbox)
            .expect("outbox entries")
            .count(),
        1
    );
}

/// ´test:crate:journal-refuses-unsafe-roots-and-final-symlink´
#[test]
fn journal_refuses_unsafe_roots_and_final_symlink() {
    let relative = Journal::from_state_root(Path::new("relative-state"));
    assert!(matches!(
        relative.append_test_escalation("x", "y"),
        Err(JournalError::StateRootNotAbsolute)
    ));

    let file_fixture = FixtureDirectory::new("root-file");
    let file_root = file_fixture.state_root();
    fs::write(&file_root, b"not a directory").expect("fixture file is written");
    assert!(matches!(
        Journal::from_state_root(&file_root).append_test_escalation("x", "y"),
        Err(JournalError::RootNotDirectory)
    ));

    let mode_fixture = FixtureDirectory::new("wide-root");
    let mode_root = mode_fixture.state_root();
    fs::create_dir(&mode_root).expect("wide root is created");
    fs::set_permissions(&mode_root, fs::Permissions::from_mode(0o755)).expect("wide mode is set");
    assert!(matches!(
        Journal::from_state_root(&mode_root).append_test_escalation("x", "y"),
        Err(JournalError::RootMode(0o755))
    ));

    let link_fixture = FixtureDirectory::new("journal-link");
    let link_root = link_fixture.state_root();
    fs::create_dir(&link_root).expect("root is created");
    fs::set_permissions(&link_root, fs::Permissions::from_mode(0o700)).expect("root mode is set");
    let target = link_fixture.0.join("target");
    fs::write(&target, b"").expect("link target is created");
    symlink(&target, link_root.join("escalations.jsonl")).expect("journal symlink is created");
    assert!(matches!(
        Journal::from_state_root(&link_root).append_test_escalation("x", "y"),
        Err(JournalError::FinalSymlink)
    ));
}

/// ´test:crate:journal-refuses-a-state-root-owned-by-another-uid´
#[test]
fn journal_refuses_a_state_root_owned_by_another_uid() {
    let directory = FixtureDirectory::new("wrong-owner");
    let root = directory.state_root();
    fs::create_dir(&root).expect("root is created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode is set");
    let actual = fs::metadata(&root).expect("root metadata").uid();
    let effective = actual.wrapping_add(1);
    let mut journal = Journal::from_state_root(&root);
    journal.set_test_effective_uid(effective);
    assert!(matches!(
        journal.append_test_escalation("x", "y"),
        Err(JournalError::RootOwner {
            actual: observed,
            effective: expected,
        }) if observed == actual && expected == effective
    ));
    assert!(!root.join("escalations.jsonl").exists());
}

/// ´test:crate:journal-review-skips-the-append-only-ownership-probe´
#[test]
fn journal_review_skips_the_append_only_ownership_probe() {
    let directory = FixtureDirectory::new("review-with-failed-owner-probe");
    let root = directory.state_root();
    let journal = Journal::from_state_root(&root);
    journal
        .append_test_escalation("printf review", "review stays readable")
        .expect("fixture escalation is appended");
    let entries_before = fs::read_dir(&root)
        .expect("state root is readable")
        .map(|entry| entry.expect("state-root entry").file_name())
        .collect::<Vec<_>>();

    Journal::set_test_ownership_probe_failure(true);
    let review = load_review(&root).expect("review does not run an ownership probe");
    assert_eq!(review.escalations().len(), 1);
    assert_eq!(review.escalations()[0].command(), "printf review");
    assert!(matches!(
        journal.append_test_escalation("printf denied", "probe fails"),
        Err(JournalError::RootOwnershipProbe(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    Journal::set_test_ownership_probe_failure(false);

    let entries_after = fs::read_dir(&root)
        .expect("state root remains readable")
        .map(|entry| entry.expect("state-root entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries_after, entries_before);
    assert_eq!(lines(&root).len(), 1);
}

/// ´test:crate:journal-review-accepts-0500-but-append-rejects-its-shape´
#[test]
fn journal_review_accepts_0500_but_append_rejects_its_shape() {
    let directory = FixtureDirectory::new("review-only-root-mode");
    let root = directory.state_root();
    let journal = Journal::from_state_root(&root);
    journal
        .append_test_escalation("printf review", "review stays readable")
        .expect("fixture escalation is appended");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500))
        .expect("state root becomes owner-read-only");

    Journal::set_test_ownership_probe_failure(true);
    let review = load_review(&root);
    let append = journal.append_test_escalation("printf denied", "shape fails before probe");
    Journal::set_test_ownership_probe_failure(false);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("state-root mode is restored");

    let review = review.expect("review accepts the owner-read-only shape");
    assert_eq!(review.escalations().len(), 1);
    assert_eq!(review.escalations()[0].command(), "printf review");
    assert!(matches!(append, Err(JournalError::RootMode(0o500))));
}

/// ´test:crate:journal-record-cap-truncates-command-and-reason-on-utf8-boundaries´
#[test]
fn journal_record_cap_truncates_command_and_reason_on_utf8_boundaries() {
    let directory = FixtureDirectory::new("record-cap");
    let root = directory.state_root();
    let command = "é".repeat(10_000);
    let reason = "界".repeat(10_000);
    Journal::from_state_root(&root)
        .append_test_escalation(&command, &reason)
        .expect("oversized variable fields are truncated");
    let bytes = read_journal_bytes(&root).expect("journal reads");
    assert!(bytes.len() <= MAX_JOURNAL_RECORD_BYTES);
    let value: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("record is JSON");
    assert_eq!(value["truncated"], true);
    assert!(value["command"].as_str().expect("command").len() < command.len());
    assert!(value["reason"].as_str().expect("reason").len() < reason.len());
}

/// ´test:crate:journal-base-fields-retain-the-exact-escalation-schema´
#[test]
fn journal_base_fields_retain_the_exact_escalation_schema() {
    let directory = FixtureDirectory::new("base-fields");
    let root = directory.state_root();
    Journal::from_state_root(&root)
        .append_test_escalation("printf base-fields", "base-fields reason")
        .expect("escalation is appended");
    let records = lines(&root);
    let object = records
        .first()
        .and_then(Value::as_object)
        .expect("record is an object");
    assert_eq!(object.len(), 24);
    assert_eq!(object["schema"], 2);
    assert_eq!(object["event"], "escalated");
    assert_eq!(object["tool_use_id"], "use-test");
    assert_eq!(object["command"], "printf base-fields");
    assert_eq!(object["reason"], "base-fields reason");
    assert_eq!(object["role"], "orchestrator");
    assert_eq!(object["loop_name"], "orchestration");
    assert_eq!(object["stale_session"], false);
    assert_eq!(object["domain_rubric_digest"], Value::Null);
    assert_eq!(object["scope"], "loop");
    assert_eq!(object["mode"], "enforce");
    assert_eq!(object["would_be_decision"], "deny");
    assert_eq!(object["emitted_decision"], "deny");
    assert_eq!(object["wall_ms"], 0);
    assert_eq!(object["model_wall_ms"], 0);
}

/// ´test:crate:journal-record-field-order-is-byte-pinned´
#[test]
fn journal_record_field_order_is_byte_pinned() {
    let bytes = serialized_order_fixture().expect("fixed record serializes");
    assert_eq!(
        bytes,
        br#"{"classification":"suspicious","command":"printf fixed","cwd":"/workspace/project","domain_rubric_digest":null,"emitted_decision":"deny","event":"escalated","event_id":"event-fixed","general_rubric_digest":"general-fixed","loop_name":null,"mode":"enforce","model_status":"success","model_wall_ms":0,"owner_rubric_digest":null,"reason":"fixture reason","recorded_at":"2026-09-03T00:00:00.000000000Z","request_digest":"request-fixed","role":"unknown","schema":2,"scope":"estate","stale_session":false,"tool":"Bash","tool_use_id":"use-fixed","wall_ms":0,"would_be_decision":"deny"}"#
    );
}

/// ´test:crate:legacy-schema-one-is-review-only-and-cannot-be-adjudicated´
#[test]
fn legacy_schema_one_is_review_only_and_cannot_be_adjudicated() {
    let directory = FixtureDirectory::new("legacy-review-only");
    let root = directory.state_root();
    fs::create_dir(&root).expect("legacy state root is created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("legacy state root is private");
    let value = json!({
        "schema": 1,
        "event": "escalated",
        "event_id": "legacy-event",
        "recorded_at": "2026-09-03T00:00:00.000000000Z",
        "tool_use_id": "legacy-use",
        "request_digest": "legacy-digest",
        "tool": "Bash",
        "cwd": "/workspace/project",
        "command": "printf legacy",
        "classification": "suspicious",
        "reason": "legacy reason",
        "general_rubric_digest": "legacy-general",
        "owner_rubric_digest": null,
        "role": "unknown",
        "loop_name": null,
        "stale_session": false,
        "domain_rubric_digest": null,
        "model_status": "success"
    });
    let journal_path = root.join("escalations.jsonl");
    let mut bytes = serde_json::to_vec(&value).expect("legacy fixture serializes");
    bytes.push(b'\n');
    fs::write(&journal_path, bytes).expect("legacy fixture is written");
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600))
        .expect("legacy journal is private");

    let review = load_review(&root).expect("legacy record remains reviewable");
    assert_eq!(review.escalations().len(), 1);
    assert!(
        review
            .render()
            .contains("scope=legacy-unscoped mode=legacy")
    );
    assert!(matches!(
        Journal::from_state_root(&root).append_disposition(
            &adjudicator(),
            "legacy-event",
            DispositionOutcome::AdjudicatedApproved,
            DispositionDetail::ApprovedRequestDigest("legacy-digest".to_owned())
        ),
        Err(JournalError::UnknownEventId)
    ));
}

/// ´test:crate:journal-lock-keeps-sixteen-thread-appends-intact´
#[test]
fn journal_lock_keeps_sixteen_thread_appends_intact() {
    let directory = FixtureDirectory::new("concurrent");
    let root = directory.state_root();
    let mut workers = Vec::new();
    for index in 0..16 {
        let journal = Journal::from_state_root(&root);
        workers.push(thread::spawn(move || {
            journal.append_test_escalation(&format!("printf {index}"), "fixture reason")
        }));
    }
    for worker in workers {
        worker
            .join()
            .expect("journal worker does not panic")
            .expect("journal worker appends");
    }
    let records = lines(&root);
    assert_eq!(records.len(), 16);
    let mut event_ids = records
        .iter()
        .map(|record| record["event_id"].as_str().expect("event id"))
        .collect::<Vec<_>>();
    event_ids.sort_unstable();
    event_ids.dedup();
    assert_eq!(event_ids.len(), 16);
}

/// ´test:crate:journal-appends-every-owner-disposition-and-refuses-a-second´
#[test]
fn journal_appends_every_owner_disposition_and_refuses_a_second() {
    let cases = [
        (
            DispositionOutcome::AdjudicatedRuleAdded,
            DispositionDetail::Rule("owner-rule-1".to_owned()),
        ),
        (
            DispositionOutcome::AdjudicatedRejected,
            DispositionDetail::Rejection("request is not authorized".to_owned()),
        ),
        (
            DispositionOutcome::CorrectedAndRerun,
            DispositionDetail::CorrectedRequestDigest("a".repeat(64)),
        ),
    ];
    for (index, (outcome, detail)) in cases.into_iter().enumerate() {
        let (directory, journal, event_id) = fixture_with_escalation(&format!("outcome-{index}"));
        journal
            .append_disposition(&adjudicator(), &event_id, outcome, detail)
            .expect("first disposition is appended");
        let records = lines(&directory.state_root());
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["event"], "disposition");
        assert_eq!(records[1]["outcome"], outcome.as_str());
        assert!(matches!(
            journal.append_disposition(
                &adjudicator(),
                &event_id,
                DispositionOutcome::AdjudicatedRejected,
                DispositionDetail::Rejection("duplicate".to_owned())
            ),
            Err(JournalError::AlreadyAdjudicated)
        ));
    }
}

/// ´test:crate:journal-disposition-skips-unrelated-malformed-lines´
#[test]
fn journal_disposition_skips_unrelated_malformed_lines() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, journal, event_id) = fixture_with_escalation("malformed-before-mark");
    let path = directory.state_root().join("escalations.jsonl");
    OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(b"{not-json}\n{}\n")?;
    journal.append_disposition(
        &adjudicator(),
        &event_id,
        DispositionOutcome::AdjudicatedRejected,
        DispositionDetail::Rejection("unrelated malformed lines are skipped".to_owned()),
    )?;
    let bytes = fs::read(path)?;
    let parseable_records = bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .collect::<Vec<_>>();
    assert_eq!(parseable_records.len(), 3);
    let journal_records = parseable_records
        .iter()
        .filter(|record| record.get("event").is_some())
        .collect::<Vec<_>>();
    assert_eq!(journal_records.len(), 2);
    assert_eq!(journal_records[1]["event"], "disposition");
    Ok(())
}

/// ´test:crate:journal-request-digest-is-canonical-and-shape-sensitive´
#[test]
fn journal_request_digest_is_canonical_and_shape_sensitive() {
    let digest = request_digest("Bash", "/workspace/project", "printf fixture");
    assert_eq!(digest.len(), 64);
    assert_eq!(
        digest,
        request_digest("Bash", "/workspace/project", "printf fixture")
    );
    assert_ne!(
        digest,
        request_digest("Bash", "/workspace/project", "printf other")
    );
    assert_ne!(
        request_digest("a", "bc", "same-command"),
        request_digest("ab", "c", "same-command")
    );
}

/// DELAY: a lock this short can only be refused, and the refusal is the subject of the tests that
/// ask for it, so load can make the refusal arrive later but never turn it into a success.
const REFUSED_LOCK_WAIT: Duration = Duration::from_millis(5);

/// WAIT: the tests that recover a stale lock have to finish the steal inside this budget, which they
/// never spend when the steal lands, so it is sized for the slowest machine the suite runs on. Five
/// milliseconds was enough on an idle machine and turned a successful recovery into an exhausted
/// deadline under load.
const STEAL_RECOVERY_WAIT: Duration = Duration::from_secs(10);

fn fixture_with_lock(
    name: &str,
    pid: u32,
    modified: Option<std::time::SystemTime>,
    wait: Duration,
) -> Result<(FixtureDirectory, Journal, PathBuf), Box<dyn std::error::Error>> {
    fixture_with_lock_contents(name, format!("{pid}\n").as_bytes(), modified, wait)
}

fn fixture_with_lock_contents(
    name: &str,
    contents: &[u8],
    modified: Option<std::time::SystemTime>,
    wait: Duration,
) -> Result<(FixtureDirectory, Journal, PathBuf), Box<dyn std::error::Error>> {
    let fixture = FixtureDirectory::new(name);
    let root = fixture.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let path = root.join("escalations.lock");
    fs::write(&path, contents)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    if let Some(modified) = modified {
        File::options()
            .write(true)
            .open(&path)?
            .set_times(FileTimes::new().set_modified(modified))?;
    }
    let mut journal = Journal::from_state_root(&root);
    // The caller names the class: a refusal is the subject of the test that asks for it, a recovery
    // is an outcome the budget has to leave room for.
    journal.set_test_lock_wait(wait);
    Ok((fixture, journal, path))
}

/// ´test:crate:journal-refuses-a-dead-but-fresh-lock´
#[test]
fn journal_refuses_a_dead_but_fresh_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (_fixture, journal, path) =
        fixture_with_lock("dead-fresh", u32::MAX, None, REFUSED_LOCK_WAIT)?;
    let error = journal
        .append_test_escalation("printf blocked", "fixture reason")
        .err()
        .ok_or("dead fresh lock unexpectedly allowed an append")?;
    assert!(matches!(&error, JournalError::Lock { .. }));
    assert!(error.to_string().contains(&path.display().to_string()));
    assert!(path.exists());
    Ok(())
}

/// ´test:crate:journal-refuses-an-old-but-live-lock´
#[test]
fn journal_refuses_an_old_but_live_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (_fixture, journal, path) = fixture_with_lock(
        "live-old",
        std::process::id(),
        Some(UNIX_EPOCH),
        REFUSED_LOCK_WAIT,
    )?;
    let error = journal
        .append_test_escalation("printf blocked", "fixture reason")
        .err()
        .ok_or("live old lock unexpectedly allowed an append")?;
    assert!(matches!(&error, JournalError::Lock { .. }));
    assert!(error.to_string().contains(&path.display().to_string()));
    assert!(path.exists());
    Ok(())
}

/// ´test:crate:journal-steals-a-dead-and-old-lock´
#[test]
fn journal_steals_a_dead_and_old_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, journal, path) =
        fixture_with_lock("dead-old", u32::MAX, Some(UNIX_EPOCH), STEAL_RECOVERY_WAIT)?;
    journal.append_test_escalation("printf recovered", "fixture reason")?;
    assert_eq!(lines(&fixture.state_root()).len(), 1);
    assert!(!path.exists());
    Ok(())
}

/// ´test:crate:journal-steals-an-empty-and-old-lock´
#[test]
fn journal_steals_an_empty_and_old_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, journal, path) =
        fixture_with_lock_contents("empty-old", b"", Some(UNIX_EPOCH), STEAL_RECOVERY_WAIT)?;
    assert_eq!(fs::metadata(&path)?.len(), 0);

    journal.append_test_escalation("printf recovered", "fixture reason")?;

    assert_eq!(lines(&fixture.state_root()).len(), 1);
    assert!(!path.exists());
    Ok(())
}

/// ´test:crate:journal-steals-every-garbage-and-old-lock-content-shape´
#[test]
fn journal_steals_every_garbage_and_old_lock_content_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: [(&str, &[u8]); 3] = [
        ("alphabetic", b"abc"),
        ("negative", b"-1"),
        ("invalid-utf8", &[0xff]),
    ];
    for (name, contents) in cases {
        let (fixture, journal, path) =
            fixture_with_lock_contents(name, contents, Some(UNIX_EPOCH), STEAL_RECOVERY_WAIT)?;
        journal.append_test_escalation("printf recovered", "fixture reason")?;
        assert_eq!(lines(&fixture.state_root()).len(), 1);
        assert!(!path.exists());
    }
    Ok(())
}

/// ´test:crate:journal-reaps-only-dead-and-old-orphaned-steal-claims´
#[test]
fn journal_reaps_only_dead_and_old_orphaned_steal_claims() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = FixtureDirectory::new("orphaned-steal-claims");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let dead_old = root.join(format!("escalations.lock.steal.{}.1-0", u32::MAX));
    let dead_fresh = root.join(format!("escalations.lock.steal.{}.2-0", u32::MAX));
    let live_old = root.join(format!("escalations.lock.steal.{}.3-0", std::process::id()));
    for path in [&dead_old, &dead_fresh, &live_old] {
        fs::write(path, b"fixture claim\n")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    for path in [&dead_old, &live_old] {
        File::options()
            .write(true)
            .open(path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH))?;
    }

    Journal::from_state_root(&root).append_test_escalation("printf fixture", "fixture reason")?;

    assert!(!dead_old.exists());
    assert!(dead_fresh.exists());
    assert!(live_old.exists());
    assert_eq!(lines(&root).len(), 1);
    Ok(())
}

/// ´test:crate:journal-owner-probe-name-includes-pid-nanoseconds-and-sequence´
#[test]
fn journal_owner_probe_name_includes_pid_nanoseconds_and_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("owner-probe-name");
    let path = test_owner_probe_path(&directory.state_root())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("probe name is not UTF-8")?;
    let prefix = format!(".permission-triage-owner-probe.{}.", std::process::id());
    let identity = name
        .strip_prefix(&prefix)
        .ok_or("probe name does not contain the process id")?;
    let (nanos, sequence) = identity
        .split_once('-')
        .ok_or("probe name does not separate time and sequence")?;
    assert!(!nanos.is_empty() && nanos.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!sequence.is_empty() && sequence.bytes().all(|byte| byte.is_ascii_digit()));
    Ok(())
}

/// ´test:crate:journal-reaps-only-dead-and-old-orphaned-owner-probes´
#[test]
fn journal_reaps_only_dead_and_old_orphaned_owner_probes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = FixtureDirectory::new("orphaned-owner-probes");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let dead_old = root.join(format!(".permission-triage-owner-probe.{}.1-0", u32::MAX));
    let dead_fresh = root.join(format!(".permission-triage-owner-probe.{}.2-0", u32::MAX));
    let legacy_dead_old = root.join(format!(".permission-triage-owner-probe.{}-4", u32::MAX));
    let live_old = root.join(format!(
        ".permission-triage-owner-probe.{}.3-0",
        std::process::id()
    ));
    for path in [&dead_old, &dead_fresh, &legacy_dead_old, &live_old] {
        fs::write(path, b"")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    for path in [&dead_old, &legacy_dead_old, &live_old] {
        File::options()
            .write(true)
            .open(path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH))?;
    }

    Journal::from_state_root(&root).append_test_escalation("printf fixture", "fixture reason")?;

    assert!(!dead_old.exists());
    assert!(dead_fresh.exists());
    assert!(!legacy_dead_old.exists());
    assert!(live_old.exists());
    assert_eq!(lines(&root).len(), 1);
    Ok(())
}

/// ´test:crate:journal-skips-an-unavailable-opportunistic-reaper-scan´
#[test]
fn journal_skips_an_unavailable_opportunistic_reaper_scan() {
    let directory = FixtureDirectory::new("reaper-read-dir-failure");
    let root = directory.state_root();
    let mut journal = Journal::from_state_root(&root);
    journal.set_test_reap_read_dir_failure();

    journal
        .append_test_escalation("printf fixture", "fixture reason")
        .expect("lock acquisition proceeds after the opportunistic scan fails");

    assert_eq!(lines(&root).len(), 1);
    assert!(!root.join("escalations.lock").exists());
}

/// ´test:crate:journal-skips-one-failed-orphan-and-continues-reaping´
#[test]
fn journal_skips_one_failed_orphan_and_continues_reaping() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = FixtureDirectory::new("reaper-entry-failure");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let skipped_name = format!("escalations.lock.steal.{}.1-0", u32::MAX);
    let skipped = root.join(&skipped_name);
    let reaped = root.join(format!("escalations.lock.steal.{}.2-0", u32::MAX));
    for path in [&skipped, &reaped] {
        fs::write(path, b"fixture claim\n")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        File::options()
            .write(true)
            .open(path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH))?;
    }
    let mut journal = Journal::from_state_root(&root);
    journal.set_test_reap_entry_failure(skipped_name.into());

    journal.append_test_escalation("printf fixture", "fixture reason")?;

    assert!(skipped.exists());
    assert!(!reaped.exists());
    assert_eq!(lines(&root).len(), 1);
    Ok(())
}

/// ´test:crate:journal-stale-steal-retries-not-found-and-names-genuine-failures´
#[test]
fn journal_stale_steal_retries_not_found_and_names_genuine_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureDirectory::new("steal-errors");
    let root = fixture.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let path = root.join("escalations.lock");
    assert_eq!(steal_stale_lock(&path)?, StealOutcome::Retry);

    fs::create_dir(&path)?;
    let error = steal_stale_lock(&path)
        .err()
        .ok_or("invalid lock path unexpectedly entered retry")?;
    assert!(matches!(error, JournalError::Lock { .. }));
    assert!(error.to_string().contains(&path.display().to_string()));
    Ok(())
}

/// ´test:crate:journal-lock-guard-cleans-up-an-acquire-time-validation-failure´
#[test]
fn journal_lock_guard_cleans_up_an_acquire_time_validation_failure() {
    let directory = FixtureDirectory::new("lock-validation-failure");
    let root = directory.state_root();
    let lock = root.join("escalations.lock");
    let mut journal = Journal::from_state_root(&root);
    journal.set_test_lock_validation_failure();
    assert!(
        journal
            .append_test_escalation("printf validation", "fixture reason")
            .is_err()
    );
    assert!(!lock.exists());
}

/// ´test:crate:journal-lock-guard-waits-for-its-restored-lock-path´
#[test]
fn journal_lock_guard_waits_for_its_restored_lock_path() -> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("restored-lock-release");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    // Prove the retry path: both metadata checks observe absence, restoration
    // signals completion, then the guard observes ownership and removes its path.
    // The release clock is synthetic. This does not cover restoration between
    // the two metadata checks; the two-stealer fixture below covers that ordering.
    assert!(test_lock_guard_restored_after(&root)?);
    Ok(())
}

/// ´test:crate:journal-two-stealers-restore-during-release´
#[test]
fn journal_two_stealers_restore_during_release() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, _, _) = fixture_with_lock(
        "two-stealers-release",
        u32::MAX,
        Some(UNIX_EPOCH),
        STEAL_RECOVERY_WAIT,
    )?;
    assert!(crate::journal::test_two_stealers_restore_during_release(
        &directory.state_root()
    )?);
    Ok(())
}

/// ´test:crate:journal-real-acquire-retries-not-found-with-a-sleep´
#[test]
fn journal_real_acquire_retries_not_found_with_a_sleep() -> Result<(), Box<dyn std::error::Error>> {
    let directory = FixtureDirectory::new("lock-not-found-retry");
    let root = directory.state_root();
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let lock = root.join("escalations.lock");
    fs::write(&lock, format!("{}\n", std::process::id()))?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    let mut journal = Journal::from_state_root(&root);
    // WAIT: the acquire must survive one vanished lock path, and the retry is one fixed poll apart,
    // so a longer budget adds nothing to a passing run and only stops a descheduled retry from
    // reading as a lock that could not be taken. The poll count below is what states the retry.
    journal.set_test_lock_wait(Duration::from_secs(10));
    journal.set_test_lock_vanish_before_open();
    journal.append_test_escalation("printf retry", "fixture reason")?;
    assert_eq!(
        journal.test_lock_acquire_polls(),
        2,
        "one vanished lock path must cause exactly one slept retry"
    );
    assert!(!lock.exists());
    Ok(())
}

/// ´test:crate:journal-lock-budget-clamps-low-middle-and-high-remaining-time´
#[test]
fn journal_lock_budget_clamps_low_middle_and_high_remaining_time() {
    // PIN: arguments and results of a pure clamp, with no clock and nothing to wait for, so machine
    // load cannot reach them.
    assert_eq!(lock_budget(Duration::ZERO), Duration::from_millis(10));
    assert_eq!(lock_budget(Duration::from_secs(2)), Duration::from_secs(1));
    assert_eq!(lock_budget(Duration::from_secs(20)), Duration::from_secs(4));
}

fn adjudicator() -> crate::CallerRole {
    let entries = std::collections::BTreeMap::from([(
        "orchestration.env".to_owned(),
        b"LOOP_NAME=orchestration\nLOOP_CWD=/workspace/project\nLOOP_SID=main\n".to_vec(),
    )]);
    let registry = crate::parse_registry(b"orchestration.env\n", &entries);
    crate::resolve_role(
        Some(&registry),
        4_000_000_000,
        "main",
        "/workspace/project",
        None,
        false,
    )
}

/// ´test:crate:request-collection-and-legacy-dispositions-share-one-commit´
#[test]
#[allow(clippy::too_many_lines)]
fn request_collection_and_legacy_dispositions_share_one_commit() {
    let (directory, _, event_id) = fixture_with_escalation("collection");
    let root = directory.state_root();
    let entries = std::collections::BTreeMap::from([("orchestration.env".to_owned(), format!("LOOP_NAME=orchestration\nLOOP_CWD=/workspace/project\nLOOP_SID=main\nLOOP_STATE_ROOT={}\n", root.display()).into_bytes())]);
    let registry = crate::parse_registry(b"orchestration.env\n", &entries);
    let caller = crate::resolve_role(
        Some(&registry),
        4_000_000_000,
        "main",
        "/workspace/project",
        None,
        false,
    );
    assert!(caller.is_orchestrator());
    let journal = Journal::from_registered_root(&root, Scope::Loop).expect("registered journal");
    let id = request_core::request_id(event_id.as_bytes());
    let original = journal.read().expect("original bytes");
    let listing = journal
        .requests(&crate::CallerRole::Unknown, "list", None, None, true)
        .expect("listing");
    assert_eq!(listing["requests"][0]["id"], id);
    assert_eq!(journal.read().expect("read unchanged"), original);
    let mark = json!({"schema":1,"items":[{"id":id,"mark_for_review":true}]});
    assert!(
        journal
            .requests(
                &crate::CallerRole::Unknown,
                "triage",
                Some(&mark),
                None,
                false
            )
            .is_err()
    );
    assert_eq!(journal.read().expect("denied unchanged"), original);
    let bad = json!({"schema":1,"items":[{"id":id,"mark_for_review":true},{"id":"f".repeat(64),"mark_for_review":true}]});
    assert!(
        journal
            .requests(&caller, "triage", Some(&bad), None, false)
            .is_err()
    );
    assert_eq!(journal.read().expect("batch unchanged"), original);
    assert!(!root.join(".requests-transaction.lock").exists());
    let door_id = "d".repeat(64);
    let door = request_core::Request::filed(
        door_id.clone(),
        "door-after-effect".to_owned(),
        json!({"source_id":"run:d","record":{"id":"run:d"}}),
        "worker".to_owned(),
        "run".to_owned(),
        1,
    );
    let mixed = json!({"schema":1,"records":[door],"document":{"schema":1,"items":[{"id":door_id,"mark_for_review":true},{"id":id,"mark_for_review":true}]},"id":null,"pending":false,"now_ns":100,"expected":null,"publication":null});
    assert!(
        journal
            .owner_transaction(
                &crate::CallerRole::Unknown,
                "triage",
                &serde_json::to_vec(&mixed).expect("mixed batch"),
                false
            )
            .is_err()
    );
    assert_eq!(
        journal.read().expect("authority refusal unchanged"),
        original
    );
    let mixed_preview = journal
        .owner_transaction(
            &caller,
            "triage",
            &serde_json::to_vec(&mixed).expect("mixed batch"),
            false,
        )
        .expect("authorized mixed preview");
    assert_eq!(mixed_preview["result"]["marked"], 2);
    assert_eq!(journal.read().expect("preview unchanged"), original);
    journal
        .requests(&caller, "triage", Some(&mark), None, false)
        .expect("marked");
    let review = journal
        .requests(&caller, "review", None, Some(&id), false)
        .expect("reviewed");
    let snapshot = journal.read().expect("before adjudication");
    let mut decision = json!({"schema":1,"id":id,"review_id":"stale","decision":{"answer":{"outcome":"adjudicated-rejected"},"reason":"fixture refused"}});
    assert!(
        journal
            .requests(&caller, "adjudicate", Some(&decision), None, false)
            .is_err()
    );
    assert_eq!(journal.read().expect("stale unchanged"), snapshot);
    decision["review_id"] = review["review"]["review_id"].clone();
    journal
        .requests(&caller, "adjudicate", Some(&decision), None, false)
        .expect("adjudicated");
    assert_eq!(
        journal
            .requests(&caller, "list", None, None, false)
            .expect("list")["requests"][0]["state"],
        "adjudicated"
    );
    assert_eq!(
        journal
            .requests(&caller, "list", None, None, true)
            .expect("pending")["requests"]
            .as_array()
            .expect("rows")
            .as_slice(),
        [] as [Value; 0]
    );
    assert!(
        journal
            .append_disposition(
                &caller,
                &event_id,
                DispositionOutcome::AdjudicatedRejected,
                DispositionDetail::Rejection("duplicate".to_owned())
            )
            .is_err()
    );
    let legacy = load_review(&root).expect("legacy review");
    assert_eq!(legacy.malformed_lines(), 0);
    assert_eq!(
        legacy.escalations()[0].outcome(),
        Some("adjudicated-rejected")
    );
    assert_eq!(
        lines(&root)
            .iter()
            .filter(|row| row["event"] == "disposition")
            .count(),
        1
    );
    journal
        .append_test_escalation("printf second", "second source")
        .expect("second escalation");
    let second = lines(&root)
        .into_iter()
        .rfind(|row| row["event"] == "escalated")
        .expect("second source")["event_id"]
        .as_str()
        .expect("source id")
        .to_owned();
    journal
        .append_disposition(
            &caller,
            &second,
            DispositionOutcome::AdjudicatedRejected,
            DispositionDetail::Rejection("old path".to_owned()),
        )
        .expect("legacy writer remains effective");
    let listing = journal
        .requests(&caller, "list", None, None, false)
        .expect("reconcile old disposition");
    assert!(
        listing["requests"]
            .as_array()
            .expect("rows")
            .iter()
            .any(
                |row| row["id"] == request_core::request_id(second.as_bytes())
                    && row["state"] == "triage-decided"
            )
    );
}

/// ´test:crate:registered-journal-read-rejects-a-foreign-owner´
#[test]
fn registered_journal_read_rejects_a_foreign_owner() {
    let directory = FixtureDirectory::new("registered-foreign-owner");
    let root = directory.state_root();
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let actual = fs::metadata(&root).expect("metadata").uid();
    let effective = actual.wrapping_add(1);
    for scope in [crate::request::Scope::Loop, crate::request::Scope::Estate] {
        let mut journal = Journal::from_registered_root(&root, scope).expect("registered root");
        journal.set_test_effective_uid(effective);
        assert!(
            matches!(journal.read(), Err(JournalError::RootOwner { actual: observed, effective: expected }) if observed == actual && expected == effective)
        );
    }
    assert_eq!(fs::read_dir(root).expect("unchanged root").count(), 0);
}
