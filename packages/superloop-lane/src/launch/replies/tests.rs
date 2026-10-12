use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

struct Fixture {
    _temp: tempfile::TempDir,
    _namespace: home::PrivateHomeGuard,
    owner_home: PathBuf,
    root: PathBuf,
    runs: OwnedFd,
    plan: crate::plan::Plan,
    record: Value,
    directory: PathBuf,
    owner: u32,
    worker: u32,
    loop_uid: u32,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        FIXTURE_WRITER.with(|writer| writer.set(None));
        TEST_OWNERS.with(|owners| owners.borrow_mut().clear());
    }
}

impl Fixture {
    fn new() -> Self {
        TEST_OWNERS.with(|owners| owners.borrow_mut().clear());
        let temp = tempfile::tempdir().expect("TMPDIR fixture");
        let owner_home = temp.path().join("owner");
        let root = owner_home.join("runs");
        let driver_dir = root.join("R");
        let directory = driver_dir.join("round");
        let worker_home = owner_home.join("worker");
        for path in [
            &owner_home,
            &root,
            &driver_dir,
            &directory,
            &worker_home,
            &worker_home.join(".local"),
            &worker_home.join(".local/outbox"),
        ] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let owner = Uid::effective().as_raw();
        let worker = if owner == 3000 { 3001 } else { 3000 };
        let loop_uid = if owner == 2000 { 41001 } else { 2000 };
        // Inject stat and writer identities only; these tests do not claim kernel uid isolation.
        FIXTURE_WRITER.with(|writer| writer.set(Some(owner)));
        map_identity(&driver_dir, loop_uid, loop_uid);
        map_identity(&directory, loop_uid, loop_uid);
        let outbox = worker_home.join(".local/outbox");
        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o750)).expect("outbox mode");
        map_identity(&outbox, worker, loop_uid);
        let plan = crate::plan::Plan {
            home: worker_home,
            driver_dir: driver_dir.clone(),
            letter: PathBuf::new(),
            document: json!({}),
        };
        let record = json!({"schema":1,"loop":"alpha","run":"R","worker_uid":worker,
            "plan":{"home":plan.home,"driver_dir":driver_dir,"paths":[{"path":plan.home,"uid":loop_uid,"gid":loop_uid},{"path":driver_dir,"kind":"directory","uid":loop_uid,"gid":loop_uid}]},
            "rounds":[{"step":"work","driver_dir":directory}]});
        let home_fd = File::open(&owner_home).expect("home");
        let runs: OwnedFd = File::open(&root).expect("runs").into();
        let namespace =
            home::activate_private_launch(&owner_home, &home_fd, &root, &runs, None, owner)
                .expect("inherited namespace anchors");
        Self {
            _temp: temp,
            _namespace: namespace,
            owner_home,
            root,
            runs,
            plan,
            record,
            directory,
            owner,
            worker,
            loop_uid,
        }
    }

    fn post(&self, name: &str, body: &[u8]) {
        self.publish(name, body);
        self.record_observation(name, body.len());
    }

    fn publish(&self, name: &str, body: &[u8]) {
        let raw = decode_name(name).expect("published name");
        let outbox = self.plan.home.join(".local/outbox");
        let temporary = outbox.join(".tmp-reply");
        fs::write(&temporary, body).expect("staging body");
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .expect("worker private mode");
        map_owner(&temporary, self.worker);
        let name_path = std::ffi::OsStr::from_bytes(&raw);
        fs::rename(&temporary, outbox.join(name_path)).expect("publication");
    }

    fn record_observation(&self, name: &str, bytes: usize) {
        let path = self.directory.join("letters.jsonl");
        let mut existing = fs::read(&path).unwrap_or_default();
        let revision = existing
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .filter(|row| row["name"] == name)
            .filter_map(|row| row["revision"].as_u64())
            .max()
            .unwrap_or(0)
            + 1;
        let at = format!("2026-01-01T00:00:{revision:02}Z");
        let row = json!({"round":"work","box":"outbox","name":name,"bytes":bytes,"kind":"file","state":"observed","revision":revision,"at":at,"identity":["outbox",name,revision,at]});
        existing.extend_from_slice(format!("{row}\n").as_bytes());
        fs::write(&path, existing).expect("journal");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("journal mode");
        map_identity(&path, self.loop_uid, self.loop_uid);
    }

    fn watcher(&self) -> lane_lifecycle::MailboxWatcher {
        fs::create_dir(self.plan.home.join(".local/inbox")).expect("inbox");
        let meta = fs::metadata(&self.plan.home).expect("actual home metadata");
        let plan = json!({"home":self.plan.home,"driver_dir":self.plan.driver_dir,
            "worker_uid":meta.uid(),"paths":[{"path":self.plan.home,"uid":meta.uid(),
            "gid":meta.gid(),"mode":format!("{:04o}",meta.mode() & 0o7777)}]});
        let path = self.plan.driver_dir.join("plan.json");
        fs::write(&path, plan.to_string()).expect("watcher's recorded plan");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("plan mode");
        lane_lifecycle::MailboxWatcher::for_round(&self.directory, "work")
            .expect("real watcher")
            .expect("recorded home")
    }

    fn map_journal(&self) {
        // Model the private launch's restrictive creation mode as well as its injected uid.
        fs::set_permissions(
            self.directory.join("letters.jsonl"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private journal mode");
        map_identity(
            &self.directory.join("letters.jsonl"),
            self.loop_uid,
            self.loop_uid,
        );
    }

    fn context(&self, name: &str) -> Result<Context, LaneError> {
        follow::validate_record(&self.plan, &self.record, "alpha", "R")?;
        Context::open(
            &self.plan,
            &self.record,
            &self.runs,
            &self.root,
            self.owner,
            name,
        )
    }

    fn command(
        &self,
        name: &str,
        dry_run: bool,
        output: &mut impl Write,
    ) -> Result<String, LaneError> {
        let mut words = vec!["alpha".into(), "R".into(), name.into()];
        if dry_run {
            words.push("--dry-run".into());
        }
        let request = Request::parse(&words)?;
        self.command_request(&request, output)
    }

    fn command_request(
        &self,
        request: &Request,
        output: &mut impl Write,
    ) -> Result<String, LaneError> {
        super::super::publish_reservation(
            &super::super::reservation_path(&self.root, "R"),
            &self.record,
        )?;
        let (_, reservation) = checkout::read_record_bound(&self.runs, "R", self.owner)?;
        let mut records = Vec::new();
        deliver(request, output, &mut records, |expected| {
            let argv = private_argv(
                &self.owner_home,
                request,
                &reservation,
                if expected.is_some() {
                    "--receipt"
                } else {
                    "--prepare"
                },
                expected,
            )?;
            let private = PrivateRequest::parse(&argv)?;
            FIXTURE_WRITER.with(|writer| writer.set(Some(self.owner)));
            private_bound(&private, self.owner, true)
        })?;
        Ok(String::from_utf8(records).expect("record UTF-8"))
    }

    fn receipts(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(self.directory.join(RECEIPTS)) else {
            return Vec::new();
        };
        entries
            .map(|entry| {
                entry
                    .expect("receipt")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }
}

use std::os::unix::ffi::OsStrExt as _;

fn map_owner(path: &Path, uid: u32) {
    let meta = fs::metadata(path).expect("fixture inode");
    map_identity(path, uid, observed_gid(&meta));
}

fn map_identity(path: &Path, uid: u32, gid: u32) {
    let meta = fs::metadata(path).expect("fixture inode");
    TEST_OWNERS.with(|owners| {
        owners.borrow_mut().insert(
            (meta.dev(), meta.ino()),
            (
                uid,
                gid,
                File::open(path).expect("hold synthetic identity inode"),
            ),
        )
    });
}

/// ´test:unit:box-run-resolves-recorded-outbox´
#[test]
fn box_run_resolves_recorded_outbox() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply\0\xff\n");
    let mut output = Vec::new();
    let record = fixture
        .command("work.md", false, &mut output)
        .expect("read reply");
    assert_eq!(output, b"reply\0\xff\n");
    assert!(
        record.starts_with(
            "READ-REPLY name=work.md bytes=8 revision=1 at=2026-01-01T00:00:01Z digest="
        )
    );
    assert!(record.contains("receipts=.reply-receipts"));
    assert_eq!(fixture.receipts().len(), 1);
    let meta = fs::metadata(fixture.directory.join(RECEIPTS)).expect("receipt directory");
    assert_eq!(observed_uid(&meta), fixture.loop_uid);
    assert!(!record.contains(" owner="));
    assert!(!record.contains(" mode="));
    assert_eq!(meta.mode() & 0o7777, 0o755);
    let receipt = fs::read(
        fixture
            .directory
            .join(RECEIPTS)
            .join(&fixture.receipts()[0]),
    )
    .expect("receipt");
    let value: Value = serde_json::from_slice(&receipt).expect("metadata record");
    assert!(value.get("body_hex").is_none());
    assert_eq!(value["reply"]["name"], "work.md");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("idempotent repeat");
    assert_eq!(fixture.receipts().len(), 1);
}

/// ´test:unit:shim-run-with-recorded-home-resolves-outbox´
#[test]
fn shim_run_with_recorded_home_resolves_outbox() {
    let mut fixture = Fixture::new();
    fixture.record["backend"] = json!("shim");
    fixture.post("work.md", b"shim reply\n");
    let mut output = Vec::new();
    fixture
        .command("work.md", false, &mut output)
        .expect("planned shim");
    assert_eq!(output, b"shim reply\n");
    assert_eq!(fixture.receipts().len(), 1);
}

/// ´test:unit:shim-without-recorded-home-does-not-claim-mailbox-coverage´
#[test]
fn shim_without_recorded_home_does_not_claim_mailbox_coverage() {
    let mut fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    fixture.record["plan"]
        .as_object_mut()
        .expect("plan")
        .remove("home");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("no recorded run")
            .kind,
        "read-reply-unplanned"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "fixture output closed",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// ´test:unit:failed-read-leaves-reply-unread´
#[test]
fn failed_read_leaves_reply_unread() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    assert_eq!(
        fixture
            .command("work.md", false, &mut BrokenOutput)
            .expect_err("broken stdout")
            .status,
        1
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
    let request = Request::parse(&["alpha".into(), "R".into(), "work.md".into()]).expect("request");
    let error = deliver(&request, &mut Vec::new(), &mut BrokenOutput, |expected| {
        assert!(expected.is_none(), "broken stderr must not acknowledge");
        fixture.context("work.md")?.execute(None, false)
    })
    .expect_err("broken record output");
    assert_eq!(error.status, 1);
    assert_eq!(fixture.receipts(), Vec::<String>::new());
    fs::remove_file(fixture.plan.home.join(".local/outbox/work.md")).expect("remove");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("absent")
            .kind,
        "read-reply-absent"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:replacement-does-not-inherit-read-receipt´
#[test]
fn replacement_does_not_inherit_read_receipt() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"first");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("first read");
    let original = fixture.receipts();
    let prepared = fixture
        .context("work.md")
        .expect("context")
        .execute(None, false)
        .expect("prepare");
    fixture.post("work.md", b"other");
    let changed = fixture
        .context("work.md")
        .expect("new context")
        .execute(prepared["identity"].as_str(), false)
        .expect_err("replacement before receipt");
    assert_eq!(changed.kind, "read-reply-changed");
    assert_eq!(fixture.receipts(), original);
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("new reply read");
    assert_eq!(fixture.receipts().len(), 2);
}

/// ´test:unit:staging-names-are-silent-and-names-cannot-inject-fields´
#[test]
fn staging_names_are_silent_and_names_cannot_inject_fields() {
    let fixture = Fixture::new();
    for name in [
        ".tmp-work",
        ".",
        "..",
        "bad%2Fname",
        "%00",
        "bad%",
        "bad name",
        "bad=name",
    ] {
        let error = fixture
            .command(name, false, &mut Vec::new())
            .expect_err("unpublished name");
        assert_eq!(error.kind, "read-reply-name");
    }
    fixture.post("work%20sender%3Dfake%0A.md", b"reply");
    let record = fixture
        .command("work%20sender%3Dfake%0A.md", false, &mut Vec::new())
        .expect("escaped name");
    assert_eq!(record.lines().count(), 1);
    assert!(!record.contains(" sender=fake"));
    assert!(record.contains("name=work%20sender%3Dfake%0A.md"));
}

/// ´test:unit:read-reply-dry-run-prints-body-and-counts-the-same-action´
#[test]
fn read_reply_dry_run_prints_body_and_counts_the_same_action() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let mut preview = Vec::new();
    let dry = fixture
        .command("work.md", true, &mut preview)
        .expect("dry run");
    assert!(!fixture.directory.join(RECEIPTS).exists());
    let mut output = Vec::new();
    let changed = fixture
        .command("work.md", false, &mut output)
        .expect("changing run");
    assert_eq!(preview, output);
    assert_eq!(dry.replace("dry_run=true", "dry_run=false"), changed);
}

/// ´test:unit:read-reply-compares-reader-and-worker-as-distinct-identities´
#[test]
fn read_reply_compares_reader_and_worker_as_distinct_identities() {
    let mut fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    assert_ne!(fixture.owner, fixture.worker);
    let reply = fixture.plan.home.join(".local/outbox/work.md");
    map_owner(&reply, fixture.loop_uid);
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("reader-owned reply refuses")
            .kind,
        "read-reply-owner"
    );
    map_owner(&reply, fixture.worker);
    fixture.record["worker_uid"] = json!(fixture.loop_uid);
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("same identities refuse")
            .kind,
        "read-reply-owner"
    );
}

/// ´test:unit:read-reply-refuses-unsafe-paths-custody-size-and-journal´
#[test]
fn read_reply_refuses_unsafe_paths_custody_size_and_journal() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let reply = fixture.plan.home.join(".local/outbox/work.md");
    fs::set_permissions(&reply, fs::Permissions::from_mode(0o644)).expect("mode");
    assert_eq!(
        fixture.context("work.md").err().expect("mode").kind,
        "read-reply-owner"
    );
    fs::set_permissions(&reply, fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(&reply, b"").expect("empty");
    assert_eq!(
        fixture.context("work.md").err().expect("empty").kind,
        "read-reply-size"
    );
    File::options()
        .write(true)
        .open(&reply)
        .expect("reply")
        .set_len(MAX_REPLY + 1)
        .expect("oversized");
    assert_eq!(
        fixture.context("work.md").err().expect("oversized").kind,
        "read-reply-size"
    );
    fs::remove_file(&reply).expect("remove");
    symlink("../outside", &reply).expect("link");
    assert_eq!(
        fixture.context("work.md").err().expect("link").kind,
        "read-reply-path"
    );
    fs::remove_file(&reply).expect("remove link");
    fixture.post("work.md", b"reply");
    let outbox = fixture.plan.home.join(".local/outbox");
    fs::set_permissions(&outbox, fs::Permissions::from_mode(0o770)).expect("unsafe dir");
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("unsafe directory")
            .kind,
        "read-reply-custody"
    );
    fs::set_permissions(&outbox, fs::Permissions::from_mode(0o750)).expect("restore");
    let journal = fixture.directory.join("letters.jsonl");
    for bytes in [b"{".as_slice(), b"bad\n", b"{}\n"] {
        fs::write(&journal, bytes).expect("journal");
        assert!(fixture.context("work.md").is_err());
    }
    fixture.post("work.md", b"reply");
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o666)).expect("unsafe journal");
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("journal custody")
            .kind,
        "read-reply-journal"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-refuses-changes-on-held-descriptors´
#[test]
fn read_reply_refuses_changes_on_held_descriptors() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"first");
    let context = fixture.context("work.md").expect("held reply");
    fixture.post("work.md", b"other");
    assert_eq!(
        context.execute(None, false).expect_err("replacement").kind,
        "read-reply-changed"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-refuses-malformed-protocol-and-receipt-custody´
#[test]
fn read_reply_refuses_malformed_protocol_and_receipt_custody() {
    let fixture = Fixture::new();
    assert_eq!(
        Request::parse(&[]).expect_err("usage").kind,
        "read-reply-usage"
    );
    assert_eq!(
        PrivateRequest::parse(&[]).expect_err("private usage").kind,
        "read-reply-private"
    );
    let request = Request::parse(&["alpha".into(), "R".into(), "work.md".into()]).expect("request");
    let mut argv = private_argv(
        &fixture.owner_home,
        &request,
        "reservation",
        "--prepare",
        None,
    )
    .expect("builder");
    argv[4] = "--wrong".into();
    assert_eq!(
        PrivateRequest::parse(&argv)
            .expect_err("private flags")
            .kind,
        "read-reply-private"
    );
    assert!(unhex("abc").is_err());
    assert!(unhex("zz").is_err());
    fixture.post("work.md", b"reply");
    fs::create_dir(fixture.directory.join(RECEIPTS)).expect("receipt directory");
    fs::set_permissions(
        fixture.directory.join(RECEIPTS),
        fs::Permissions::from_mode(0o777),
    )
    .expect("bad custody");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("receipt custody")
            .kind,
        "read-reply-custody"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-preserves-helper-refusals-and-rejects-bad-responses´
#[test]
fn read_reply_preserves_helper_refusals_and_rejects_bad_responses() {
    use std::os::unix::process::ExitStatusExt as _;
    for status in [1, 2] {
        let response = build::ChildResult {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: Vec::new(),
            stderr: b"read-reply-absent: missing reply".to_vec(),
        };
        let error = helper_response(&response).expect_err("helper failed");
        assert_eq!(i32::from(error.status), status);
        assert!(error.detail.contains("read-reply-absent"));
    }
    let response = build::ChildResult {
        status: std::process::ExitStatus::from_raw(0),
        stdout: b"invalid".to_vec(),
        stderr: Vec::new(),
    };
    assert_eq!(
        helper_response(&response).expect_err("bad JSON").kind,
        "read-reply-helper"
    );
    let request = Request::parse(&["alpha".into(), "R".into(), "work.md".into()]).expect("request");
    for response in [
        json!({}),
        json!({"body_hex":"00"}),
        json!({"body_hex":"00","identity":"bad"}),
    ] {
        assert_eq!(
            deliver(&request, &mut Vec::new(), &mut Vec::new(), |_| Ok(
                response.clone()
            ))
            .expect_err("malformed response")
            .kind,
            "read-reply-helper"
        );
    }
}

/// ´test:unit:read-reply-receipt-refuses-links-foreign-mode-and-conflicting-records´
#[test]
fn read_reply_receipt_refuses_links_foreign_mode_and_conflicting_records() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("read");
    let path = fixture
        .directory
        .join(RECEIPTS)
        .join(&fixture.receipts()[0]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("bad mode");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("mode")
            .kind,
        "read-reply-receipt"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(&path, b"{}").expect("bad record");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("record")
            .kind,
        "read-reply-changed"
    );
    fs::remove_file(&path).expect("remove receipt");
    symlink("unrelated", &path).expect("link");
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("link")
            .kind,
        "read-reply-path"
    );
}

/// ´test:unit:read-reply-refuses-stale-size-and-injected-journal-fields´
#[test]
fn read_reply_refuses_stale_size_and_injected_journal_fields() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let path = fixture.directory.join("letters.jsonl");
    let original: Value =
        serde_json::from_slice(&fs::read(&path).expect("journal")).expect("record");
    for (key, value, kind) in [
        ("bytes", json!(6), "read-reply-unobserved"),
        ("revision", json!(0), "read-reply-journal"),
        ("at", json!("now name=forged"), "read-reply-journal"),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        fs::write(&path, format!("{changed}\n")).expect("journal");
        assert_eq!(
            fixture
                .command("work.md", false, &mut Vec::new())
                .expect_err("invalid observation")
                .kind,
            kind
        );
    }
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-private-binding-refuses-changed-and-unplanned-runs´
#[test]
fn read_reply_private_binding_refuses_changed_and_unplanned_runs() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let request = Request::parse(&["alpha".into(), "R".into(), "work.md".into()]).expect("request");
    let path = super::super::reservation_path(&fixture.root, "R");
    super::super::publish_reservation(&path, &fixture.record).expect("reservation");
    let (_, identity) =
        checkout::read_record_bound(&fixture.runs, "R", fixture.owner).expect("identity");
    let argv =
        private_argv(&fixture.owner_home, &request, &identity, "--prepare", None).expect("builder");
    let mut private_request = PrivateRequest::parse(&argv).expect("parser");
    private_bound(&private_request, fixture.owner, false).expect("private read");
    private_request.owner_home = fixture.owner_home.join("elsewhere");
    assert_eq!(
        private_bound(&private_request, fixture.owner, false)
            .expect_err("home mismatch")
            .kind,
        "read-reply-private"
    );
    private_request.owner_home = fixture.owner_home.clone();
    private_request.reservation = "changed".into();
    assert_eq!(
        private_bound(&private_request, fixture.owner, false)
            .expect_err("changed record")
            .kind,
        "read-reply-changed"
    );
    for changed in [
        json!({"schema":1,"worker_uid":fixture.worker}),
        {
            let mut record = fixture.record.clone();
            record["plan"]["driver_dir"] = json!(fixture.root.join("S"));
            record
        },
        {
            let mut record = fixture.record.clone();
            record["plan"]
                .as_object_mut()
                .expect("plan")
                .remove("driver_dir");
            record
        },
        {
            let mut record = fixture.record.clone();
            record.as_object_mut().expect("record").remove("rounds");
            record
        },
    ] {
        super::super::publish_reservation(&path, &changed).expect("changed reservation");
        private_request.reservation =
            checkout::read_record_bound(&fixture.runs, "R", fixture.owner)
                .expect("identity")
                .1;
        assert_eq!(
            private_bound(&private_request, fixture.owner, false)
                .expect_err("unplanned")
                .kind,
            "read-reply-unplanned"
        );
    }
    fs::remove_file(path).expect("missing reservation");
    assert_eq!(
        private_bound(&private_request, fixture.owner, false)
            .expect_err("unplanned shim")
            .kind,
        "read-reply-unplanned"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:failed-receipt-publication-leaves-no-acknowledgement´
#[test]
fn failed_receipt_publication_leaves_no_acknowledgement() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    for stage in ["write", "sync", "verify", "rename", "directory-sync"] {
        RECEIPT_FAULT.with(|fault| fault.set(Some(stage)));
        let error = fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("publication fault");
        assert_eq!(error.status, 1);
        assert!(error.detail.contains(stage));
        assert_eq!(fixture.receipts(), Vec::<String>::new());
    }
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("retry after faults");
    assert_eq!(fixture.receipts().len(), 1);
}

/// ´test:unit:read-reply-separates-namespace-loop-and-worker-identities´
#[test]
fn read_reply_separates_namespace_loop_and_worker_identities() {
    let fixture = Fixture::new();
    assert_ne!(fixture.owner, fixture.loop_uid);
    assert_ne!(fixture.owner, fixture.worker);
    assert_ne!(fixture.loop_uid, fixture.worker);
    fixture.post("work.md", b"reply");
    let local = fixture.plan.home.join(".local");
    map_owner(&local, fixture.loop_uid);
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("local belongs to namespace owner")
            .kind,
        "read-reply-custody"
    );
    map_owner(&local, fixture.owner);
    map_owner(&fixture.directory, fixture.owner);
    assert!(fixture.context("work.md").is_err(), "round belongs to loop");
    map_owner(&fixture.directory, fixture.loop_uid);
    let journal = fixture.directory.join("letters.jsonl");
    map_owner(&journal, fixture.owner);
    assert_eq!(
        fixture
            .context("work.md")
            .err()
            .expect("journal belongs to loop")
            .kind,
        "read-reply-journal"
    );
    map_owner(&journal, fixture.loop_uid);
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("drop from namespace owner to loop");
    assert_eq!(
        FIXTURE_WRITER.with(std::cell::Cell::get),
        Some(fixture.loop_uid)
    );
    let prepared = fixture
        .context("work.md")
        .expect("context")
        .execute(None, false)
        .expect("prepare without drop");
    fixture
        .context("work.md")
        .expect("context")
        .execute(prepared["identity"].as_str(), false)
        .expect("already loop identity, no drop");
    fixture.post("second.md", b"second");
    let prepared = fixture
        .context("second.md")
        .expect("context")
        .execute(None, false)
        .expect("prepare");
    FIXTURE_WRITER.with(|writer| writer.set(Some(fixture.owner)));
    let error = fixture
        .context("second.md")
        .expect("context")
        .execute(prepared["identity"].as_str(), false)
        .expect_err("omitting drop cannot publish owner-owned receipt");
    assert_eq!(error.kind, "read-reply-receipt");
    assert_eq!(fixture.receipts().len(), 1);
}

/// ´test:unit:read-reply-refuses-loop-and-run-names´
#[test]
fn read_reply_refuses_loop_and_run_names() {
    for (words, kind) in [
        (["Bad", "R", "work.md"], "loop-name"),
        (["alpha", "../R", "work.md"], "run-name"),
    ] {
        let error = Request::parse(&words.map(str::to_owned)).expect_err("invalid name");
        assert_eq!(error.kind, kind);
        assert_eq!(error.status, 2);
    }
}

/// ´test:unit:read-reply-refuses-receipt-response-identity-mismatch´
#[test]
fn read_reply_refuses_receipt_response_identity_mismatch() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let request = Request::parse(&["alpha".into(), "R".into(), "work.md".into()]).expect("request");
    let mut output = Vec::new();
    let error = deliver(&request, &mut output, &mut Vec::new(), |expected| {
        if expected.is_some() {
            Ok(json!({"identity":"different"}))
        } else {
            fixture.context("work.md")?.execute(None, false)
        }
    })
    .expect_err("receipt response mismatch");
    assert_eq!(error.kind, "read-reply-changed");
    assert_eq!(error.status, 2);
    assert_eq!(output, b"reply");
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-failed-mkdirat-leaves-no-receipt´
#[test]
fn read_reply_failed_mkdirat_leaves_no_receipt() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let parent = File::open(fixture.directory.join("letters.jsonl")).expect("non-directory anchor");
    let error = receipt_directory(&parent, fixture.loop_uid).expect_err("mkdirat ENOTDIR");
    assert_eq!(error.kind, "read-reply-io");
    assert_eq!(error.status, 1);
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-staged-receipt-mismatch-leaves-no-acknowledgement´
#[test]
fn read_reply_staged_receipt_mismatch_leaves_no_acknowledgement() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    RECEIPT_FAULT.with(|fault| fault.set(Some("staged-mismatch")));
    let error = fixture
        .command("work.md", false, &mut Vec::new())
        .expect_err("staged custody differs");
    assert_eq!(error.kind, "read-reply-receipt");
    assert_eq!(error.status, 2);
    assert!(error.detail.contains("staged receipt identity differs"));
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-maximum-body-survives-real-child-capture´
#[test]
fn read_reply_maximum_body_survives_real_child_capture() {
    let fixture = Fixture::new();
    let body = vec![0xff; 1_000_000];
    fixture.post("work.md", &body);
    let prepared = fixture
        .context("work.md")
        .expect("context")
        .execute(None, false)
        .expect("prepare maximum reply");
    let response = serde_json::to_vec(&prepared).expect("response");
    assert!(response.len() > 2_000_000);
    assert!(response.len() < 2_097_152);
    let child = build::child(
        Path::new("/usr/bin/cat"),
        Vec::new(),
        &std::collections::BTreeMap::new(),
        &fixture.owner_home,
        10,
        "read-reply-cap-fixture",
    );
    let captured = build::run_child(&child, Some(&response)).expect("bounded child capture");
    assert!(captured.status.success());
    assert_eq!(captured.stdout, response);
    let request = Request::parse(&[
        "alpha".into(),
        "R".into(),
        "work.md".into(),
        "--dry-run".into(),
    ])
    .expect("request");
    let mut output = Vec::new();
    deliver(&request, &mut output, &mut Vec::new(), |_| {
        helper_response(&captured)
    })
    .expect("decode and deliver capture");
    assert_eq!(output, body);
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

fn range_request(offset: u64, length: u64, dry_run: bool) -> Request {
    let mut words = vec![
        "alpha".into(),
        "R".into(),
        "work.md".into(),
        "--offset".into(),
        offset.to_string(),
        "--length".into(),
        length.to_string(),
    ];
    if dry_run {
        words.push("--dry-run".into());
    }
    Request::parse(&words).expect("range request")
}

/// ´test:unit:read-reply-range-delivers-bounded-binary-bytes-without-receipts´
#[test]
fn read_reply_range_delivers_bounded_binary_bytes_without_receipts() {
    let fixture = Fixture::new();
    let mut body = vec![0xff; 1_000_002];
    body[1] = 0;
    body[1_000_001] = 42;
    fixture.post("work.md", &body);
    for dry_run in [false, true] {
        for (offset, length) in [(0, 1), (1, 1_000_000), (1_000_001, 1)] {
            let request = range_request(offset, length, dry_run);
            let mut output = Vec::new();
            let report = fixture
                .command_request(&request, &mut output)
                .expect("range delivery");
            let start = usize::try_from(offset).expect("offset");
            let end = usize::try_from(offset + length).expect("end");
            assert_eq!(output, body[start..end]);
            assert!(report.contains("total_bytes=1000002"));
            assert!(report.contains(&format!("offset={offset} length={length}")));
            assert!(report.contains(&format!("digest={}", hex(&Sha256::digest(&output)))));
            assert!(report.contains("receipts=none actions=0"));
            assert!(report.contains(" revision="));
            assert!(report.contains(" at="));
            assert!(!report.contains("at=invalid"));
            assert_eq!(fixture.receipts(), Vec::<String>::new());
        }
    }
    fixture.post("work.md", b"whole");
    fixture
        .command_request(&range_request(0, 5, false), &mut Vec::new())
        .expect("whole-sized range");
    assert_eq!(fixture.receipts(), Vec::<String>::new());
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("whole reply still acknowledges");
    assert_eq!(fixture.receipts().len(), 1);
}

/// ´test:unit:read-reply-range-refuses-malformed-overflow-and-out-of-file-bounds´
#[test]
fn read_reply_range_refuses_malformed_overflow_and_out_of_file_bounds() {
    assert_eq!(
        parse_range("0", "0").expect_err("empty range").detail,
        "length must contain 1 through 1000000 bytes"
    );
    assert_eq!(
        parse_range("0", "1000001").expect_err("large range").detail,
        "length must contain 1 through 1000000 bytes"
    );
    assert_eq!(
        parse_range("18446744073709551615", "1")
            .expect_err("overflow")
            .detail,
        "offset + length overflows u64"
    );
    for (suffix, kind) in [
        (vec!["--offset", "0"], "read-reply-usage"),
        (vec!["--length", "1"], "read-reply-usage"),
        (vec!["--offset", "-1", "--length", "1"], "read-reply-range"),
        (vec!["--offset", "+1", "--length", "1"], "read-reply-range"),
        (vec!["--offset", "0", "--length", "0"], "read-reply-range"),
        (
            vec!["--offset", "0", "--length", "1000001"],
            "read-reply-range",
        ),
        (
            vec!["--offset", "18446744073709551615", "--length", "1"],
            "read-reply-range",
        ),
        (
            vec!["--offset", "18446744073709551616", "--length", "1"],
            "read-reply-range",
        ),
        (vec!["--offset", "x", "--length", "1"], "read-reply-range"),
    ] {
        let words = ["alpha", "R", "work.md"]
            .into_iter()
            .chain(suffix)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            Request::parse(&words).expect_err("invalid range").kind,
            kind
        );
    }
    let fixture = Fixture::new();
    fixture.post("work.md", b"abc");
    for (offset, length) in [(3, 1), (4, 1), (0, 4), (2, 2)] {
        let mut output = Vec::new();
        assert_eq!(
            fixture
                .command_request(&range_request(offset, length, false), &mut output)
                .expect_err("overrun")
                .kind,
            "read-reply-range"
        );
        assert_eq!(output, Vec::<u8>::new());
    }
    fixture.post("work.md", b"");
    assert_eq!(
        fixture
            .command_request(&range_request(0, 1, false), &mut Vec::new())
            .expect_err("empty file")
            .kind,
        "read-reply-range"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:read-reply-range-preserves-custody-observation-and-replacement-checks´
#[test]
fn read_reply_range_preserves_custody_observation_and_replacement_checks() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"abcdef");
    let open = || {
        Context::open_range(
            &fixture.plan,
            &fixture.record,
            &fixture.runs,
            &fixture.root,
            fixture.owner,
            "work.md",
            Some((1, 2)),
        )
    };
    let held = open().expect("range context");
    let error = open()
        .expect("receipt context")
        .execute(Some(&"0".repeat(64)), false)
        .expect_err("range receipt guard");
    assert_eq!(error.kind, "read-reply-private");
    assert_eq!(
        error.detail,
        "range reads cannot publish whole-reply receipts"
    );
    let request = range_request(1, 2, false);
    let mut output = Vec::new();
    let mismatch = deliver(&request, &mut output, &mut Vec::new(), |_| {
        let mut response = open()?.execute(None, false)?;
        response["reply"]["offset"] = json!(0);
        Ok(response)
    })
    .expect_err("mismatched helper response");
    assert_eq!(mismatch.kind, "read-reply-helper");
    assert_eq!(
        mismatch.detail,
        "range response differs from requested bytes"
    );
    assert_eq!(output, [] as [u8; 0]);
    let inspect = private_argv(&fixture.owner_home, &request, "record", "--inspect", None)
        .expect("inspect vector");
    assert_eq!(
        PrivateRequest::parse(&inspect)
            .expect_err("range inspection")
            .detail,
        "range reads prepare bytes only; no receipt or inspection"
    );
    fixture.post("work.md", b"ghijkl");
    assert_eq!(
        held.execute(None, false).expect_err("replaced").kind,
        "read-reply-changed"
    );
    let path = fixture.plan.home.join(".local/outbox/work.md");
    fs::write(&path, b"changed without observation").expect("unobserved write");
    assert_eq!(
        open().err().expect("unobserved").kind,
        "read-reply-unobserved"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert_eq!(open().err().expect("custody").kind, "read-reply-owner");
    let request = range_request(1, 2, false);
    let argv = private_argv(
        &fixture.owner_home,
        &request,
        "record",
        "--receipt",
        Some(&"0".repeat(64)),
    )
    .expect("argv");
    assert_eq!(
        PrivateRequest::parse(&argv)
            .expect_err("range receipt")
            .kind,
        "read-reply-private"
    );
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:stale-inner-receipt-identity-refuses´
#[test]
fn stale_inner_receipt_identity_refuses() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("read");
    let path = fixture
        .directory
        .join(RECEIPTS)
        .join(&fixture.receipts()[0]);
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(&path).expect("receipt")).expect("metadata");
    receipt["identity"] = json!("0".repeat(64));
    fs::write(&path, receipt.to_string()).expect("stale identity");
    let saved = fs::read(&path).expect("stale bytes");
    let error = fixture
        .command("work.md", false, &mut Vec::new())
        .expect_err("stale receipt");
    assert_eq!(error.kind, "read-reply-changed");
    assert_eq!(error.status, 2);
    assert_eq!(fs::read(path).expect("preserved stale receipt"), saved);
}

/// ´test:unit:reader-publication-clears-monitor-handback´
#[test]
fn reader_publication_clears_monitor_handback() {
    let fixture = Fixture::new();
    let mut watcher = fixture.watcher();
    fixture.publish("work.md", b"reply");
    watcher
        .poll(&mut Vec::new())
        .expect("real first observation");
    fixture.map_journal();
    let observed: Value = serde_json::from_slice(
        &fs::read(fixture.directory.join("letters.jsonl")).expect("journal"),
    )
    .expect("observed row");
    let meta = fs::metadata(fixture.plan.home.join(".local/outbox/work.md")).expect("reply");
    assert!(
        lane_lifecycle::reply_version_matches(
            &observed,
            meta.ino(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
        .expect("shared version predicate")
    );
    let notices = crate::driver::follow::outbox::unread_replies(&fixture.plan.driver_dir)
        .expect("first monitor");
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].name, "work.md");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("reader publication through inherited descriptors");
    assert_eq!(
        crate::driver::follow::outbox::unread_replies(&fixture.plan.driver_dir)
            .expect("fresh monitor"),
        []
    );
    fixture.publish("work.md", b"other");
    let replaced =
        fs::metadata(fixture.plan.home.join(".local/outbox/work.md")).expect("replacement");
    assert!(
        !lane_lifecycle::reply_version_matches(
            &observed,
            replaced.ino(),
            replaced.ctime(),
            replaced.ctime_nsec(),
        )
        .expect("new version")
    );
    assert_eq!(
        fixture
            .command("work.md", false, &mut Vec::new())
            .expect_err("reader uses the shared mismatch")
            .kind,
        "read-reply-unobserved"
    );
    watcher
        .poll(&mut Vec::new())
        .expect("same-size replacement observation");
    fixture.map_journal();
    assert_eq!(
        crate::driver::follow::outbox::unread_replies(&fixture.plan.driver_dir)
            .expect("replacement observation")[0]
            .revision,
        2
    );
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("replacement receipt");
    assert_eq!(
        crate::driver::follow::outbox::unread_replies(&fixture.plan.driver_dir)
            .expect("acknowledged replacement"),
        []
    );
}

/// ´test:unit:reply-receipts-exercise-measures-planned-run-and-names-unmeasured-publication´
#[test]
#[allow(clippy::too_many_lines)] // Keep the measured and unmeasured runs on one planned fixture.
fn reply_receipts_exercise_measures_planned_run_and_names_unmeasured_publication() {
    for can_replace in [false, true] {
        let fixture = Fixture::new();
        let mut watcher = fixture.watcher();
        fixture.publish("work.md", b"reply\0\xff\n");
        watcher.poll(&mut Vec::new()).expect("real observation");
        fixture.map_journal();
        super::super::publish_reservation(
            &super::super::reservation_path(&fixture.root, "R"),
            &fixture.record,
        )
        .expect("planned reservation");
        let (_, reservation) = checkout::read_record_bound(&fixture.runs, "R", fixture.owner)
            .expect("bound reservation");
        let mut invoke = |request: &Request, expected: Option<&str>, inspect: bool| {
            let words = if inspect {
                inspection_argv(&fixture.owner_home, request, &reservation)?
            } else {
                private_argv(
                    &fixture.owner_home,
                    request,
                    &reservation,
                    if expected.is_some() {
                        "--receipt"
                    } else {
                        "--prepare"
                    },
                    expected,
                )?
            };
            let parsed = PrivateRequest::parse(&words)?;
            assert_eq!(parsed.inspect, inspect);
            FIXTURE_WRITER.with(|writer| writer.set(Some(fixture.owner)));
            private_bound(&parsed, fixture.owner, true)
        };
        let journal_path = fixture.directory.join("letters.jsonl");
        let reply_path = fixture.plan.home.join(".local/outbox/work.md");
        let journal_before = fs::read(&journal_path).expect("journal before inspection");
        let version_before = version(&fs::metadata(&reply_path).expect("reply before inspection"));
        let selection = Request {
            loop_name: "alpha".into(),
            run: "R".into(),
            name: "-".into(),
            dry_run: true,
            range: None,
        };
        let inspected = invoke(&selection, None, true).expect("inspection alone");
        assert_eq!(inspected["receipt_directory"], false);
        assert_eq!(fixture.receipts(), Vec::<String>::new());
        assert!(!fixture.directory.join(RECEIPTS).exists());
        assert_eq!(
            fs::read(&journal_path).expect("journal after inspection"),
            journal_before
        );
        assert_eq!(
            version(&fs::metadata(&reply_path).expect("reply after inspection")),
            version_before
        );
        let mut replace = || {
            if !can_replace {
                return Err("fixture has no worker-side publication callback".into());
            }
            fixture.publish("work.md", b"other\0\xfe\n");
            watcher
                .poll(&mut Vec::new())
                .expect("real replacement observation");
            fixture.map_journal();
            Ok(())
        };
        let report = exercise::measure_with("alpha", "R", &mut invoke, &mut replace);
        for name in [
            "dry_run",
            "repeat_read",
            "staging_refusal",
            "missing_refusal",
        ] {
            assert_eq!(report["claims"][name]["verdict"], "pass", "{report}");
        }
        let expected = if can_replace { "pass" } else { "unmeasured" };
        assert_eq!(report["claims"]["replacement"]["verdict"], expected);
        assert_eq!(report["verdict"], expected);
        assert_eq!(
            super::super::exercise::case_status(&report).expect("case status"),
            i32::from(!can_replace)
        );
        assert_eq!(fixture.receipts().len(), if can_replace { 2 } else { 1 });
        assert_eq!(report["changed"], true);
        assert!(
            report["claims"]["staging_refusal"]["reason"]
                .as_str()
                .expect("reason")
                .contains("read-reply-name")
        );
        assert!(
            report["claims"]["missing_refusal"]["reason"]
                .as_str()
                .expect("reason")
                .contains("read-reply-absent")
        );
        let repeat = exercise::measure_with("alpha", "R", &mut invoke, &mut || {
            Err("no replacement".into())
        });
        assert_eq!(repeat["claims"]["dry_run"]["verdict"], "unmeasured");
        assert_eq!(repeat["claims"]["repeat_read"]["verdict"], "unmeasured");
        assert_eq!(repeat["changed"], false);
        let failed = exercise::measure_with(
            "alpha",
            "R",
            &mut |request, expected, inspect| {
                let mut response = invoke(request, expected, inspect)?;
                if !inspect && expected.is_none() {
                    response["body_hex"] = json!(hex(b"incorrect body"));
                }
                Ok(response)
            },
            &mut || Err("no replacement".into()),
        );
        assert_eq!(failed["claims"]["dry_run"]["verdict"], "fail");
        assert_eq!(
            failed["verdict"], "fail",
            "failure is weaker than unmeasured"
        );
        let omitted = exercise::measure_with(
            "alpha",
            "R",
            &mut |request, expected, inspect| {
                let mut response = invoke(request, expected, inspect)?;
                if inspect {
                    response["name"] = Value::Null;
                }
                Ok(response)
            },
            &mut || unreachable!(),
        );
        assert_eq!(omitted["verdict"], "fail");
        assert_eq!(omitted["claims"]["dry_run"]["verdict"], "fail");
        assert!(
            omitted["reason"]
                .as_str()
                .expect("reason")
                .contains("inspection omitted name")
        );
        // Lost or malformed evidence never becomes a passing exercise.
        fs::write(fixture.directory.join("letters.jsonl"), b"{broken}\n").expect("bad journal");
        let malformed = exercise::measure_with("alpha", "R", &mut invoke, &mut || unreachable!());
        assert_eq!(malformed["verdict"], "unmeasured");
        assert!(
            malformed["reason"]
                .as_str()
                .expect("reason")
                .contains("read-reply-journal")
        );
        fs::remove_file(fixture.directory.join("letters.jsonl")).expect("missing journal");
        let absent = exercise::measure_with("alpha", "R", &mut invoke, &mut || unreachable!());
        assert_eq!(absent["verdict"], "unmeasured");
        assert!(
            absent["reason"]
                .as_str()
                .expect("reason")
                .contains("read-reply-unobserved")
        );
    }
}

/// ´test:unit:reply-receipts-exercise-refused-steps-fail-with-known-changes´
#[test]
fn reply_receipts_exercise_refused_steps_fail_with_known_changes() {
    // Each call expected to succeed: inspection, prepare, receipt and inspection
    // after receipt, including both refusal claims' surrounding inspections.
    for (fail_at, step) in [
        (1, None),
        (2, Some("dry_run")),
        (3, Some("dry_run")),
        (4, Some("repeat_read")),
        (5, Some("repeat_read")),
        (6, Some("repeat_read")),
        (7, Some("repeat_read")),
        (8, Some("repeat_read")),
        (9, Some("replacement")),
        (10, Some("replacement")),
        (11, Some("replacement")),
        (12, Some("replacement")),
        (13, Some("staging_refusal")),
        (14, Some("staging_refusal")),
        (15, Some("missing_refusal")),
        (17, Some("missing_refusal")),
    ] {
        let fixture = Fixture::new();
        let mut watcher = fixture.watcher();
        fixture.publish("work.md", b"reply");
        watcher.poll(&mut Vec::new()).expect("observed reply");
        fixture.map_journal();
        super::super::publish_reservation(
            &super::super::reservation_path(&fixture.root, "R"),
            &fixture.record,
        )
        .expect("planned reservation");
        let (_, reservation) = checkout::read_record_bound(&fixture.runs, "R", fixture.owner)
            .expect("bound reservation");
        let mut calls = 0;
        let report = exercise::measure_with(
            "alpha",
            "R",
            &mut |request, expected, inspect| {
                calls += 1;
                if calls == fail_at {
                    return Err(refusal("read-reply-injected", "exercise step refused"));
                }
                let phase = if inspect {
                    "--inspect"
                } else if expected.is_some() {
                    "--receipt"
                } else {
                    "--prepare"
                };
                let words =
                    private_argv(&fixture.owner_home, request, &reservation, phase, expected)?;
                let parsed = PrivateRequest::parse(&words)?;
                FIXTURE_WRITER.with(|writer| writer.set(Some(fixture.owner)));
                private_bound(&parsed, fixture.owner, true)
            },
            &mut || {
                fixture.publish("work.md", b"other");
                watcher
                    .poll(&mut Vec::new())
                    .expect("replacement observation");
                fixture.map_journal();
                Ok(())
            },
        );
        assert_eq!(
            calls, fail_at,
            "sequence stops at the refused step: {report}"
        );
        let changed = (fail_at != 5).then_some(fail_at > 5);
        assert_eq!(report["changed"], json!(changed), "{report}");
        let receipt_count = match fail_at {
            1..=5 => 0,
            6..=11 => 1,
            _ => 2,
        };
        assert_eq!(fixture.receipts().len(), receipt_count);
        if let Some(step) = step {
            assert_eq!(report["verdict"], "fail", "{report}");
            assert_eq!(report["claims"][step]["verdict"], "fail", "{report}");
            assert!(
                report["claims"][step]["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("read-reply-injected"),
                "{report}"
            );
        } else {
            assert_eq!(report["verdict"], "unmeasured", "{report}");
            assert!(
                report["claims"]
                    .as_object()
                    .expect("claims")
                    .values()
                    .all(|claim| claim["verdict"] == "unmeasured")
            );
        }
        assert_eq!(
            super::super::exercise::case_status(&report).expect("case status"),
            1
        );
    }
}

/// ´test:unit:reply-receipts-exercise-retains-acknowledgement-on-response-mismatch´
#[test]
fn reply_receipts_exercise_retains_acknowledgement_on_response_mismatch() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let report = exercise::measure_with(
        "alpha",
        "R",
        &mut |request, expected, inspect| {
            if inspect {
                return exercise::inspect(
                    &fixture.plan,
                    &fixture.record,
                    &fixture.runs,
                    &fixture.root,
                    fixture.owner,
                    &request.name,
                );
            }
            let mut value = fixture.context(&request.name)?.execute(expected, true)?;
            if expected.is_some() {
                value["identity"] = json!("f".repeat(64));
            }
            Ok(value)
        },
        &mut || unreachable!(),
    );
    assert_eq!(report["verdict"], "fail", "{report}");
    assert_eq!(report["claims"]["repeat_read"]["verdict"], "fail");
    assert_eq!(report["changed"], true);
    assert_eq!(fixture.receipts().len(), 1);
    assert!(
        report["reason"]
            .as_str()
            .expect("reason")
            .contains("read-reply-changed")
    );
}

/// ´test:unit:completion-only-row-keeps-read-receipt´
#[test]
fn completion_only_row_keeps_read_receipt() {
    let fixture = Fixture::new();
    let mut watcher = fixture.watcher();
    fixture.publish("work.md", b"reply");
    watcher.poll(&mut Vec::new()).expect("observed row");
    fixture.map_journal();
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("read observed version");
    let receipts = fixture.receipts();
    watcher.finish(&mut Vec::new()).expect("completion row");
    fixture.map_journal();
    assert_eq!(
        crate::driver::follow::outbox::unread_replies(&fixture.directory)
            .expect("monitor after finish"),
        []
    );
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("idempotent read after completion");
    assert_eq!(fixture.receipts(), receipts);
}

/// ´test:unit:reader-refuses-same-size-version-before-watcher-observes-it´
#[test]
fn reader_refuses_same_size_version_before_watcher_observes_it() {
    let fixture = Fixture::new();
    let mut watcher = fixture.watcher();
    fixture.publish("work.md", b"first");
    watcher
        .poll(&mut Vec::new())
        .expect("observe first version");
    fixture.map_journal();
    fixture.publish("work.md", b"other");
    for dry_run in [false, true] {
        let mut output = Vec::new();
        let error = fixture
            .command("work.md", dry_run, &mut output)
            .expect_err("not yet observed");
        assert_eq!(error.kind, "read-reply-unobserved");
        assert_eq!(error.status, 2);
        assert_eq!(output, Vec::<u8>::new());
        assert_eq!(fixture.receipts(), Vec::<String>::new());
    }
    watcher.poll(&mut Vec::new()).expect("observe replacement");
    fixture.map_journal();
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("observed version can be read");
}

/// ´test:unit:reader-names-malformed-version-on-another-row-as-journal-refusal´
#[test]
fn reader_names_malformed_version_on_another_row_as_journal_refusal() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let path = fixture.directory.join("letters.jsonl");
    let original = fs::read_to_string(&path).expect("journal");
    let mut bad: Value = serde_json::from_str(&original).expect("row");
    bad["name"] = json!("other.md");
    bad["identity"][1] = json!("other.md");
    bad["file_version"] = json!({});
    fs::write(path, format!("{original}{bad}\n")).expect("bad unrelated version");
    let mut output = Vec::new();
    let error = fixture
        .command("work.md", false, &mut output)
        .expect_err("malformed journal");
    assert_eq!(error.kind, "read-reply-journal");
    assert_eq!(error.status, 2);
    assert_eq!(output, Vec::<u8>::new());
    assert_eq!(fixture.receipts(), Vec::<String>::new());
}

/// ´test:unit:reader-keeps-receipt-across-recorded-device-renumbering´
#[test]
fn reader_keeps_receipt_across_recorded_device_renumbering() {
    let fixture = Fixture::new();
    let mut watcher = fixture.watcher();
    fixture.publish("work.md", b"reply");
    watcher.poll(&mut Vec::new()).expect("observe");
    fixture.map_journal();
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("first receipt");
    let path = fixture
        .directory
        .join(RECEIPTS)
        .join(&fixture.receipts()[0]);
    let mut saved: Value =
        serde_json::from_slice(&fs::read(&path).expect("receipt")).expect("record");
    let identity = reply_identity(&saved["reply"]);
    saved["reply"]["file"]["device"] =
        json!(saved["reply"]["file"]["device"].as_u64().expect("device") ^ 1);
    assert_eq!(reply_identity(&saved["reply"]), identity);
    fs::write(&path, format!("{saved}\n")).expect("record earlier device number");
    let journal = fixture.directory.join("letters.jsonl");
    let mut row: Value =
        serde_json::from_slice(&fs::read(&journal).expect("journal")).expect("row");
    row["file_version"]["device"] =
        json!(row["file_version"]["device"].as_u64().expect("device") ^ 1);
    fs::write(journal, format!("{row}\n")).expect("record earlier journal device");
    fixture
        .command("work.md", false, &mut Vec::new())
        .expect("same file after renumbering");
    assert_eq!(fixture.receipts().len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path).expect("receipt")).expect("record"),
        saved
    );
}

/// ´test:unit:reader-and-monitor-name-malformed-instants-as-journal-refusals´
#[test]
fn reader_and_monitor_name_malformed_instants_as_journal_refusals() {
    let fixture = Fixture::new();
    let mut watcher = fixture.watcher();
    fixture.publish("work.md", b"reply");
    watcher.poll(&mut Vec::new()).expect("observation");
    fixture.map_journal();
    let journal = fixture.directory.join("letters.jsonl");
    let original: Value =
        serde_json::from_slice(&fs::read(&journal).expect("journal")).expect("row");
    for at in [
        "",
        "now name=forged",
        "2026-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00.Z",
        "é",
    ] {
        let mut row = original.clone();
        row["at"] = json!(at);
        row["identity"][3] = json!(at);
        assert!(lane_lifecycle::reply_observations(&[row.clone()]).is_err());
        fs::write(&journal, format!("{row}\n")).expect("malformed instant agreeing with identity");
        let mut output = Vec::new();
        let error = fixture
            .command("work.md", false, &mut output)
            .expect_err("reader journal refusal");
        assert_eq!(error.kind, "read-reply-journal");
        assert_eq!(error.status, 2);
        assert_eq!(output, Vec::<u8>::new());
        assert_eq!(fixture.receipts(), Vec::<String>::new());
        assert_eq!(
            crate::driver::follow::outbox::unread_replies(&fixture.directory)
                .expect_err("monitor journal refusal")
                .kind,
            "outbox-journal"
        );
    }
}

/// Invoke explicitly with `cargo test -p superloop-lane --locked
/// read_reply_near_journal_cap_measures_two_phase_cost -- --ignored --nocapture`.
///
/// ´test:unit:read-reply-near-journal-cap-measures-two-phase-cost´
#[test]
#[ignore = "opt-in near-cap journal cost measurement; no timing assertion"]
fn read_reply_near_journal_cap_measures_two_phase_cost() {
    let fixture = Fixture::new();
    fixture.post("work.md", b"reply");
    let journal = fixture.directory.join("letters.jsonl");
    let row = fs::read(&journal).expect("observation");
    let limit = usize::try_from(MAX_JOURNAL).expect("journal bound");
    let rows = limit / row.len();
    let bytes = row.repeat(rows);
    assert!(bytes.len() <= limit && bytes.len() > limit - row.len());
    fs::write(&journal, &bytes).expect("near-cap journal");
    let mut output = Vec::new();
    let start = std::time::Instant::now();
    fixture
        .command("work.md", false, &mut output)
        .expect("two-phase read");
    let elapsed = start.elapsed();
    assert_eq!(output, b"reply");
    assert_eq!(fixture.receipts().len(), 1);
    writeln!(
        std::io::stderr(),
        "READ-REPLY COST fixture=two-phase bytes={} rows={} elapsed_ms={} helper_process_overhead=unmeasured",
        bytes.len(),
        rows,
        elapsed.as_millis()
    ).expect("cost report");
}

/// ´test:unit:reply-receipts-exercise-reports-unknown-change-on-lost-receipt-response´
#[test]
fn reply_receipts_exercise_reports_unknown_change_on_lost_receipt_response() {
    for publish_before_error in [false, true] {
        let fixture = Fixture::new();
        fixture.post("work.md", b"reply");
        let report = exercise::measure_with(
            "alpha",
            "R",
            &mut |request, expected, inspect| {
                if inspect {
                    return exercise::inspect(
                        &fixture.plan,
                        &fixture.record,
                        &fixture.runs,
                        &fixture.root,
                        fixture.owner,
                        &request.name,
                    );
                }
                if expected.is_some() {
                    if publish_before_error {
                        fixture.context(&request.name)?.execute(expected, true)?;
                    }
                    return Err(refusal("read-reply-injected", "receipt response lost"));
                }
                fixture.context(&request.name)?.execute(expected, true)
            },
            &mut || unreachable!(),
        );
        assert_eq!(report["verdict"], "fail");
        assert_eq!(report["claims"]["repeat_read"]["verdict"], "fail");
        assert_eq!(report["changed"], Value::Null, "{report}");
        assert_eq!(fixture.receipts().len(), usize::from(publish_before_error));
    }
}

/// ´test:unit:two-round-same-second-selection-clears-the-monitors-receipt´
#[test]
fn two_round_same_second_selection_clears_the_monitors_receipt() {
    let mut fixture = Fixture::new();
    let _watcher = fixture.watcher();
    fixture.post("work.md", b"reply");
    let first = fixture.directory.clone();
    let second = fixture.plan.driver_dir.join("round-two");
    fs::create_dir(&second).expect("second round");
    fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).expect("mode");
    map_identity(&second, fixture.loop_uid, fixture.loop_uid);
    fixture.directory = second.clone();
    fixture.record_observation("work.md", 5);
    fixture.record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(json!({"step":"next", "driver_dir":second}));
    // The newest reservation round has revision 1; the earlier directory has
    // revision 2 at the same second. Previously reader and monitor disagreed.
    let journal = first.join("letters.jsonl");
    let mut row: Value =
        serde_json::from_slice(&fs::read(&journal).expect("journal")).expect("row");
    row["revision"] = json!(2);
    row["identity"][2] = json!(2);
    fs::write(&journal, format!("{row}\n")).expect("same-second higher revision");
    let notices = crate::driver::follow::outbox::unread_replies(&second).expect("monitor");
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].revision, 2);
    let line = fixture
        .command("work.md", false, &mut Vec::new())
        .expect("read and receipt");
    assert!(line.contains("revision=2 "), "{line}");
    assert_eq!(
        fs::read_dir(first.join(RECEIPTS))
            .expect("selected receipts")
            .count(),
        1
    );
    assert!(!second.join(RECEIPTS).exists());
    assert_eq!(
        crate::driver::follow::outbox::unread_replies(&second).expect("acknowledged"),
        []
    );
}
