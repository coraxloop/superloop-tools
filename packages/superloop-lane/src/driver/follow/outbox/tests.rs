use super::*;
use lane_lifecycle::reply_observation_key;
use serde_json::json;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use crate::driver::follow::tests::support::TestDir;

struct Fixture {
    temp: TestDir,
    root: PathBuf,
    round: PathBuf,
}
impl Fixture {
    fn new(backend: &str) -> Self {
        let temp = TestDir::new("outbox");
        let root = temp.path().join("R");
        let round = root.join("round");
        fs::create_dir_all(&round).expect("round");
        let plan = json!({"home":temp.path().join("worker"),"driver_dir":root,"backend":backend});
        fs::write(root.join("plan.json"), plan.to_string()).expect("plan");
        Self { temp, root, round }
    }
    fn post(&self, name: &str, revision: u64) -> Value {
        let at = format!("2026-01-01T00:00:{revision:02}Z");
        let identity = json!(["outbox", name, revision, at]);
        let row = json!({"box":"outbox","kind":"file","name":name,"revision":revision,"at":at,"bytes":5,"state":"observed","identity":identity});
        let path = self.round.join("letters.jsonl");
        let mut bytes = fs::read(&path).unwrap_or_default();
        bytes.extend_from_slice(format!("{row}\n").as_bytes());
        fs::write(path, bytes).expect("journal");
        identity
    }
    fn receipt(&self, identity: &Value) -> PathBuf {
        let directory = self.round.join(".reply-receipts");
        fs::create_dir_all(&directory).expect("receipts");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("listable");
        let path = directory.join(format!(
            "{}.json",
            reply_observation_key(identity).expect("key")
        ));
        // A filename-only monitor must never parse this deliberately invalid private body.
        fs::write(&path, b"not readable receipt JSON").expect("receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private receipt");
        path
    }
    fn notices(&self) -> Vec<ReplyNotice> {
        unread_replies(&self.round).expect("scan")
    }
    fn call(&self) -> (Value, String) {
        let config = crate::driver::follow::Config {
            run_dir: self.round.clone(),
            cap: 50_000,
            bounce: 30,
            wait: 1,
            save_offset: true,
        };
        let (mut capture, mut messages) = (Vec::new(), Vec::new());
        crate::driver::follow::run_with_messages(&config, &mut capture, &mut messages)
            .expect("monitor call");
        (
            serde_json::from_slice(&capture).expect("unchanged JSON envelope"),
            String::from_utf8(messages).expect("escaped notices"),
        )
    }
}

/// ´test:unit:two-outbox-replies-share-one-handback´
#[test]
fn two_outbox_replies_share_one_handback() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    f.post("two.md", 2);
    let (capture, lines) = f.call();
    assert_eq!(capture["schema"], 2);
    assert_eq!(
        lines,
        "NEW MESSAGE name=one.md at=2026-01-01T00:00:01Z revision=1\nNEW MESSAGE name=two.md at=2026-01-01T00:00:02Z revision=2\n"
    );
}

/// ´test:unit:reply-after-handback-survives-fresh-watcher´
#[test]
fn reply_after_handback_survives_fresh_watcher() {
    let f = Fixture::new("box");
    let first = f.post("one.md", 1);
    assert_eq!(f.call().1.lines().count(), 1);
    f.receipt(&first);
    f.post("two.md", 2);
    assert!(f.call().1.starts_with("NEW MESSAGE name=two.md "));
}

/// ´test:unit:reply-arriving-during-read-is-not-acknowledged´
#[test]
fn reply_arriving_during_read_is_not_acknowledged() {
    let f = Fixture::new("box");
    let first = f.post("one.md", 1);
    assert_eq!(f.notices().len(), 1);
    f.post("two.md", 2);
    f.receipt(&first);
    assert_eq!(
        f.notices()
            .iter()
            .map(|n| n.name.as_str())
            .collect::<Vec<_>>(),
        ["two.md"]
    );
}

/// ´test:unit:fresh-watcher-rebuilds-from-mailbox-and-receipts´
#[test]
fn fresh_watcher_rebuilds_from_mailbox_and_receipts() {
    let f = Fixture::new("box");
    let first = f.post("one.md", 1);
    assert_eq!(f.notices(), f.notices());
    let path = f.receipt(&first);
    assert_eq!(f.notices(), []);
    fs::remove_file(path).expect("remove receipt");
    assert_eq!(f.notices().len(), 1);
    f.receipt(&first);
    f.post("one.md", 2);
    assert_eq!(f.notices()[0].revision, 2);
}

/// ´test:unit:delivered-journal-does-not-hide-unread-reply´
#[test]
fn delivered_journal_does_not_hide_unread_reply() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    assert_eq!(f.call().1.lines().count(), 1);
    assert!(f.round.join(".letter-delivered.json").exists());
    assert_eq!(f.call().1.lines().count(), 1);
}

/// ´test:unit:outbox-observation-does-not-claim-completion´
#[test]
fn outbox_observation_does_not_claim_completion() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let (capture, lines) = f.call();
    assert!(
        !capture["records"]
            .as_array()
            .expect("records")
            .iter()
            .any(|r| r["kind"] == "finished")
    );
    assert!(!lines.contains("finished"));
}

/// ´test:unit:staging-names-are-silent´
#[test]
fn staging_names_are_silent() {
    let f = Fixture::new("box");
    f.post(".tmp-reply", 1);
    let public = f.post("one.md", 1);
    let path = f.receipt(&public);
    fs::rename(
        &path,
        path.with_file_name(format!(
            ".tmp-{}",
            path.file_name().expect("name").to_string_lossy()
        )),
    )
    .expect("staged receipt");
    assert_eq!(f.notices().len(), 1);
    assert_eq!(f.notices()[0].name, "one.md");
}

/// ´test:unit:box-run-lists-its-recorded-outbox´
#[test]
fn box_run_lists_its_recorded_outbox() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    assert_eq!(f.notices().len(), 1);
}

/// ´test:unit:planned-shim-lists-its-recorded-outbox´
#[test]
fn planned_shim_lists_its_recorded_outbox() {
    let f = Fixture::new("shim");
    f.post("one.md", 1);
    assert_eq!(f.notices().len(), 1);
}

/// ´test:unit:unplanned-shim-claims-no-coverage´
#[test]
fn unplanned_shim_claims_no_coverage() {
    let f = Fixture::new("shim");
    f.post("one.md", 1);
    fs::remove_file(f.root.join("plan.json")).expect("unplanned");
    assert_eq!(f.notices(), []);
    fs::write(f.root.join("plan.json"), "{}").expect("no home");
    assert_eq!(f.notices(), []);
}

/// ´test:unit:missing-ancestor-search-bit-refuses-by-name´
#[test]
fn missing_ancestor_search_bit_refuses_by_name() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    for path in [f.temp.path(), &f.root, &f.round] {
        let old = fs::metadata(path).expect("metadata").permissions();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("remove search");
        let failure = unread_replies(&f.round).expect_err("missing search");
        assert_eq!(failure.kind, "outbox-search");
        assert_eq!(failure.path, path);
        assert!(failure.reason.contains("required-directory-owner="));
        assert!(!failure.reason.contains("use-run-identity"));
        fs::set_permissions(path, old).expect("restore");
    }
    let file = File::open(&f.round).expect("held round");
    let metadata = file.metadata().expect("metadata");
    let foreign = metadata.uid().checked_add(1).expect("fixture uid");
    fs::set_permissions(&f.round, fs::Permissions::from_mode(0o710)).expect("group search");
    assert!(
        HostIdentity {
            uid: foreign,
            groups: vec![metadata.gid()]
        }
        .search(&file, &f.round)
        .is_ok()
    );
    assert_eq!(
        HostIdentity {
            uid: foreign,
            groups: Vec::new()
        }
        .search(&file, &f.round)
        .expect_err("other denied")
        .kind,
        "outbox-search"
    );
}

/// ´test:unit:latest-round-selects-its-own-receipt-directory´
#[test]
fn latest_round_selects_its_own_receipt_directory() {
    let mut f = Fixture::new("box");
    let old = f.post("one.md", 1);
    f.receipt(&old);
    f.round = f.root.join("second");
    fs::create_dir(&f.round).expect("second");
    f.post("one.md", 2);
    assert_eq!(f.notices().len(), 1);
    assert_eq!(f.notices()[0].revision, 2);
}

/// ´test:unit:outbox-refuses-unsafe-paths-and-malformed-records´
#[test]
fn outbox_refuses_unsafe_paths_and_malformed_records() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    let path = f.receipt(&identity);
    fs::remove_file(&path).expect("receipt");
    symlink("outside", &path).expect("receipt symlink");
    assert_eq!(f.notices().len(), 1);
    fs::remove_file(path).expect("symlink");
    let journal = f.round.join("letters.jsonl");
    let saved = fs::read(&journal).expect("journal");
    for row in [
        b"{\n".as_slice(),
        b"{\"box\":\"outbox\",\"kind\":\"file\"}\n",
    ] {
        fs::write(&journal, row).expect("malformed");
        assert_eq!(
            unread_replies(&f.round).expect_err("bad journal").kind,
            "outbox-journal"
        );
    }
    fs::write(&journal, &saved).expect("restore");
    let mut torn = saved;
    torn.extend_from_slice(b"{\"name\":");
    fs::write(&journal, torn).expect("torn tail");
    assert_eq!(f.notices().len(), 1);
    fs::remove_file(&journal).expect("remove journal");
    symlink("outside", &journal).expect("linked journal");
    assert_eq!(
        unread_replies(&f.round).expect_err("link").kind,
        "outbox-path"
    );
}

/// ´test:unit:outbox-names-cannot-inject-handback-fields´
#[test]
fn outbox_names_cannot_inject_handback_fields() {
    let f = Fixture::new("box");
    f.post("reply%20name%3Dfake%0A.md", 1);
    assert_eq!(f.notices()[0].to_string().lines().count(), 1);
    assert!(!f.notices()[0].to_string().contains(" name=fake"));
    f.post("reply name=fake", 1);
    let error = unread_replies(&f.round).expect_err("unescaped name");
    assert_eq!(error.kind, "outbox-name");
    assert_eq!(error.to_string().lines().count(), 1);
}

/// ´test:unit:outbox-refusal-paths-name-the-record-or-directory´
#[test]
fn outbox_refusal_paths_name_the_record_or_directory() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    let host = HostIdentity::current().expect("host identity");
    assert_eq!(
        scan(
            &f.round.join(".."),
            &host,
            &mut Vec::new(),
            &mut Cost::default()
        )
        .expect_err("parent traversal")
        .kind,
        "outbox-path"
    );
    let linked = f.root.join("linked");
    symlink(&f.round, &linked).expect("linked round");
    assert_eq!(
        unread_replies(&linked).expect_err("linked ancestor").kind,
        "outbox-path"
    );
    let plan_path = f.root.join("plan.json");
    let plan = fs::read(&plan_path).expect("plan");
    fs::write(&plan_path, "{").expect("malformed plan");
    assert_eq!(
        unread_replies(&f.round).expect_err("bad plan").kind,
        "outbox-record"
    );
    fs::write(
        &plan_path,
        json!({"home":"recorded", "driver_dir":"wrong"}).to_string(),
    )
    .expect("wrong plan");
    assert_eq!(
        unread_replies(&f.round).expect_err("wrong driver").kind,
        "outbox-plan"
    );
    fs::write(&plan_path, plan).expect("restore plan");
    let reservation = f.temp.path().join(".reservation-R.json");
    for record in [
        json!({}),
        json!({"rounds":[{}]}),
        json!({"rounds":[{"driver_dir":f.temp.path().join("foreign")}]}),
        json!({"rounds":[{"driver_dir":f.root.join("absent")} ]}),
    ] {
        fs::write(&reservation, record.to_string()).expect("bad round record");
        assert_eq!(
            unread_replies(&f.round)
                .expect("reservation is not watcher input")
                .len(),
            1
        );
    }
    fs::remove_file(reservation).expect("remove reservation");
    let journal = f.round.join("letters.jsonl");
    let saved = fs::read(&journal).expect("journal");
    let valid: Value = serde_json::from_slice(&saved).expect("row");
    for (key, value) in [
        ("at", json!("now name=fake")),
        ("revision", json!(0)),
        (
            "identity",
            json!(["outbox", "other", 1, "2026-01-01T00:00:01Z"]),
        ),
    ] {
        let mut row = valid.clone();
        row[key] = value;
        fs::write(&journal, format!("{row}\n")).expect("bad row");
        assert_eq!(
            unread_replies(&f.round).expect_err("bad observation").kind,
            "outbox-journal"
        );
    }
    File::options()
        .write(true)
        .open(&journal)
        .expect("journal")
        .set_len(MAX_RECORD + 1)
        .expect("oversize");
    assert_eq!(
        unread_replies(&f.round).expect_err("oversize journal").kind,
        "outbox-record"
    );
    fs::write(&journal, saved).expect("restore journal");
    f.receipt(&identity);
    let receipts = f.round.join(".reply-receipts");
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o600)).expect("no search");
    assert_eq!(
        unread_replies(&f.round).expect_err("receipt search").kind,
        "outbox-search"
    );
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).expect("restore");
    fs::remove_dir_all(&receipts).expect("remove receipt directory");
    symlink("outside", &receipts).expect("linked receipts");
    assert_eq!(
        unread_replies(&f.round).expect_err("receipt symlink").kind,
        "outbox-path"
    );
}

/// ´test:unit:outbox-access-failure-is-named´
#[test]
fn outbox_access_failure_is_named() {
    let f = Fixture::new("box");
    FAULT.with(|fault| fault.set("identity"));
    let error = unread_replies(&f.round).expect_err("identity query failed");
    assert_eq!(error.kind, "outbox-access");
    assert_eq!(error.path, f.round);
}

/// ´test:unit:outbox-receipts-failure-is-named´
#[test]
fn outbox_receipts_failure_is_named() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    f.receipt(&identity);
    FAULT.with(|fault| fault.set("receipt-list"));
    let error = unread_replies(&f.round).expect_err("receipt enumeration failed");
    assert_eq!(error.kind, "outbox-receipts");
    assert_eq!(error.path, f.round.join(".reply-receipts"));
}

/// ´test:unit:outbox-refusal-preserves-the-capture-and-its-status´
#[test]
fn outbox_refusal_preserves_the_capture_and_its_status() {
    let f = Fixture::new("box");
    fs::write(f.root.join("plan.json"), "{").expect("invalid outbox plan");
    let (capture, lines) = f.call();
    assert_eq!(capture["schema"], 2);
    assert!(capture.get("error").is_none());
    assert!(lines.starts_with("OUTBOX REFUSAL kind=outbox-record detail="));
    assert_eq!(lines.lines().count(), 1);
    assert_eq!(lines.split_ascii_whitespace().count(), 4);
}

struct InjectedIdentities;
impl Drop for InjectedIdentities {
    fn drop(&mut self) {
        TEST_OWNERS.with(|owners| owners.borrow_mut().clear());
        TEST_CALLER.with(|caller| caller.set(None));
        TEST_SCOPE.with(|scope| *scope.borrow_mut() = None);
    }
}

/// ´test:unit:loop-watcher-uses-durable-rounds-with-owner-private-reservation´
#[test]
fn loop_watcher_uses_durable_rounds_with_owner_private_reservation() {
    let mut f = Fixture::new("box");
    let loop_uid = 2200;
    let owner_uid = 1100;
    let _identities = InjectedIdentities;
    TEST_SCOPE.with(|scope| *scope.borrow_mut() = Some(f.temp.path().into()));
    // Inject caller and fstat ownership; kernel isolation is host evidence.
    for (path, uid, mode) in [
        (f.temp.path(), owner_uid, 0o711),
        (f.root.as_path(), loop_uid, 0o700),
        (f.round.as_path(), loop_uid, 0o700),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("custody mode");
        let meta = fs::metadata(path).expect("held identity");
        TEST_OWNERS.with(|owners| {
            owners
                .borrow_mut()
                .insert((meta.dev(), meta.ino()), (uid, uid))
        });
    }
    let reservation = f.temp.path().join(".reservation-R.json");
    fs::write(&reservation, b"owner-only input, deliberately not JSON").expect("reservation");
    fs::set_permissions(&reservation, fs::Permissions::from_mode(0o600)).expect("owner private");
    let first = f.post("reply.md", 1);
    let next = f.post("next.md", 2);
    TEST_CALLER.with(|caller| caller.set(Some(loop_uid)));
    let round = f.round.clone();
    // Arm at the run root to prove discovery without a preselected round; a session arms at the round directory, whose parent holds plan.json.
    f.round = f.root.clone();
    let (capture, lines) = f.call();
    assert_eq!(capture["schema"], 2);
    assert_eq!(lines.lines().count(), 2);
    assert!(lines.contains("NEW MESSAGE name=reply.md "));
    f.round = round.clone();
    f.receipt(&first);
    f.round = f.root.clone();
    let (_, lines) = f.call();
    assert_eq!(
        lines,
        "announced-before name=next.md at=2026-01-01T00:00:02Z revision=2\n"
    );
    f.round = round;
    f.receipt(&next);
    f.round = f.root.clone();
    assert_eq!(f.call().1, "");
    TEST_CALLER.with(|caller| caller.set(Some(owner_uid)));
    f.round = f.root.join("round");
    let error = unread_replies(&f.round).expect_err("owner cannot search the loop run");
    assert_eq!(error.kind, "outbox-search");
    assert_eq!(error.path, f.root);
    let (_, lines) = f.call();
    assert_eq!(lines.lines().count(), 1);
    assert!(lines.starts_with("OUTBOX REFUSAL kind=outbox-search "));
    assert!(lines.contains("use-run-identity%3Dloop-via-superloop"));
    assert!(lines.contains("required-directory-owner%3D2200"));
}

/// ´test:unit:republished-reply-revision-holds-until-independent-release´
#[test]
fn republished_reply_revision_holds_until_independent_release() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    f.call();
    f.post("one.md", 1);
    fs::write(f.round.join(".letter-count"), b"2").expect("journal delivered");
    let config = crate::driver::follow::Config {
        run_dir: f.round.clone(),
        cap: 50_000,
        bounce: 0,
        wait: 2,
        save_offset: true,
    };
    let (mut capture, mut messages) = (Vec::new(), Vec::new());
    let mut waits = 0;
    crate::driver::follow::run_with_messages_wait(&config, &mut capture, &mut messages, |_| {
        waits += 1;
        assert_eq!(waits, 1, "independent event releases next poll");
        fs::write(f.round.join("events.jsonl"), b"progress\n").expect("progress");
    })
    .expect("capture");
    assert_eq!(waits, 1, "announced revision must hold");
    assert_eq!(
        String::from_utf8(messages).expect("text"),
        "announced-before name=one.md at=2026-01-01T00:00:01Z revision=1\n"
    );
    let record: Value = serde_json::from_slice(&capture).expect("capture JSON");
    assert!(
        record["records"]
            .as_array()
            .expect("records")
            .iter()
            .any(|row| row["kind"] == "delta")
    );
}

/// ´test:unit:new-reply-name-or-revision-releases-announced-hold´
#[test]
fn new_reply_name_or_revision_releases_announced_hold() {
    for name in ["one.md", "two.md"] {
        let f = Fixture::new("box");
        f.post("one.md", 1);
        f.call();
        f.post(name, 2);
        fs::write(f.round.join(".letter-count"), b"2").expect("journal delivered");
        let config = crate::driver::follow::Config {
            run_dir: f.round.clone(),
            cap: 50_000,
            bounce: 30,
            wait: 2,
            save_offset: true,
        };
        let (mut capture, mut messages) = (Vec::new(), Vec::new());
        crate::driver::follow::run_with_messages_wait(&config, &mut capture, &mut messages, |_| {
            panic!("new name or revision must release immediately");
        })
        .expect("capture");
        assert!(
            String::from_utf8(messages)
                .expect("text")
                .contains(&format!(
                    "NEW MESSAGE name={name} at=2026-01-01T00:00:02Z revision=2"
                ))
        );
        assert_eq!(
            Announcements::read(&f.round)
                .expect("state")
                .entries
                .get(name),
            Some(&2)
        );
    }
}

/// ´test:unit:reply-receipt-prunes-announced-set-and-releases-hold´
#[test]
fn reply_receipt_prunes_announced_set_and_releases_hold() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    f.call();
    let config = crate::driver::follow::Config {
        run_dir: f.round.clone(),
        cap: 50_000,
        bounce: 30,
        wait: 2,
        save_offset: true,
    };
    let (mut capture, mut messages) = (Vec::new(), Vec::new());
    let mut waits = 0;
    crate::driver::follow::run_with_messages_wait(&config, &mut capture, &mut messages, |_| {
        waits += 1;
        assert_eq!(waits, 1, "receipt releases next poll");
        f.receipt(&identity);
    })
    .expect("capture");
    assert_eq!(waits, 1);
    assert_eq!(messages, [] as [u8; 0]);
    assert!(
        Announcements::read(&f.round)
            .expect("state")
            .entries
            .is_empty()
    );
}

/// ´test:unit:announced-reply-hold-preserves-cap-and-report-release´
#[test]
fn announced_reply_hold_preserves_cap_and_report_release() {
    for report in [false, true] {
        let f = Fixture::new("box");
        f.post("one.md", 1);
        f.call();
        fs::write(f.round.join("events.jsonl"), b"progress\n").expect("progress");
        if report {
            fs::write(f.round.join("run-report.txt"), b"RUN-REPORT exit=0\n").expect("report");
        }
        let config = crate::driver::follow::Config {
            run_dir: f.round,
            cap: if report { 50_000 } else { 1 },
            bounce: 3600,
            wait: 2,
            save_offset: true,
        };
        let (mut capture, mut messages) = (Vec::new(), Vec::new());
        crate::driver::follow::run_with_messages_wait(&config, &mut capture, &mut messages, |_| {
            panic!("cap and report release before the announced hold");
        })
        .expect("capture");
        assert!(
            String::from_utf8(messages)
                .expect("text")
                .starts_with("announced-before name=one.md ")
        );
        let record: Value = serde_json::from_slice(&capture).expect("capture JSON");
        let records = record["records"].as_array().expect("records");
        assert!(records.iter().any(|row| row["kind"] == "delta"));
        assert_eq!(records.iter().any(|row| row["kind"] == "finished"), report);
    }
}

/// ´test:unit:announced-reply-is-listed-at-bounded-wait-expiry´
#[test]
fn announced_reply_is_listed_at_bounded_wait_expiry() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    f.call();
    let started = std::time::Instant::now();
    let (capture, messages) = f.call();
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(capture["records"].as_array().expect("records").len(), 1);
    assert_eq!(
        messages,
        "announced-before name=one.md at=2026-01-01T00:00:01Z revision=1\n"
    );
}

/// ´test:unit:malformed-announced-reply-set-is-refused-by-name´
#[test]
fn malformed_announced_reply_set_is_refused_by_name() {
    for raw in [
        "not JSON",
        r#"{"schema":2,"replies":[]}"#,
        r#"{"schema":1,"replies":[],"extra":0}"#,
        r#"{"schema":1,"replies":[{"name":"one.md","revision":0}]}"#,
        r#"{"schema":1,"replies":[{"name":"../one.md","revision":1}]}"#,
        r#"{"schema":1,"replies":[{"name":"one.md","revision":1},{"name":"one.md","revision":2}]}"#,
    ] {
        let f = Fixture::new("box");
        f.post("one.md", 1);
        fs::write(f.round.join(ANNOUNCED_RECORD), raw).expect("malformed record");
        let (capture, messages) = f.call();
        assert_eq!(capture["schema"], 2);
        assert!(messages.starts_with("OUTBOX REFUSAL kind=outbox-record "));
        assert!(messages.contains(ANNOUNCED_RECORD));
        assert!(!messages.contains("NEW MESSAGE"));
        assert_eq!(
            fs::read_to_string(f.round.join(ANNOUNCED_RECORD)).expect("retained"),
            raw
        );
    }
}

/// ´test:unit:failed-announced-reply-write-preserves-previous-record´
#[test]
fn failed_announced_reply_write_preserves_previous_record() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    f.call();
    let path = f.round.join(ANNOUNCED_RECORD);
    let previous = fs::read(&path).expect("previous record");
    let announced = Announcements::read(&f.round).expect("announced set");
    let error = announced
        .publish(|file| {
            file.write_all(b"{\"schema\":")?;
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        })
        .expect_err("partial staging write fails");
    assert_eq!(error.path, path);
    assert_eq!(error.kind, "outbox-record");
    assert_eq!(fs::read(&path).expect("retained record"), previous);
    assert_eq!(
        Announcements::read(&f.round)
            .expect("still readable")
            .entries
            .get("one.md"),
        Some(&1)
    );
    assert_eq!(fs::metadata(&path).expect("mode").mode() & 0o777, 0o600);
    assert!(!fs::read_dir(&f.round).expect("directory").any(|entry| {
        entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    f.post("one.md", 2);
    assert!(
        f.call().1.contains("revision=2"),
        "later reply remains eligible"
    );
}

/// ´test:unit:announced-reply-publication-uses-the-read-directory-descriptor´
#[test]
fn announced_reply_publication_uses_the_read_directory_descriptor() {
    let f = Fixture::new("box");
    let mut announced = Announcements::read(&f.round).expect("empty announced set");
    let moved = f.root.join("moved");
    fs::rename(&f.round, &moved).expect("move held directory");
    fs::create_dir(&f.round).expect("replacement directory");
    let replacement = f.round.join(ANNOUNCED_RECORD);
    fs::write(&replacement, b"replacement must stay untouched").expect("replacement record");
    announced
        .announced(&[ReplyNotice {
            name: "one.md".into(),
            at: "2026-01-01T00:00:01Z".into(),
            revision: 1,
        }])
        .expect("publish through held directory");
    assert_eq!(
        Announcements::read(&moved)
            .expect("held record")
            .entries
            .get("one.md"),
        Some(&1)
    );
    assert_eq!(
        fs::read(&replacement).expect("replacement bytes"),
        b"replacement must stay untouched"
    );
}

/// ´test:unit:announced-reply-set-refuses-oversize-and-linked-records´
#[test]
fn announced_reply_set_refuses_oversize_and_linked_records() {
    let f = Fixture::new("box");
    let path = f.round.join(ANNOUNCED_RECORD);
    File::create(&path)
        .expect("record")
        .set_len(MAX_RECORD + 1)
        .expect("oversize");
    assert_eq!(
        Announcements::read(&f.round).err().expect("refused").path,
        path
    );
    fs::remove_file(&path).expect("remove");
    symlink(f.round.join("missing"), &path).expect("link");
    assert_eq!(
        Announcements::read(&f.round).err().expect("refused").path,
        path
    );
}

/// ´test:unit:durable-round-discovery-is-pinned-and-names-enumeration-failure´
#[test]
fn durable_round_discovery_is_pinned_and_names_enumeration_failure() {
    let f = Fixture::new("box");
    f.post("reply.md", 1);
    symlink(f.temp.path(), f.root.join("foreign")).expect("unfollowed directory link");
    fs::create_dir(f.root.join(".staging")).expect("staging directory");
    fs::write(f.root.join(".staging/letters.jsonl"), b"invalid\n")
        .expect("ignored staging journal");
    assert_eq!(
        unread_replies(&f.root).expect("durable directories").len(),
        1
    );
    FAULT.with(|fault| fault.set("round-list"));
    let error = unread_replies(&f.root).expect_err("enumeration failure");
    assert_eq!(error.kind, "outbox-rounds");
    assert_eq!(error.path, f.root);
}

/// ´test:unit:quiet-outbox-wait-reports-one-scan´
#[test]
fn quiet_outbox_wait_reports_one_scan() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    f.receipt(&identity);
    fs::write(f.round.join(".letter-count"), b"1").expect("capture already delivered");
    let bytes = fs::metadata(f.round.join("letters.jsonl"))
        .expect("journal")
        .len();
    let (capture, messages) = f.call();
    assert_eq!(messages, "");
    let cost = &capture["records"][0]["cost"];
    assert_eq!(cost["scans"], 1);
    assert_eq!(cost["journal_bytes"], bytes);
    assert_eq!(cost["receipt_names"], 1);
    assert!(cost["scan_wall_ms"].is_u64());
    std::io::Write::write_all(
        &mut std::io::stdout(),
        format!("quiet scan cost={cost}\n").as_bytes(),
    )
    .expect("measurement");
}

/// ´test:unit:changed-journal-adds-one-scan-to-capture´
#[test]
fn changed_journal_adds_one_scan_to_capture() {
    for same_size in [false, true] {
        let f = Fixture::new("box");
        let identity = f.post("one.md", 1);
        f.receipt(&identity);
        let journal = f.round.join("letters.jsonl");
        let old_bytes = fs::metadata(&journal).expect("journal").len();
        fs::write(f.round.join(".letter-count"), b"1").expect("delivered");
        let config = crate::driver::follow::Config {
            run_dir: f.round.clone(),
            cap: 50_000,
            bounce: 30,
            wait: 2,
            save_offset: true,
        };
        let (mut capture, mut messages) = (Vec::new(), Vec::new());
        let mut waits = 0;
        crate::driver::follow::run_with_messages_wait(&config, &mut capture, &mut messages, |_| {
            waits += 1;
            assert_eq!(waits, 1, "the next poll must serve the changed journal");
            if same_size {
                let bytes = fs::read_to_string(&journal)
                    .expect("journal")
                    .replace("one.md", "two.md");
                fs::write(&journal, bytes).expect("same-size journal rewrite");
                File::options()
                    .write(true)
                    .open(&journal)
                    .expect("journal")
                    .set_times(std::fs::FileTimes::new().set_modified(
                        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123),
                    ))
                    .expect("distinct measured mtime");
                assert_eq!(fs::metadata(&journal).expect("journal").len(), old_bytes);
            } else {
                f.post("two.md", 2);
            }
        })
        .expect("capture");
        let value: Value = serde_json::from_slice(&capture).expect("one envelope");
        let cost = &value["records"][0]["cost"];
        assert_eq!(cost["scans"], 2);
        assert_eq!(
            cost["journal_bytes"],
            old_bytes + fs::metadata(&journal).expect("journal").len()
        );
        assert_eq!(cost["receipt_names"], 2);
        assert!(
            String::from_utf8(messages)
                .expect("notices")
                .contains("NEW MESSAGE name=two.md")
        );
        std::io::Write::write_all(
            &mut std::io::stdout(),
            format!("same_size={same_size} scan cost={cost}\n").as_bytes(),
        )
        .expect("measurement");
    }
}

/// ´test:unit:outbox-cache-observes-receipt-and-directory-changes´
#[test]
fn outbox_cache_observes_receipt_and_directory_changes() {
    let f = Fixture::new("box");
    let identity = f.post("one.md", 1);
    let mut scanner = Scanner::default();
    assert_eq!(scanner.poll(&f.round).expect("first").len(), 1);
    assert_eq!(scanner.poll(&f.round).expect("quiet").len(), 1);
    assert_eq!(scanner.cost.value()["scans"], 1);
    f.receipt(&identity);
    assert_eq!(scanner.poll(&f.round).expect("receipt"), []);
    assert_eq!(scanner.cost.value()["scans"], 2);
    fs::write(
        f.round.join(".reply-receipts/.tmp-unpublished"),
        b"metadata",
    )
    .expect("receipt directory mtime change");
    assert_eq!(scanner.poll(&f.round).expect("directory only"), []);
    assert_eq!(scanner.cost.value()["scans"], 3);
    assert_eq!(scanner.poll(&f.round).expect("quiet again"), []);
    assert_eq!(scanner.cost.value()["scans"], 3);
}

/// ´test:unit:cached-outbox-rechecks-ancestor-custody´
#[test]
fn cached_outbox_rechecks_ancestor_custody() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let mut scanner = Scanner::default();
    assert_eq!(scanner.poll(&f.round).expect("first").len(), 1);
    fs::set_permissions(&f.round, fs::Permissions::from_mode(0o600)).expect("remove search");
    let error = scanner
        .poll(&f.round)
        .expect_err("changed search permission");
    assert_eq!(error.kind, "outbox-search");
    fs::set_permissions(&f.round, fs::Permissions::from_mode(0o700)).expect("restore");
}

/// ´test:unit:failed-outbox-rescan-never-serves-stale-replies´
#[test]
fn failed_outbox_rescan_never_serves_stale_replies() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let journal = f.round.join("letters.jsonl");
    let saved = fs::read(&journal).expect("saved journal");
    let mut scanner = Scanner::default();
    assert_eq!(scanner.poll(&f.round).expect("first scan").len(), 1);
    fs::write(&journal, b"invalid\n").expect("changed journal");
    for count in [2, 3] {
        let error = scanner
            .poll(&f.round)
            .expect_err("failed rescan cannot cache old replies");
        assert_eq!(error.kind, "outbox-journal");
        assert_eq!(scanner.cost.value()["scans"], count);
        assert!(!scanner.ready);
    }
    fs::write(&journal, saved).expect("repair journal");
    assert_eq!(
        scanner
            .poll(&f.round)
            .expect("fresh scan after repair")
            .len(),
        1
    );
    assert_eq!(scanner.cost.value()["scans"], 4);
}

/// ´test:unit:cached-outbox-invalidates-on-plan-change´
#[test]
fn cached_outbox_invalidates_on_plan_change() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let plan = f.root.join("plan.json");
    let original = fs::read(&plan).expect("plan bytes");
    let mut scanner = Scanner::default();
    assert_eq!(scanner.poll(&f.round).expect("planned scan").len(), 1);
    fs::write(&plan, json!({"home":"", "driver_dir":f.root}).to_string())
        .expect("no mailbox coverage");
    assert_eq!(scanner.poll(&f.round).expect("changed plan"), []);
    assert_eq!(scanner.cost.value()["scans"], 2);
    fs::write(&plan, original).expect("restore plan");
    assert_eq!(scanner.poll(&f.round).expect("restored coverage").len(), 1);
    assert_eq!(scanner.cost.value()["scans"], 3);
}

/// ´test:unit:cached-outbox-invalidates-on-run-binding-replacement´
#[test]
fn cached_outbox_invalidates_on_run_binding_replacement() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let plan = fs::read(f.root.join("plan.json")).expect("plan bytes");
    let mut scanner = Scanner::default();
    assert_eq!(scanner.poll(&f.round).expect("first run")[0].name, "one.md");
    fs::rename(&f.root, f.temp.path().join("prior-run")).expect("detach held run");
    fs::create_dir_all(&f.round).expect("replacement run binding");
    fs::write(f.root.join("plan.json"), plan).expect("same recorded plan");
    f.post("two.md", 2);
    assert_eq!(
        scanner.poll(&f.round).expect("replacement binding")[0].name,
        "two.md"
    );
    assert_eq!(scanner.cost.value()["scans"], 2);
    assert_eq!(
        scanner.poll(&f.round).expect("quiet replacement")[0].name,
        "two.md"
    );
    assert_eq!(scanner.cost.value()["scans"], 2);
}

/// ´test:unit:reservation-rewrites-do-not-invalidate-outbox-cache´
#[test]
fn reservation_rewrites_do_not_invalidate_outbox_cache() {
    let f = Fixture::new("box");
    let reservation = f.temp.path().join(".reservation-R.json");
    fs::write(&reservation, b"owner-only input").expect("reservation");
    fs::set_permissions(&reservation, fs::Permissions::from_mode(0o600)).expect("owner only");
    f.post("one.md", 1);
    let mut scanner = Scanner::default();
    let before = scanner.poll(&f.round).expect("first scan");
    let temporary = f.temp.path().join(".tmp-reservation");
    fs::write(&temporary, b"changed owner-only input").expect("new reservation");
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).expect("owner only");
    fs::rename(temporary, reservation).expect("reservation publication");
    assert_eq!(scanner.poll(&f.round).expect("same observations"), before);
    assert_eq!(scanner.cost.value()["scans"], 1);
}

/// ´test:unit:same-size-journal-rename-invalidates-with-unchanged-mtime´
#[test]
fn same_size_journal_rename_invalidates_with_unchanged_mtime() {
    let f = Fixture::new("box");
    f.post("one.md", 1);
    let journal = f.round.join("letters.jsonl");
    let before = fs::metadata(&journal).expect("original journal metadata");
    let mut scanner = Scanner::default();
    assert_eq!(
        scanner.poll(&f.round).expect("first scan")[0].name,
        "one.md"
    );
    let temporary = f.round.join(".tmp-journal");
    let replacement = fs::read_to_string(&journal)
        .expect("journal rows")
        .replace("one.md", "two.md");
    fs::write(&temporary, replacement).expect("same-size replacement");
    // Deliberately preserve mtime: this proves inode detection, not clock resolution.
    File::options()
        .write(true)
        .open(&temporary)
        .expect("staged journal")
        .set_times(std::fs::FileTimes::new().set_modified(before.modified().expect("old mtime")))
        .expect("preserve mtime");
    fs::rename(temporary, &journal).expect("atomic journal replacement");
    let after = fs::metadata(&journal).expect("replacement metadata");
    assert_eq!(
        (after.len(), after.mtime(), after.mtime_nsec()),
        (before.len(), before.mtime(), before.mtime_nsec())
    );
    assert_ne!(after.ino(), before.ino());
    assert_eq!(
        scanner.poll(&f.round).expect("inode invalidation")[0].name,
        "two.md"
    );
    assert_eq!(scanner.cost.value()["scans"], 2);
}

/// ´test:unit:failed-reply-publication-does-not-advance-event-offset´
#[test]
fn failed_reply_publication_does_not_advance_event_offset() {
    struct Refuse;
    impl std::io::Write for Refuse {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed message stream"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new("box");
    f.post("reply.md", 1);
    fs::write(f.round.join("events.jsonl"), b"event\n").expect("events");
    let config = crate::driver::follow::Config {
        run_dir: f.round.clone(),
        cap: 50_000,
        bounce: 0,
        wait: 1,
        save_offset: true,
    };
    let mut capture = Vec::new();
    assert_eq!(
        crate::driver::follow::run_with_messages(&config, &mut capture, &mut Refuse),
        Err(crate::driver::follow::FeedError::Relay)
    );
    assert!(!f.round.join(".feed-offset").exists());
    let document: Value = serde_json::from_slice(&capture).expect("stdout was published");
    assert!(
        document["records"]
            .as_array()
            .expect("records")
            .iter()
            .any(|r| r["kind"] == "delta")
    );
}
