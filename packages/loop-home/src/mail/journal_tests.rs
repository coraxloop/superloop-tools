use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mail-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        Self(root)
    }
    fn directory(&self) -> File {
        File::open(&self.0).expect("fixture root descriptor")
    }
    fn create(&self) -> Journal {
        Journal::create(self.directory()).expect("create journal")
    }
    fn open(&self) -> Journal {
        Journal::open(self.directory()).expect("recover journal")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned fixture");
    }
}
fn instant(value: &str) -> Instant {
    Instant::parse(value).expect("fixture instant")
}
fn first() -> Instant {
    instant("2026-01-01T00:00:00.000Z")
}
fn later() -> Instant {
    instant("2026-02-01T00:00:00.000Z")
}
fn record(time: &Instant) -> Record {
    Record {
        version: 1,
        delivery: time.clone(),
        acceptance: time.clone(),
        sender: "alpha".into(),
        recipient: "beta+w".into(),
        outgoing: "beta+w.01.letter".into(),
        bytes: 3,
        digest: digest(b"\0\xff\n"),
        registry_digest: digest(b"registry"),
        configuration_digests: vec![digest(b"loop-config")],
        source_path: "/fixture/alpha/.mail-staging/source".into(),
        source_identity: Identity {
            device: 1,
            inode: 2,
        },
        recipient_temporary: Temporary {
            path: "/fixture/beta/workers/w/.mail-staging/payload".into(),
            identity: Identity {
                device: 1,
                inode: 3,
            },
        },
        sender_temporary: None,
        sent_name: format!("beta+w.{time}.letter"),
        inbox_name: format!("alpha.{time}.letter"),
        phase: Phase::Accepted,
        completed: None,
        pending_error: None,
        discard_disposition: None,
    }
}
fn present(record: &Record) -> Witness {
    Witness::Present {
        identity: record.recipient_temporary.identity.clone(),
        bytes: record.bytes,
        digest: record.digest.clone(),
    }
}
fn accept(journal: &mut Journal) -> Record {
    let record = record(&journal.reserve(first()).expect("reserve"));
    journal.accept(&record).expect("accept");
    record
}
fn complete(journal: &mut Journal, record: &Record) {
    journal
        .advance(&record.delivery, Phase::Sent, &present(record), first())
        .expect("sent");
    journal
        .advance(&record.delivery, Phase::Inbox, &Witness::Absent, first())
        .expect("inbox");
    journal
        .advance(&record.delivery, Phase::Complete, &Witness::Absent, first())
        .expect("complete");
}

/// ´claim:loophome:journal-clock-watermark-survives-restart-and-compaction´
/// ´test:unit:journal-clock-watermark-survives-restart-and-compaction´
#[test]
fn journal_clock_watermark_survives_restart_and_compaction() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    complete(&mut journal, &record);
    assert_eq!(journal.prune(&later(), &Pins::default()).expect("prune"), 1);
    assert!(
        journal.accept(&record).is_err(),
        "compaction cannot make a reserved instant reusable"
    );
    drop(journal);
    let mut journal = fixture.open();
    for now in [first(), instant("2025-12-31T23:59:59.999Z")] {
        assert!(matches!(journal.reserve(now), Err(MailError::ClockWait)));
    }
    journal
        .reserve(instant("2026-01-01T00:00:00.001Z"))
        .expect("actual later tick");
}

/// ´claim:loophome:journal-calendar-checks-the-exact-mail-language´
/// ´test:unit:journal-calendar-checks-the-exact-mail-language´
#[test]
fn journal_calendar_checks_the_exact_mail_language() {
    for value in [
        "0001-01-01T00:00:00.000Z",
        "9999-12-31T23:59:59.999Z",
        "2000-02-29T12:00:00.001Z",
    ] {
        assert_eq!(instant(value).to_string(), value);
    }
    for value in [
        "0000-01-01T00:00:00.000Z",
        "1900-02-29T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-01-01T00:00:60.000Z",
        "2026-01-01T24:00:00.000Z",
        "2026-01-01T00:00:00.00Z",
        "2026-01-01t00:00:00.000Z",
    ] {
        assert!(Instant::parse(value).is_err(), "{value}");
    }
    assert_eq!(instant("0001-01-01T00:00:00.000Z").millis(), 0);
    assert_eq!(
        instant("2000-03-01T00:00:00.000Z").millis() - instant("2000-02-28T00:00:00.000Z").millis(),
        172_800_000
    );
}

/// ´claim:loophome:journal-witness-states-do-not-use-inbox-survival´
/// ´test:unit:journal-witness-states-do-not-use-inbox-survival´
#[test]
fn journal_witness_states_do_not_use_inbox_survival() {
    let mut record = record(&first());
    for phase in [Phase::Accepted, Phase::Sent] {
        record.phase = phase;
        assert_eq!(
            recover(&record, &present(&record)).expect("present"),
            Recovery::Publish
        );
        assert_eq!(
            recover(&record, &Witness::Absent).expect("renamed"),
            Recovery::Finish
        );
    }
    record.phase = Phase::Inbox;
    assert_eq!(
        recover(&record, &Witness::Absent).expect("already moved into read"),
        Recovery::Finish
    );
    assert!(recover(&record, &present(&record)).is_err());
    record.phase = Phase::Complete;
    record.completed = Some(first());
    assert_eq!(
        recover(&record, &Witness::Absent).expect("complete"),
        Recovery::Terminal
    );
    assert!(recover(&record, &Witness::Invalid).is_err());
}

/// ´claim:loophome:journal-discard-remains-discard-across-every-witness-state´
/// ´test:unit:journal-discard-remains-discard-across-every-witness-state´
#[test]
fn journal_discard_remains_discard_across_every_witness_state() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    assert!(
        journal
            .discard(&first(), &Witness::Absent, "restore original outbox")
            .is_err()
    );
    journal
        .discard(
            &first(),
            &present(&record),
            "restore original outbox without overwrite",
        )
        .expect("durable discard");
    drop(journal);
    let mut journal = fixture.open();
    let discarded = journal.record(&first()).expect("record");
    for witness in [present(&record), Witness::Absent] {
        assert_eq!(
            recover(&discarded, &witness).expect("discard recovery"),
            Recovery::Discard
        );
    }
    journal
        .pending(&first(), "source restoration collision")
        .expect("pending repair");
    assert_eq!(
        journal
            .prune(&later(), &Pins::default())
            .expect("pending pin"),
        0
    );
    journal
        .finish_discard(&first(), first())
        .expect("restored and synced");
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(
        recover(&journal.record(&first()).expect("record"), &Witness::Absent).expect("terminal"),
        Recovery::Terminal
    );
    let terminal = journal.record(&first()).expect("terminal record");
    assert_eq!(terminal.completed, Some(later()));
    assert!(terminal.pending_error.is_none());
    assert_eq!(
        journal
            .prune(&later(), &Pins::default())
            .expect("age postponed"),
        0
    );
    assert_eq!(
        journal
            .prune(&instant("2026-03-03T00:00:00.000Z"), &Pins::default())
            .expect("history interval elapsed"),
        1
    );
}

/// ´claim:loophome:journal-provenance-requires-exact-scoped-publication-evidence´
/// ´test:unit:journal-provenance-requires-exact-scoped-publication-evidence´
#[test]
fn journal_provenance_requires_exact_scoped_publication_evidence() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    let recipient = Address::parse(&record.recipient).expect("recipient");
    let verify = |j: &Journal, w: &Witness| {
        j.verify(
            &recipient,
            &first(),
            &record.inbox_name,
            record.bytes,
            &record.digest,
            w,
        )
        .expect("verification")
    };
    assert_eq!(
        verify(&journal, &present(&record)),
        Verification::ForgedLocalEntry
    );
    journal
        .advance(&first(), Phase::Sent, &present(&record), first())
        .expect("sent only");
    assert_eq!(
        verify(&journal, &present(&record)),
        Verification::ForgedLocalEntry
    );
    assert_eq!(
        verify(&journal, &Witness::Absent),
        Verification::Delivered,
        "rename witness proves publication before phase update"
    );
    for (actor, name, bytes, digest) in [
        (
            Address::parse("other").expect("address"),
            record.inbox_name.clone(),
            record.bytes,
            record.digest.clone(),
        ),
        (
            recipient.clone(),
            "forged.letter".into(),
            record.bytes,
            record.digest.clone(),
        ),
        (
            recipient.clone(),
            record.inbox_name.clone(),
            record.bytes + 1,
            record.digest.clone(),
        ),
        (
            recipient.clone(),
            record.inbox_name.clone(),
            record.bytes,
            digest(b"wrong"),
        ),
    ] {
        assert_eq!(
            journal
                .verify(&actor, &first(), &name, bytes, &digest, &Witness::Absent)
                .expect("verdict"),
            Verification::ForgedLocalEntry
        );
    }
    assert_eq!(
        journal
            .verify(
                &recipient,
                &later(),
                &record.inbox_name,
                3,
                &record.digest,
                &Witness::Absent
            )
            .expect("unknown"),
        Verification::ForgedLocalEntry
    );
    complete_from_sent(&mut journal);
    journal.prune(&later(), &Pins::default()).expect("prune");
    assert_eq!(
        journal.unrecorded_sent(&first()),
        Verification::CompactedHistory
    );
    assert_eq!(
        verify(&journal, &Witness::Absent),
        Verification::ForgedLocalEntry,
        "summary is not individual proof"
    );
}
fn complete_from_sent(journal: &mut Journal) {
    journal
        .advance(&first(), Phase::Inbox, &Witness::Absent, first())
        .expect("inbox");
    journal
        .advance(&first(), Phase::Complete, &Witness::Absent, first())
        .expect("complete");
}

/// ´claim:loophome:journal-retention-preserves-live-pins-and-postpones-backward-time´
/// ´test:unit:journal-retention-preserves-live-pins-and-postpones-backward-time´
#[test]
fn journal_retention_preserves_live_pins_and_postpones_backward_time() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    complete(&mut journal, &record);
    assert_eq!(
        journal
            .prune(&instant("2026-01-30T23:59:59.999Z"), &Pins::default())
            .expect("too young"),
        0
    );
    let mut pins = Pins::default();
    pins.active_inboxes.insert(first());
    assert_eq!(
        journal.prune(&later(), &pins).expect("active inbox pins"),
        0
    );
    pins.active_inboxes.clear();
    pins.reservations.insert(first());
    assert_eq!(journal.prune(&later(), &pins).expect("reservation pins"), 0);
    pins.reservations.clear();
    assert_eq!(
        journal
            .prune(&instant("2026-01-31T00:00:00.000Z"), &pins)
            .expect("backward time"),
        0
    );
    assert_eq!(
        journal
            .prune(&later(), &pins)
            .expect("retired/read/sent copies do not pin"),
        1
    );
    assert_eq!(journal.records().expect("records"), [] as [Record; 0]);
}

/// ´claim:loophome:journal-compaction-recovery-folds-each-record-once´
/// ´test:unit:journal-compaction-recovery-folds-each-record-once´
#[test]
fn journal_compaction_recovery_folds_each_record_once() {
    for deleted in [false, true] {
        let fixture = Fixture::new();
        let mut journal = fixture.create();
        let record = accept(&mut journal);
        complete(&mut journal, &record);
        CRASH_AFTER_CHECKPOINT.with(|flag| flag.set(true));
        assert!(journal.prune(&later(), &Pins::default()).is_err());
        let head = journal.checkpoint.head.clone();
        if deleted {
            store::remove(&journal.records, &format!("{}.toml", first()))
                .expect("deletion durable before crash");
        }
        drop(journal);
        let mut journal = fixture.open();
        assert_eq!(journal.checkpoint.count, 1);
        assert_eq!(journal.checkpoint.head, head);
        assert!(journal.checkpoint.pending.is_none());
        assert_eq!(
            journal
                .prune(&later(), &Pins::default())
                .expect("repeat prune"),
            0
        );
        assert!(
            fs::metadata(fixture.0.join("checkpoint.toml"))
                .expect("checkpoint")
                .len()
                <= SUMMARY_MAX_BYTES
        );
        assert_eq!(
            store::names(&journal.root).expect("bounded state"),
            ["checkpoint.toml", "deliveries", "state.toml", "writer.lock"]
        );
    }
}

/// ´claim:loophome:journal-capacity-includes-scratch-and-never-evicts-pins´
/// ´test:unit:journal-capacity-includes-scratch-and-never-evicts-pins´
#[test]
fn journal_capacity_includes_scratch_and_never_evicts_pins() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    assert!(
        journal
            .capacity(STAGING_MAX_BYTES - MAX_LETTER_BYTES * 3)
            .is_ok()
    );
    assert!(matches!(
        journal.capacity(STAGING_MAX_BYTES - MAX_LETTER_BYTES * 3 + 1),
        Err(MailError::Capacity)
    ));
    let padding_path = fixture.0.join("pinned-capacity");
    let file = fs::File::create(&padding_path).expect("capacity fixture");
    fs::set_permissions(&padding_path, fs::Permissions::from_mode(0o600)).expect("private fixture");
    let current = store::size(&journal.root).expect("account journal bytes");
    let room = JOURNAL_MAX_BYTES - current - 3 * RECORD_MAX_BYTES - 3 * SUMMARY_MAX_BYTES;
    file.set_len(room).expect("inclusive capacity fixture");
    journal
        .capacity(0)
        .expect("inclusive journal cap reserves all scratch");
    file.set_len(room + 1).expect("one byte over capacity");
    assert!(matches!(journal.capacity(0), Err(MailError::Capacity)));
    assert_eq!(
        journal
            .record(&record.delivery)
            .expect("pending payload record preserved"),
        record
    );
}

/// ´claim:loophome:journal-refuses-corruption-unsafe-storage-and-concurrent-writers´
/// ´test:unit:journal-refuses-corruption-unsafe-storage-and-concurrent-writers´
#[test]
fn journal_refuses_corruption_unsafe_storage_and_concurrent_writers() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    assert!(
        Journal::open(fixture.directory()).is_err(),
        "exclusive writer"
    );
    let record = accept(&mut journal);
    let bad = Witness::Present {
        identity: Identity {
            device: 99,
            inode: 3,
        },
        bytes: 3,
        digest: record.digest.clone(),
    };
    assert!(recover(&record, &bad).is_err());
    drop(journal);
    let state = fixture.0.join("state.toml");
    let saved = fs::read(&state).expect("state");
    fs::write(&state, b"version = 2\n").expect("corrupt state");
    assert!(Journal::open(fixture.directory()).is_err());
    fs::write(&state, &saved).expect("restore fixture");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert!(Journal::open(fixture.directory()).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).expect("private again");
    fs::remove_file(&state).expect("remove state");
    assert!(
        Journal::open(fixture.directory()).is_err(),
        "missing state is never invented"
    );
    symlink("checkpoint.toml", &state).expect("symlink state");
    assert!(Journal::open(fixture.directory()).is_err());
}

/// ´claim:loophome:journal-metadata-interruption-preserves-committed-state´
/// ´test:unit:journal-metadata-interruption-preserves-committed-state´
#[test]
fn journal_metadata_interruption_preserves_committed_state() {
    for boundary in 1..=4 {
        let fixture = Fixture::new();
        let mut journal = fixture.create();
        let record = accept(&mut journal);
        store::INTERRUPT.with(|selected| selected.set(boundary));
        assert!(
            journal
                .discard(&first(), &present(&record), "restore source")
                .is_err()
        );
        drop(journal);
        let journal = fixture.open();
        let recovered = journal.record(&first()).expect("recover committed phase");
        let expected = if boundary < 3 {
            Recovery::Publish
        } else {
            Recovery::Discard
        };
        assert_eq!(
            recover(&recovered, &present(&record)).expect("decision"),
            expected
        );
        assert!(
            store::names(&journal.records)
                .expect("no scratch")
                .iter()
                .all(|n| !n.ends_with(".replace"))
        );
    }
}

/// ´claim:loophome:journal-uncommitted-acceptance-needs-source-reconciliation´
/// ´test:unit:journal-uncommitted-acceptance-needs-source-reconciliation´
#[test]
fn journal_uncommitted_acceptance_needs_source_reconciliation() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = record(&journal.reserve(first()).expect("reserve"));
    // Model a synced initial record interrupted before its no-replace rename.
    let scratch = format!(".{}.toml.replace", first());
    store::write(&journal.root, &journal.records, &scratch, &record, false)
        .expect("uncommitted metadata fixture");
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(journal.uncommitted(), vec![record.clone()]);
    assert_eq!(
        journal.records().expect("committed records"),
        [] as [Record; 0]
    );
    assert!(journal.reserve(later()).is_err());
    assert!(
        journal
            .reconcile_uncommitted(&first(), &record.outgoing, 3, &digest(b"wrong"))
            .is_err()
    );
    assert_eq!(journal.uncommitted().len(), 1);
    journal
        .reconcile_uncommitted(&first(), &record.outgoing, record.bytes, &record.digest)
        .expect("adapter proves durable source restoration");
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(journal.uncommitted(), [] as [Record; 0]);
    journal
        .reserve(later())
        .expect("admission resumes after reconciliation");
}

/// ´claim:loophome:journal-terminal-clock-rollback-postpones-uncertain-history´
/// ´test:unit:journal-terminal-clock-rollback-postpones-uncertain-history´
#[test]
fn journal_terminal_clock_rollback_postpones_uncertain_history() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let record = accept(&mut journal);
    journal
        .pending(&first(), "transient publication failure")
        .expect("pending repair");
    journal
        .advance(&first(), Phase::Inbox, &Witness::Absent, first())
        .expect("published");
    journal
        .advance(
            &first(),
            Phase::Complete,
            &Witness::Absent,
            instant("2025-01-01T00:00:00.000Z"),
        )
        .expect("cleanup remains terminal despite rollback");
    let terminal = journal.record(&record.delivery).expect("record");
    assert_eq!(terminal.completed, Some(first()));
    assert!(
        terminal.pending_error.is_none(),
        "resolved failure no longer pins"
    );
    assert_eq!(
        journal
            .prune(&instant("2026-01-30T23:59:59.999Z"), &Pins::default())
            .expect("age measured from the latest known instant"),
        0
    );
    assert_eq!(
        journal
            .prune(&later(), &Pins::default())
            .expect("eligible after the history interval"),
        1
    );
}

/// ´claim:loophome:journal-compaction-chain-commits-records-in-delivery-order´
/// ´test:unit:journal-compaction-chain-commits-records-in-delivery-order´
#[test]
fn journal_compaction_chain_commits_records_in_delivery_order() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let mut expected = ZERO_DIGEST.to_owned();
    for time in [
        first(),
        instant("2026-01-01T00:00:00.001Z"),
        instant("2026-01-01T00:00:00.002Z"),
    ] {
        let item = record(&journal.reserve(time.clone()).expect("reserve"));
        journal.accept(&item).expect("accept");
        journal
            .advance(&time, Phase::Inbox, &Witness::Absent, time.clone())
            .expect("publication witness");
        journal
            .advance(&time, Phase::Complete, &Witness::Absent, time.clone())
            .expect("terminal");
        let bytes = store::bytes(&journal.records, &format!("{time}.toml"), RECORD_MAX_BYTES)
            .expect("exact record bytes");
        expected = digest(format!("{expected}\n{}\n", digest(&bytes)).as_bytes());
    }
    assert_eq!(
        journal
            .prune(&later(), &Pins::default())
            .expect("sorted compaction"),
        3
    );
    assert_eq!(journal.checkpoint.count, 3);
    assert_eq!(journal.checkpoint.head, expected);
    drop(journal);
    assert_eq!(fixture.open().checkpoint.head, expected);
}

/// ´claim:loophome:journal-corruption-does-not-destroy-replacement-evidence´
/// ´test:unit:journal-corruption-does-not-destroy-replacement-evidence´
#[test]
fn journal_corruption_does_not_destroy_replacement_evidence() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let item = accept(&mut journal);
    store::INTERRUPT.with(|selected| selected.set(1));
    assert!(
        journal
            .discard(&first(), &present(&item), "restore source")
            .is_err()
    );
    let scratch = fixture
        .0
        .join("deliveries")
        .join(format!(".{}.toml.replace", first()));
    let retained = fs::read(&scratch).expect("replacement witness");
    fs::write(
        fixture
            .0
            .join("deliveries")
            .join(format!("{}.toml", first())),
        b"corrupt",
    )
    .expect("corrupt fixture");
    drop(journal);
    assert!(Journal::open(fixture.directory()).is_err());
    assert_eq!(
        fs::read(&scratch).expect("reconciliation evidence retained"),
        retained
    );
}

/// ´claim:loophome:journal-record-growth-preserves-compaction-scratch´
/// ´test:unit:journal-record-growth-preserves-compaction-scratch´
#[test]
fn journal_record_growth_preserves_compaction_scratch() {
    let fixture = Fixture::new();
    let mut journal = fixture.create();
    let item = accept(&mut journal);
    complete(&mut journal, &item);
    let padding_path = fixture.0.join("pinned-capacity");
    let padding = File::create(&padding_path).expect("capacity fixture");
    fs::set_permissions(&padding_path, fs::Permissions::from_mode(0o600)).expect("private padding");
    let current = store::size(&journal.root).expect("journal size");
    padding
        .set_len(JOURNAL_MAX_BYTES - current - 2 * SUMMARY_MAX_BYTES)
        .expect("reserve only compaction scratch");
    let terminal = journal.record(&first()).expect("terminal");
    assert!(matches!(
        journal.replace(&terminal),
        Err(MailError::Capacity)
    ));
    assert_eq!(
        journal
            .prune(&later(), &Pins::default())
            .expect("scratch remains available for compaction"),
        1
    );
    assert!(store::size(&journal.root).expect("bounded journal") <= JOURNAL_MAX_BYTES);
}
