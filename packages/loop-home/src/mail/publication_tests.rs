use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const DURABLE: Durability = Durability {
    crash_consistent_rename: true,
    durable_sync: true,
};
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mail-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture");
        Self { root }
    }
    fn endpoint(&self, name: &str, group: u32) -> Endpoint {
        let address = Address::parse(name).expect("fixture address");
        let mailbox = self.root.join(address.relative_mailbox());
        fs::create_dir_all(&mailbox).expect("mailbox");
        for (path, mode) in [
            (mailbox.clone(), 0o750),
            (mailbox.join("inbox"), 0o770),
            (mailbox.join("sent"), 0o770),
            (mailbox.join("outbox"), 0o700),
            (mailbox.join("read"), 0o700),
            (mailbox.join("draft"), 0o700),
        ] {
            if path != mailbox {
                fs::create_dir(&path).expect("folder");
            }
            let directory = File::open(&path).expect("directory");
            fchown(&directory, None, Some(Gid::from_raw(group)))
                .expect("fixture actor group is mapped to test account");
            fchmod(&directory, Mode::from_bits_truncate(mode)).expect("directory mode");
        }
        let staging = mailbox
            .parent()
            .expect("actor parent")
            .join(".mail-staging");
        fs::create_dir(&staging).expect("staging");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).expect("private staging");
        Endpoint::open(&self.root, address, group, DURABLE)
            .expect("provisioned publication endpoint")
    }
    fn journal(&self) -> Journal {
        let root = self.root.join(".mail-service");
        fs::create_dir(&root).expect("journal");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private journal");
        Journal::create(File::open(root).expect("journal root")).expect("create journal")
    }
    fn reopen(&self) -> Journal {
        Journal::open(File::open(self.root.join(".mail-service")).expect("journal root"))
            .expect("recover journal")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        STOP.with(|stop| stop.set(None));
        OBSERVE.with(|observer| *observer.borrow_mut() = None);
        fs::remove_dir_all(&self.root).expect("remove fixture-owned tree");
    }
}
fn now() -> Instant {
    Instant::parse("2026-01-01T00:00:00.001Z").expect("fixture instant")
}
fn group() -> u32 {
    nix::unistd::getegid().as_raw()
}
fn other_group() -> u32 {
    nix::unistd::getgroups()
        .expect("fixture groups")
        .into_iter()
        .map(Gid::as_raw)
        .find(|gid| *gid != group())
        .expect("publication copy fixture requires a second mapped supplementary group")
}
fn source(sender: &Endpoint, recipient: &Endpoint, bytes: &[u8]) -> String {
    let outgoing = format!("{}.01.letter", recipient.address);
    fs::write(sender.staging_path.join(&outgoing), bytes).expect("claimed source fixture");
    outgoing
}
fn accepted(
    journal: &mut Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
) -> Record {
    journal
        .capacity(staging_bytes(&[sender, recipient]).expect("aggregate staging"))
        .expect("reserve full copies");
    prepare(journal, sender, recipient, outgoing)
        .expect("synced snapshots")
        .accept(
            journal,
            now(),
            digest(b"registry"),
            vec![digest(b"configuration")],
        )
        .expect("durable acceptance")
}
fn read(endpoint: &Endpoint, folder: &str, name: &str) -> Vec<u8> {
    fs::read(endpoint.mailbox_path.join(folder).join(name)).expect("published bytes")
}

/// ´claim:loophome:mail-publication-links-only-readable-shared-inodes´
/// ´test:unit:mail-publication-links-only-readable-shared-inodes´
#[test]
fn mail_publication_links_only_readable_shared_inodes() {
    for bytes in [
        Vec::new(),
        vec![0, 255, 10],
        vec![42; usize::try_from(MAX_LETTER_BYTES).expect("fixture size")],
    ] {
        let fixture = Fixture::new();
        let endpoint = fixture.endpoint("0-loop", group());
        let mut journal = fixture.journal();
        let outgoing = source(&endpoint, &endpoint, &bytes);
        let record = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
        assert!(record.sender_temporary.is_none());
        assert_eq!(
            staging_bytes(&[&endpoint, &endpoint]).expect("aliases count once"),
            bytes.len() as u64 * 2
        );
        publish(&mut journal, &endpoint, &endpoint, &record.delivery).expect("publish");
        assert_eq!(read(&endpoint, "inbox", &record.inbox_name), bytes);
        assert_eq!(read(&endpoint, "sent", &record.sent_name), bytes);
        let inbox = fs::metadata(endpoint.mailbox_path.join("inbox").join(&record.inbox_name))
            .expect("inbox identity");
        let sent = fs::metadata(endpoint.mailbox_path.join("sent").join(&record.sent_name))
            .expect("sent identity");
        assert_eq!(identity(&inbox), identity(&sent));
        assert_eq!(inbox.mode() & 0o777, 0o640);
        cleanup_source(
            &endpoint,
            &endpoint,
            &journal.record(&record.delivery).expect("phase"),
        )
        .expect("source cleanup");
        journal
            .advance(&record.delivery, Phase::Complete, &Witness::Absent, now())
            .expect("complete after sidecar cleanup");
        assert_eq!(
            staging_bytes(&[&endpoint]).expect("no temporary payloads"),
            0
        );
    }
}

/// ´claim:loophome:mail-publication-copies-for-distinct-actor-read-groups´
/// ´test:unit:mail-publication-copies-for-distinct-actor-read-groups´
#[test]
fn mail_publication_copies_for_distinct_actor_read_groups() {
    let fixture = Fixture::new();
    let sender = fixture.endpoint("alpha", group());
    let recipient = fixture.endpoint("beta+worker", other_group());
    let mut journal = fixture.journal();
    let bytes = b"\0\xffopaque\n";
    let outgoing = source(&sender, &recipient, bytes);
    let record = accepted(&mut journal, &sender, &recipient, &outgoing);
    assert!(record.sender_temporary.is_some());
    assert_eq!(
        staging_bytes(&[&sender, &recipient]).expect("three independent copies"),
        bytes.len() as u64 * 3
    );
    publish(&mut journal, &sender, &recipient, &record.delivery).expect("copy path");
    let sent = fs::metadata(sender.mailbox_path.join("sent").join(&record.sent_name))
        .expect("sender copy");
    let inbox = fs::metadata(
        recipient
            .mailbox_path
            .join("inbox")
            .join(&record.inbox_name),
    )
    .expect("inbox");
    assert_ne!(identity(&sent), identity(&inbox));
    assert_eq!(sent.gid(), sender.group);
    assert_eq!(inbox.gid(), recipient.group);
    assert_eq!(sent.mode() & 0o777, 0o640);
    assert_eq!(inbox.mode() & 0o777, 0o640);
    assert_eq!(read(&sender, "sent", &record.sent_name), bytes);
    assert_eq!(read(&recipient, "inbox", &record.inbox_name), bytes);
}

/// ´claim:loophome:mail-publication-recovers-every-durable-boundary-without-redelivery´
/// ´test:unit:mail-publication-recovers-every-durable-boundary-without-redelivery´
#[test]
fn mail_publication_recovers_every_durable_boundary_without_redelivery() {
    for copy in [false, true] {
        for stop in 5..=10 {
            let fixture = Fixture::new();
            let sender = fixture.endpoint("alpha", group());
            let recipient = copy.then(|| fixture.endpoint("beta", other_group()));
            let receiver = recipient.as_ref().unwrap_or(&sender);
            let mut journal = fixture.journal();
            let outgoing = source(&sender, receiver, b"exact\0bytes");
            let record = accepted(&mut journal, &sender, receiver, &outgoing);
            let inbox = receiver.mailbox_path.join("inbox").join(&record.inbox_name);
            let history = receiver.mailbox_path.join("read/history");
            let moved = history.clone();
            OBSERVE.with(|observer| {
                *observer.borrow_mut() = Some(Box::new(move |point| {
                    if point == 8 {
                        fs::rename(&inbox, &moved).expect("actor moves inbox before phase update");
                    }
                }));
            });
            STOP.with(|selected| selected.set(Some(stop)));
            assert!(publish(&mut journal, &sender, receiver, &record.delivery).is_err());
            OBSERVE.with(|observer| *observer.borrow_mut() = None);
            drop(journal);
            let mut journal = fixture.reopen();
            publish(&mut journal, &sender, receiver, &record.delivery).expect("resume publication");
            if stop >= 8 {
                assert_eq!(fs::read(&history).expect("read history"), b"exact\0bytes");
                assert!(
                    !receiver
                        .mailbox_path
                        .join("inbox")
                        .join(&record.inbox_name)
                        .exists(),
                    "missing temporary proves rename, not redelivery"
                );
            } else {
                assert_eq!(read(receiver, "inbox", &record.inbox_name), b"exact\0bytes");
            }
            assert_eq!(
                journal.record(&record.delivery).expect("phase").phase,
                Phase::Inbox
            );
        }
    }
}

/// ´claim:loophome:mail-publication-refuses-collisions-and-changed-witnesses´
/// ´test:unit:mail-publication-refuses-collisions-and-changed-witnesses´
#[test]
fn mail_publication_refuses_collisions_and_changed_witnesses() {
    for folder in ["sent", "inbox"] {
        let fixture = Fixture::new();
        let endpoint = fixture.endpoint("alpha", group());
        let mut journal = fixture.journal();
        let outgoing = source(&endpoint, &endpoint, b"body");
        let record = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
        let name = if folder == "sent" {
            &record.sent_name
        } else {
            &record.inbox_name
        };
        let collision = endpoint.mailbox_path.join(folder).join(name);
        fs::write(&collision, b"actor entry").expect("collision fixture");
        assert!(publish(&mut journal, &endpoint, &endpoint, &record.delivery).is_err());
        assert_eq!(
            fs::read(&collision).expect("collision retained"),
            b"actor entry"
        );
        assert!(matches!(
            endpoint.witness(&record).expect("witness retained"),
            Witness::Present { .. }
        ));
    }
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"body");
    let record = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
    fs::write(&record.recipient_temporary.path, b"evil").expect("corrupt protected fixture");
    assert_eq!(
        endpoint.witness(&record).expect("invalid witness"),
        Witness::Invalid
    );
    assert!(publish(&mut journal, &endpoint, &endpoint, &record.delivery).is_err());
    assert_eq!(
        fs::read(sender_source(&endpoint, &outgoing)).expect("source retained"),
        b"body"
    );
}
fn sender_source(endpoint: &Endpoint, outgoing: &str) -> PathBuf {
    endpoint.staging_path.join(outgoing)
}

/// ´claim:loophome:mail-discard-restores-before-removing-private-payloads´
/// ´test:unit:mail-discard-restores-before-removing-private-payloads´
#[test]
fn mail_discard_restores_before_removing_private_payloads() {
    for stop in 11..=13 {
        let fixture = Fixture::new();
        let sender = fixture.endpoint("alpha", group());
        let recipient = fixture.endpoint("beta", other_group());
        let mut journal = fixture.journal();
        let outgoing = source(&sender, &recipient, b"restore\0me");
        let record = accepted(&mut journal, &sender, &recipient, &outgoing);
        STOP.with(|selected| selected.set(Some(7)));
        assert!(publish(&mut journal, &sender, &recipient, &record.delivery).is_err());
        journal
            .discard(
                &record.delivery,
                &recipient.witness(&record).expect("present"),
                "restore original outbox without overwrite",
            )
            .expect("durable discard");
        STOP.with(|selected| selected.set(Some(stop)));
        assert!(discard(&mut journal, &sender, &recipient, &record.delivery).is_err());
        // Ordinary withdrawal after restoration cannot cause another restoration.
        fs::rename(
            sender.mailbox_path.join("outbox").join(&outgoing),
            sender.mailbox_path.join("draft/withdrawn"),
        )
        .expect("withdraw restored source");
        drop(journal);
        let mut journal = fixture.reopen();
        discard(&mut journal, &sender, &recipient, &record.delivery).expect("resume discard");
        assert_eq!(
            fs::read(sender.mailbox_path.join("draft/withdrawn")).expect("restored bytes"),
            b"restore\0me"
        );
        assert!(!sender.mailbox_path.join("outbox").join(&outgoing).exists());
        assert_eq!(
            staging_bytes(&[&sender, &recipient]).expect("no pending payloads"),
            0
        );
        assert!(
            journal
                .record(&record.delivery)
                .expect("restored")
                .completed
                .is_none()
        );
        journal
            .finish_discard(&record.delivery, now())
            .expect("service records terminal after refusal projection");
        assert!(
            journal
                .record(&record.delivery)
                .expect("terminal")
                .completed
                .is_some()
        );
    }
}

/// ´claim:loophome:mail-publication-refuses-unsafe-storage-and-source-mutation´
/// ´test:unit:mail-publication-refuses-unsafe-storage-and-source-mutation´
#[test]
fn mail_publication_refuses_unsafe_storage_and_source_mutation() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let journal = fixture.journal();
    for durability in [
        Durability {
            crash_consistent_rename: false,
            durable_sync: true,
        },
        Durability {
            crash_consistent_rename: true,
            durable_sync: false,
        },
    ] {
        assert!(
            Endpoint::open(&fixture.root, endpoint.address.clone(), group(), durability).is_err()
        );
    }
    let outgoing = source(&endpoint, &endpoint, b"original");
    let path = sender_source(&endpoint, &outgoing);
    let changed = path.clone();
    OBSERVE.with(|observer| {
        *observer.borrow_mut() = Some(Box::new(move |point| {
            if point == 0 {
                fs::write(&changed, b"changed length").expect("retained writer mutation");
            }
        }));
    });
    assert!(prepare(&journal, &endpoint, &endpoint, &outgoing).is_err());
    OBSERVE.with(|observer| *observer.borrow_mut() = None);
    fs::remove_file(&path).expect("remove fixture source");
    symlink("missing", &path).expect("symlink source");
    assert!(prepare(&journal, &endpoint, &endpoint, &outgoing).is_err());
    fs::remove_file(&path).expect("remove fixture symlink");
    fs::write(
        &path,
        vec![0; usize::try_from(MAX_LETTER_BYTES).expect("fixture size") + 1],
    )
    .expect("oversize source");
    assert!(prepare(&journal, &endpoint, &endpoint, &outgoing).is_err());
    fs::write(&path, b"linked").expect("source");
    fs::hard_link(&path, endpoint.staging_path.join("extra-link")).expect("multiply linked source");
    assert!(prepare(&journal, &endpoint, &endpoint, &outgoing).is_err());
}

/// ´claim:loophome:mail-unaccepted-snapshot-cleanup-preserves-the-source´
/// ´test:unit:mail-unaccepted-snapshot-cleanup-preserves-the-source´
#[test]
fn mail_unaccepted_snapshot_cleanup_preserves_the_source() {
    for stop in 1..=4 {
        let fixture = Fixture::new();
        let endpoint = fixture.endpoint("alpha", group());
        let mut journal = fixture.journal();
        let outgoing = source(&endpoint, &endpoint, b"unpublished\0body");
        STOP.with(|selected| selected.set(Some(stop)));
        assert!(prepare(&journal, &endpoint, &endpoint, &outgoing).is_err());
        drop(journal);
        journal = fixture.reopen();
        reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing)
            .expect("prove restoration before deleting unaccepted payload");
        assert_eq!(read(&endpoint, "outbox", &outgoing), b"unpublished\0body");
        assert_eq!(
            staging_bytes(&[&endpoint]).expect("all orphan snapshots reaped"),
            0
        );
        assert_eq!(journal.records().expect("no delivery"), [] as [Record; 0]);
    }
}

/// ´claim:loophome:mail-unpublished-restoration-survives-withdrawal-after-rename´
/// ´test:unit:mail-unpublished-restoration-survives-withdrawal-after-rename´
#[test]
fn mail_unpublished_restoration_survives_withdrawal_after_rename() {
    for stop in 14..=16 {
        let fixture = Fixture::new();
        let endpoint = fixture.endpoint("alpha", group());
        let mut journal = fixture.journal();
        let outgoing = source(&endpoint, &endpoint, b"restore once");
        let _prepared =
            prepare(&journal, &endpoint, &endpoint, &outgoing).expect("snapshot before acceptance");
        STOP.with(|selected| selected.set(Some(stop)));
        assert!(reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing).is_err());
        assert!(
            journal.reserve(now()).is_err(),
            "unfinished restoration blocks admission"
        );
        if stop >= 15 {
            fs::rename(
                endpoint.mailbox_path.join("outbox").join(&outgoing),
                endpoint.mailbox_path.join("draft/withdrawn"),
            )
            .expect("ordinary withdrawal");
        }
        drop(journal);
        let mut journal = fixture.reopen();
        assert_eq!(
            pending_restorations(&journal)
                .expect("startup inventory")
                .len(),
            1
        );
        reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing)
            .expect("finish restoration from intent witness");
        if stop >= 15 {
            assert_eq!(read(&endpoint, "draft", "withdrawn"), b"restore once");
            assert!(
                !endpoint
                    .mailbox_path
                    .join("outbox")
                    .join(&outgoing)
                    .exists()
            );
        }
        assert_eq!(staging_bytes(&[&endpoint]).expect("reaped payloads"), 0);
        assert_eq!(
            pending_restorations(&journal).expect("no retained cleanup records"),
            [] as [(Address, Address, String); 0]
        );
        journal.reserve(now()).expect("admission resumes");
    }
}

/// ´claim:loophome:mail-uncommitted-record-reconciles-through-the-filesystem-adapter´
/// ´test:unit:mail-uncommitted-record-reconciles-through-the-filesystem-adapter´
#[test]
fn mail_uncommitted_record_reconciles_through_the_filesystem_adapter() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"unaccepted snapshot");
    let prepared = prepare(&journal, &endpoint, &endpoint, &outgoing).expect("prepare");
    STOP.with(|selected| selected.set(Some(17)));
    assert!(
        prepared
            .accept(&mut journal, now(), digest(b"registry"), vec![])
            .is_err()
    );
    let record = journal
        .record(&now())
        .expect("acceptance bytes before intent cleanup");
    let deliveries = fixture.root.join(".mail-service/deliveries");
    // Model the same synced bytes immediately before the initial record rename.
    fs::rename(
        deliveries.join(format!("{}.toml", record.delivery)),
        deliveries.join(format!(".{}.toml.replace", record.delivery)),
    )
    .expect("pre-acceptance crash state");
    drop(journal);
    let mut journal = fixture.reopen();
    assert_eq!(journal.uncommitted().len(), 1);
    reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing)
        .expect("restore exact source and clear unpublished metadata");
    assert_eq!(read(&endpoint, "outbox", &outgoing), b"unaccepted snapshot");
    assert_eq!(journal.uncommitted(), [] as [Record; 0]);
    assert_eq!(staging_bytes(&[&endpoint]).expect("reaped snapshots"), 0);
}

/// ´claim:loophome:mail-terminal-cleanup-never-removes-a-reused-outgoing-name´
/// ´test:unit:mail-terminal-cleanup-never-removes-a-reused-outgoing-name´
#[test]
fn mail_terminal_cleanup_never_removes_a_reused_outgoing_name() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"first");
    let record = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
    publish(&mut journal, &endpoint, &endpoint, &record.delivery).expect("first delivery");
    cleanup_source(
        &endpoint,
        &endpoint,
        &journal.record(&record.delivery).expect("inbox"),
    )
    .expect("cleanup");
    journal
        .advance(&record.delivery, Phase::Complete, &Witness::Absent, now())
        .expect("terminal");
    source(&endpoint, &endpoint, b"second");
    cleanup_source(
        &endpoint,
        &endpoint,
        &journal.record(&record.delivery).expect("terminal"),
    )
    .expect("terminal cleanup is already durable");
    assert_eq!(
        fs::read(sender_source(&endpoint, &outgoing)).expect("new source retained"),
        b"second"
    );
    let _prepared =
        prepare(&journal, &endpoint, &endpoint, &outgoing).expect("new unpublished attempt");
    reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing)
        .expect("old terminal history does not pin new preparation");
    assert_eq!(read(&endpoint, "outbox", &outgoing), b"second");
}

/// ´claim:loophome:mail-retained-witness-names-are-not-reused-by-later-submissions´
/// ´test:unit:mail-retained-witness-names-are-not-reused-by-later-submissions´
#[test]
fn mail_retained_witness_names_are_not_reused_by_later_submissions() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"first");
    let first = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
    publish(&mut journal, &endpoint, &endpoint, &first.delivery).expect("publish first");
    cleanup_source(
        &endpoint,
        &endpoint,
        &journal.record(&first.delivery).expect("inbox"),
    )
    .expect("clean source");
    journal
        .advance(&first.delivery, Phase::Complete, &Witness::Absent, now())
        .expect("complete");
    source(&endpoint, &endpoint, b"second");
    let prepared = prepare(&journal, &endpoint, &endpoint, &outgoing).expect("new snapshot");
    assert_ne!(
        prepared.recipient_temporary.path,
        first.recipient_temporary.path
    );
    assert_eq!(
        endpoint
            .witness(&first)
            .expect("retained witness remains absent"),
        Witness::Absent
    );
    assert_eq!(
        journal
            .verify(
                &endpoint.address,
                &first.delivery,
                &first.inbox_name,
                first.bytes,
                &first.digest,
                &Witness::Absent
            )
            .expect("old live inbox remains verifiable"),
        super::super::journal::Verification::Delivered
    );
}

/// ´claim:loophome:mail-publication-rechecks-custody-and-filesystem-identity´
/// ´test:unit:mail-publication-rechecks-custody-and-filesystem-identity´
#[test]
fn mail_publication_rechecks_custody_and_filesystem_identity() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"private");
    let mut prepared = prepare(&journal, &endpoint, &endpoint, &outgoing).expect("prepare");
    prepared.recipient_temporary.identity.device += 1;
    let record = prepared
        .accept(&mut journal, now(), digest(b"registry"), vec![])
        .expect("mismatch fixture");
    assert_eq!(
        endpoint.witness(&record).expect("device mismatch"),
        Witness::Invalid
    );
    assert!(publish(&mut journal, &endpoint, &endpoint, &record.delivery).is_err());
    fs::set_permissions(&endpoint.staging_path, fs::Permissions::from_mode(0o770))
        .expect("unsafe stage fixture");
    assert!(
        endpoint.witness(&record).is_err(),
        "an unprotected staging directory cannot attest absence"
    );
}

/// ´claim:loophome:mail-preparation-intent-recovery-preserves-accepted-delivery´
/// ´test:unit:mail-preparation-intent-recovery-preserves-accepted-delivery´
#[test]
fn mail_preparation_intent_recovery_preserves_accepted_delivery() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint("alpha", group());
    let mut journal = fixture.journal();
    let outgoing = source(&endpoint, &endpoint, b"accepted once");
    let prepared = prepare(&journal, &endpoint, &endpoint, &outgoing).expect("prepare");
    STOP.with(|selected| selected.set(Some(17)));
    assert!(
        prepared
            .accept(&mut journal, now(), digest(b"registry"), vec![])
            .is_err()
    );
    drop(journal);
    let mut journal = fixture.reopen();
    assert_eq!(pending_preparations(&journal).expect("inventory").len(), 1);
    assert!(reconcile_unpublished(&mut journal, &endpoint, &endpoint, &outgoing).is_err());
    let delivery = reconcile_accepted_preparation(&journal, &endpoint, &endpoint, &outgoing)
        .expect("retain acceptance and retire only intent");
    publish(&mut journal, &endpoint, &endpoint, &delivery)
        .expect("publish from accepted snapshots");
    let record = journal.record(&delivery).expect("record");
    assert_eq!(
        read(&endpoint, "inbox", &record.inbox_name),
        b"accepted once"
    );
    assert_eq!(
        pending_preparations(&journal).expect("intent retired"),
        [] as [(Address, Address, String); 0]
    );
}

/// ´claim:loophome:mail-private-temporaries-do-not-narrow-public-name-capacity´
/// ´test:unit:mail-private-temporaries-do-not-narrow-public-name-capacity´
#[test]
fn mail_private_temporaries_do_not_narrow_public_name_capacity() {
    let fixture = Fixture::new();
    let name = "a".repeat(180);
    let endpoint = fixture.endpoint(&name, group());
    let mut journal = fixture.journal();
    let outgoing = format!("{name}.{}.letter", "s".repeat(64));
    assert!(outgoing.len() <= 255);
    fs::write(sender_source(&endpoint, &outgoing), b"long public names")
        .expect("representable outgoing name");
    let record = accepted(&mut journal, &endpoint, &endpoint, &outgoing);
    publish(&mut journal, &endpoint, &endpoint, &record.delivery)
        .expect("short internal names preserve routable public grammar");
    assert_eq!(
        read(&endpoint, "inbox", &record.inbox_name),
        b"long public names"
    );
}
