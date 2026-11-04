use super::*;
use crate::mail::configuration::Configuration;
use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    root: PathBuf,
    actor: Actor,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mail-core-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root custody");
        for (name, mode) in [
            ("alpha", 0o711),
            ("alpha/mail", 0o750),
            ("alpha/mail/inbox", 0o770),
            ("alpha/mail/sent", 0o770),
            ("alpha/mail/outbox", 0o700),
            ("alpha/.mail-staging", 0o700),
            ("journal", 0o700),
        ] {
            fs::create_dir(root.join(name)).expect("directory");
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(mode)).expect("mode");
        }
        let endpoint = publication::Endpoint::open(
            &root,
            Address::parse("alpha").expect("address"),
            nix::unistd::getegid().as_raw(),
            publication::Durability {
                crash_consistent_rename: true,
                durable_sync: true,
            },
        )
        .expect("endpoint");
        let actor = Actor {
            endpoint,
            outbox: File::open(root.join("alpha/mail/outbox")).expect("outbox"),
            staging: File::open(root.join("alpha/.mail-staging")).expect("stage"),
            inbox: File::open(root.join("alpha/mail/inbox")).expect("inbox"),
            uid: nix::unistd::geteuid().as_raw(),
            group: nix::unistd::getegid().as_raw(),
            active: true,
        };
        Self { root, actor }
    }
    fn journal(&self) -> Journal {
        Journal::create(File::open(self.root.join("journal")).expect("journal root"))
            .expect("journal")
    }
    fn reopen(&self) -> Journal {
        Journal::open(File::open(self.root.join("journal")).expect("journal root")).expect("reopen")
    }
    fn outbox(&self, name: impl AsRef<Path>) -> PathBuf {
        self.root.join("alpha/mail/outbox").join(name)
    }
    fn project(&self, journal: &Journal, name: &OsStr) -> Result<()> {
        refusal::project(
            journal,
            &self.actor.outbox,
            &self.actor.staging,
            refusal::Projection {
                sender: "alpha",
                name,
                group: nix::unistd::getegid().as_raw(),
                observation: Some((4, digest(b"body"))),
                code: "invalid-name",
                reason: "outgoing name is invalid",
                now: Instant::now()?,
                delivery: None,
                staging_bytes: publication::staging_bytes(&[&self.actor.endpoint])?,
            },
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.root);
    }
}

/// ´claim:loophome:mail-core-orders-a-finite-scan-by-slug-and-sender-rounds´
/// ´test:unit:mail-core-orders-a-finite-scan-by-slug-and-sender-rounds´
#[test]
fn mail_core_orders_a_finite_scan_by_slug_and_sender_rounds() {
    let mut alpha = vec![
        OsString::from("z.00.letter"),
        OsString::from("a.02.letter"),
        OsString::from("b.00.letter"),
    ];
    alpha.sort_by_cached_key(|name| sort_key(name));
    let queues = BTreeMap::from([
        (Address::parse("alpha").expect("address"), alpha.into()),
        (
            Address::parse("beta").expect("address"),
            VecDeque::from([OsString::from("a.00.letter")]),
        ),
    ]);
    let actual = schedule(queues)
        .into_iter()
        .map(|(sender, name)| (sender.to_string(), name.into_string().expect("ASCII")))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            ("alpha".into(), "b.00.letter".into()),
            ("beta".into(), "a.00.letter".into()),
            ("alpha".into(), "z.00.letter".into()),
            ("alpha".into(), "a.02.letter".into())
        ]
    );
}

/// ´claim:loophome:mail-configuration-validates-directed-estate-grants´
/// ´test:unit:mail-configuration-validates-directed-estate-grants´
#[test]
fn mail_configuration_validates_directed_estate_grants() {
    let source=b"workers = [{name='a',state='active'},{name='b',state='active'},{name='old',state='retired'}]\nother='preserved'\n[mail]\nversion=1\nallow=[{from='a',to='b'}]\n";
    let config = Configuration::parse(source).expect("directory");
    let address = |name| Address::parse(name).expect("address");
    assert!(
        config
            .authorize(&address("alpha+a"), &address("alpha+b"))
            .is_ok()
    );
    assert!(
        config
            .authorize(&address("alpha+a"), &address("alpha"))
            .is_ok()
    );
    for (sender, recipient, code) in [
        ("alpha+b", "alpha+a", "not-whitelisted"),
        ("alpha+a", "alpha+a", "not-whitelisted"),
        ("alpha+a", "beta", "outside-estate"),
        ("alpha+a", "beta+b", "outside-estate"),
        ("alpha+old", "alpha", "retired-worker"),
    ] {
        assert!(
            config
                .authorize(&address(sender), &address(recipient))
                .expect_err("refusal")
                .to_string()
                .starts_with(code)
        );
    }
    let text = String::from_utf8(source.to_vec()).expect("text");
    for invalid in [
        text.replace("state='retired'", "state='unknown'"),
        text.replace("name='old'", "name='a'"),
        text.replace("to='b'", "to='missing'"),
        text.replace("version=1", "version=2"),
        text.replace("version=1", "version=1\nunknown=true"),
        text.replace(
            "[{from='a',to='b'}]",
            "[{from='a',to='b'},{from='a',to='b'}]",
        ),
        text.replace("allow=[{from='a',to='b'}]", ""),
    ] {
        assert!(
            Configuration::parse(invalid.as_bytes()).is_err(),
            "{invalid}"
        );
    }
    assert_eq!(config.other["other"].as_str(), Some("preserved"));
}

/// ´claim:loophome:mail-refusal-restarts-each-publication-boundary-with-source-intact´
/// ´test:unit:mail-refusal-restarts-each-publication-boundary-with-source-intact´
#[test]
fn mail_refusal_restarts_each_publication_boundary_with_source_intact() {
    for point in 1..=5 {
        let fixture = Fixture::new();
        let journal = fixture.journal();
        let name = OsStr::new("invalid");
        fs::write(fixture.outbox(name), b"body").expect("source");
        refusal::STOP.with(|stop| stop.set(point));
        assert!(fixture.project(&journal, name).is_err());
        refusal::STOP.with(|stop| stop.set(0));
        drop(journal);
        let journal = fixture.reopen();
        fixture.project(&journal, name).expect("restart projection");
        assert_eq!(fs::read(fixture.outbox(name)).expect("source"), b"body");
        assert!(
            refusal::recognized(
                &journal,
                &fixture.actor.outbox,
                "alpha",
                OsStr::new("invalid.reason.toml")
            )
            .expect("provenance")
        );
        let bytes = fs::read(fixture.outbox("invalid.reason.toml")).expect("reason");
        let text = String::from_utf8(bytes).expect("UTF-8");
        assert!(!text.contains("body"));
        let sidecar: toml::Value = toml::from_str(&text).expect("schema");
        assert_eq!(sidecar["code"].as_str(), Some("invalid-name"));
        assert_eq!(sidecar["bytes"].as_integer(), Some(4));
        assert_eq!(
            publication::staging_bytes(&[&fixture.actor.endpoint]).expect("staging"),
            0
        );
    }
}

/// ´claim:loophome:mail-refusal-never-trusts-suffix-or-overwrites-actor-entries´
/// ´test:unit:mail-refusal-never-trusts-suffix-or-overwrites-actor-entries´
#[test]
fn mail_refusal_never_trusts_suffix_or_overwrites_actor_entries() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let name = OsStr::new("invalid");
    fs::write(fixture.outbox(name), b"body").expect("source");
    fs::write(fixture.outbox("actor.reason.toml"), b"actor bytes").expect("fake sidecar");
    assert!(
        !refusal::recognized(
            &journal,
            &fixture.actor.outbox,
            "alpha",
            OsStr::new("actor.reason.toml")
        )
        .expect("not provenance")
    );
    fixture.project(&journal, name).expect("projection");
    fs::rename(
        fixture.outbox("invalid.reason.toml"),
        fixture.outbox("saved"),
    )
    .expect("replace sidecar");
    fs::write(fixture.outbox("invalid.reason.toml"), b"replacement").expect("actor replacement");
    assert!(
        refusal::clear(
            &journal,
            &fixture.actor.outbox,
            &fixture.actor.staging,
            "alpha",
            name
        )
        .is_err()
    );
    assert_eq!(
        fs::read(fixture.outbox("invalid.reason.toml")).expect("retained"),
        b"replacement"
    );
}

/// ´claim:loophome:mail-refusal-fallback-and-withdrawal-preserve-raw-names´
/// ´test:unit:mail-refusal-fallback-and-withdrawal-preserve-raw-names´
#[test]
fn mail_refusal_fallback_and_withdrawal_preserve_raw_names() {
    for name in [
        OsStr::from_bytes(b"invalid-\xff").to_owned(),
        OsString::from("a".repeat(255)),
    ] {
        let fixture = Fixture::new();
        let journal = fixture.journal();
        fs::write(fixture.outbox(&name), b"body").expect("raw source");
        fixture
            .project(&journal, &name)
            .expect("fallback projection");
        let reason = format!("refusal-{}.reason.toml", digest(name.as_bytes()));
        assert!(
            refusal::recognized(
                &journal,
                &fixture.actor.outbox,
                "alpha",
                OsStr::new(&reason)
            )
            .expect("fallback provenance")
        );
        fs::remove_file(fixture.outbox(&name)).expect("withdraw");
        refusal::maintain(
            &journal,
            &fixture.actor.outbox,
            &fixture.actor.staging,
            "alpha",
        )
        .expect("stale cleanup");
        assert!(!fixture.outbox(reason).exists());
    }
}

/// ´claim:loophome:mail-core-inspects-opaque-bounds-and-file-kind-before-claim´
/// ´test:unit:mail-core-inspects-opaque-bounds-and-file-kind-before-claim´
#[test]
fn mail_core_inspects_opaque_bounds_and_file_kind_before_claim() {
    let fixture = Fixture::new();
    let name = OsStr::new("alpha.00.letter");
    for bytes in [
        vec![],
        vec![0, 255, 10],
        vec![19; usize::try_from(MAX_LETTER_BYTES).expect("fixture size")],
    ] {
        fs::write(fixture.outbox(name), &bytes).expect("source");
        assert_eq!(
            observe(&fixture.actor, name).expect("bounded bytes"),
            (bytes.len() as u64, digest(&bytes))
        );
    }
    fs::write(
        fixture.outbox(name),
        vec![0; usize::try_from(MAX_LETTER_BYTES).expect("fixture size") + 1],
    )
    .expect("oversize");
    assert!(
        observe(&fixture.actor, name)
            .expect_err("oversize")
            .to_string()
            .starts_with("oversize")
    );
    fs::remove_file(fixture.outbox(name)).expect("remove");
    symlink("absent", fixture.outbox(name)).expect("symlink");
    assert!(observe(&fixture.actor, name).is_err());
    fs::remove_file(fixture.outbox(name)).expect("remove");
    fs::write(fixture.outbox(name), b"body").expect("source");
    fs::hard_link(fixture.outbox(name), fixture.outbox("alias")).expect("alias");
    assert!(
        observe(&fixture.actor, name)
            .expect_err("hard link")
            .to_string()
            .starts_with("invalid-file")
    );
}

/// ´claim:loophome:mail-core-sleeps-through-equal-and-backward-utc-before-admission´
/// ´test:unit:mail-core-sleeps-through-equal-and-backward-utc-before-admission´
#[test]
fn mail_core_sleeps_through_equal_and_backward_utc_before_admission() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct Script {
        times: VecDeque<Instant>,
        waits: Rc<Cell<u32>>,
    }
    impl Clock for Script {
        fn now(&mut self) -> Result<Instant> {
            Ok(self.times.pop_front().expect("scripted actual observation"))
        }
        fn wait(&mut self) {
            self.waits.set(self.waits.get() + 1);
        }
    }
    let fixture = Fixture::new();
    let mut journal = fixture.journal();
    let first = Instant::parse("2026-01-01T00:00:00.000Z").expect("first");
    let next = Instant::parse("2026-01-01T00:00:00.001Z").expect("next");
    journal.reserve(first.clone()).expect("watermark");
    let directory = Directory {
        home: fixture.root.clone(),
        service: nix::unistd::geteuid().as_raw(),
        owner: nix::unistd::geteuid().as_raw(),
        durability: publication::Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    };
    let waits = Rc::new(Cell::new(0));
    let mut service = Service::new(directory, journal);
    service.clock = Box::new(Script {
        times: VecDeque::from([
            first.clone(),
            Instant::parse("2025-01-01T00:00:00.000Z").expect("rollback"),
            next.clone(),
        ]),
        waits: waits.clone(),
    });
    assert_eq!(service.tick().expect("next actual tick"), next);
    assert_eq!(waits.get(), 2);
    assert!(matches!(
        service.journal.check_clock(&first),
        Err(MailError::ClockWait)
    ));
    service
        .journal
        .reserve(next.clone())
        .expect("reserve only the actual observation");
    drop(service);
    assert!(matches!(
        fixture.reopen().check_clock(&next),
        Err(MailError::ClockWait)
    ));
}

/// ´claim:loophome:unavailable-inbox-pins-until-trusted-retirement´
/// ´test:unit:unavailable-inbox-pins-until-trusted-retirement´
#[test]
fn unavailable_inbox_pins_until_trusted_retirement() {
    let fixture = Fixture::new();
    let mut journal = fixture.journal();
    let instant = Instant::parse("2026-01-01T00:00:00.001Z").expect("instant");
    let outgoing = "alpha.01.letter";
    fs::write(
        fixture.root.join("alpha/.mail-staging").join(outgoing),
        b"opaque bytes",
    )
    .expect("claimed source");
    let record = publication::prepare(
        &journal,
        &fixture.actor.endpoint,
        &fixture.actor.endpoint,
        outgoing,
    )
    .expect("prepare")
    .accept(
        &mut journal,
        instant.clone(),
        digest(b"registry"),
        vec![digest(b"configuration")],
    )
    .expect("accepted");
    publication::publish(
        &mut journal,
        &fixture.actor.endpoint,
        &fixture.actor.endpoint,
        &record.delivery,
    )
    .expect("publish");
    let current = journal.record(&record.delivery).expect("inbox phase");
    publication::cleanup_source(&fixture.actor.endpoint, &fixture.actor.endpoint, &current)
        .expect("cleanup");
    journal
        .advance(&record.delivery, Phase::Complete, &Witness::Absent, instant)
        .expect("complete");
    let mut service = Service::new(
        Directory {
            home: fixture.root.clone(),
            service: nix::unistd::Uid::effective().as_raw(),
            owner: nix::unistd::Uid::effective().as_raw(),
            durability: publication::Durability {
                crash_consistent_rename: true,
                durable_sync: true,
            },
        },
        journal,
    );
    let mut unavailable = Inventory {
        retired: BTreeSet::new(),
        actors: BTreeMap::new(),
        failures: vec!["alpha: unsafe-storage: endpoint unavailable".into()],
    };
    let pins = service.pins(&unavailable).expect("service pin projection");
    assert!(pins.active_inboxes.contains(&record.delivery));
    let removed = service
        .journal
        .prune(
            &Instant::parse("2026-02-01T00:00:00.001Z").expect("history elapsed"),
            &pins,
        )
        .expect("compaction");
    assert_eq!(removed, 0);
    service
        .journal
        .record(&record.delivery)
        .expect("unavailable active inbox remains verifiable");
    unavailable
        .retired
        .insert(Address::parse("alpha").expect("trusted retirement projection"));
    let pins = service
        .pins(&unavailable)
        .expect("trusted retirement pin projection");
    assert!(!pins.active_inboxes.contains(&record.delivery));
    assert!(
        service
            .journal
            .prune(
                &Instant::parse("2026-02-01T00:00:00.001Z").expect("history elapsed"),
                &pins
            )
            .expect("retired compaction")
            > 0
    );
    assert!(service.journal.record(&record.delivery).is_err());
    assert!(
        fixture
            .root
            .join("alpha/mail/inbox")
            .join(&record.inbox_name)
            .exists()
    );
}
