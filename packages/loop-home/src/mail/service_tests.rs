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
        configuration: None,
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
    unavailable_pin_transition(false);
}
/// ´claim:loophome:deregistered-loop-releases-unavailable-recipient-pins´
/// ´test:unit:deregistered-loop-releases-unavailable-recipient-pins´
#[test]
fn deregistered_loop_releases_unavailable_recipient_pins() {
    unavailable_pin_transition(true);
}
#[allow(clippy::too_many_lines)]
fn unavailable_pin_transition(deregistered: bool) {
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
            configuration: None,
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
    let config = fixture.root.join(".config/loops");
    fs::create_dir_all(&config).expect("registry directory");
    let registry = "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=3000,launch='dev/alpha'}]\n";
    fs::write(config.join("registry.toml"), registry).expect("registered loop");
    fs::write(
        config.join("allocations.toml"),
        format!("mail_uid={}\n", nix::unistd::Uid::effective().as_raw()),
    )
    .expect("service allocation");
    for name in ["registry.toml", "allocations.toml"] {
        fs::set_permissions(config.join(name), fs::Permissions::from_mode(0o644))
            .expect("trusted metadata");
    }
    let mut unavailable = service
        .directory
        .inventory()
        .expect("fresh registry despite missing endpoint");
    assert!(unavailable.loops.contains("alpha"));
    assert_ne!(unavailable.failures, [] as [String; 0]);
    let pins = Service::pins(
        &unavailable,
        &service.journal.records().expect("compactor records"),
    )
    .expect("service pin projection");
    assert!(pins.active_inboxes.contains(&record.delivery));
    let removed = service
        .journal
        .prune_projected(
            &Instant::parse("2026-02-01T00:00:00.001Z").expect("history elapsed"),
            |records| Service::pins(&unavailable, records),
        )
        .expect("compaction");
    assert_eq!(removed, 0);
    service
        .journal
        .record(&record.delivery)
        .expect("unavailable active inbox remains verifiable");
    if deregistered {
        fs::write(
            config.join("registry.toml"),
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n",
        )
        .expect("deregistered loop");
        unavailable = service
            .directory
            .inventory()
            .expect("fresh deregistered registry");
        assert!(unavailable.loops.is_empty());
    } else {
        unavailable
            .retired
            .insert(Address::parse("alpha").expect("trusted retirement projection"));
    }
    let pins = Service::pins(
        &unavailable,
        &service.journal.records().expect("compactor records"),
    )
    .expect("trusted retirement pin projection");
    assert!(!pins.active_inboxes.contains(&record.delivery));
    assert!(
        service
            .journal
            .prune_projected(
                &Instant::parse("2026-02-01T00:00:00.001Z").expect("history elapsed"),
                |records| Service::pins(&unavailable, records)
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

/// # Panics
/// Panics if a real anchored decision failure loses its named refusal in the sidecar.
/// ´claim:loophome:mail-service-records-anchor-refusal-code´
/// ´test:unit:mail-service-records-anchor-refusal-code´
#[test]
fn mail_service_records_anchor_refusal_code() {
    let fixture = Fixture::new();
    let (mut service, config) = anchored_service(&fixture);
    let address = Address::parse("alpha").expect("address");
    let inventory = Inventory {
        loops: BTreeSet::from(["alpha".into()]),
        actors: BTreeMap::from([(address.clone(), copy_actor(&fixture))]),
        failures: Vec::new(),
        retired: BTreeSet::new(),
    };
    seed_anchor_decision(&fixture);
    service
        .directory
        .decision(&address, &Address::parse("alpha+worker").expect("worker"))
        .expect("decision is valid before custody changes");
    let name = OsStr::new("alpha+worker.review.letter");
    fs::write(fixture.outbox(name), b"body").expect("source");
    fs::set_permissions(fixture.outbox(name), fs::Permissions::from_mode(0o600))
        .expect("source mode");
    // The inventory is already admitted. Its independent decision read is later.
    fs::set_permissions(&config, fs::Permissions::from_mode(0o750))
        .expect("change before decision");
    let error = service
        .deliver(&inventory, &address, name)
        .expect_err("live decision refusal");
    assert!(
        matches!(error, MailError::Entry(ref reason) if reason.starts_with("anchor-mode:")),
        "{error}"
    );
    // A persistent fault also refuses the inventory reread used by projection.
    // Model restoration between the real delivery failure and its projection.
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("restore custody");
    // The registry revision observed by projection may have removed the sender.
    // The already admitted actor's held outbox still receives its refusal.
    fs::write(
        config.join("registry.toml"),
        "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n",
    )
    .expect("new registry revision");
    let allocations = config.join("allocations.toml");
    fs::write(
        &allocations,
        format!("mail_uid={}\n", nix::unistd::geteuid().as_raw()),
    )
    .expect("service reservation");
    fs::set_permissions(allocations, fs::Permissions::from_mode(0o600)).expect("ledger mode");
    let observation = observe(&fixture.actor, name).ok();
    let error = service
        .refuse_candidate(&inventory, &address, name, observation, error)
        .expect_err("service projects then preserves the decision refusal");
    let sidecar: toml::Value = toml::from_str(
        &fs::read_to_string(fixture.outbox("alpha+worker.review.letter.reason.toml"))
            .expect("published sidecar"),
    )
    .expect("sidecar codec");
    assert_eq!(sidecar["code"].as_str(), Some("anchor-mode"));
    assert_eq!(sidecar["reason"].as_str(), Some(error.to_string().as_str()));
    assert!(
        refusal::recognized(
            &service.journal,
            &fixture.actor.outbox,
            "alpha",
            OsStr::new("alpha+worker.review.letter.reason.toml")
        )
        .expect("durable protected binding")
    );
}
fn copy_actor(fixture: &Fixture) -> Actor {
    Actor {
        endpoint: publication::Endpoint::open(
            &fixture.root,
            Address::parse("alpha").expect("address"),
            nix::unistd::getegid().as_raw(),
            publication::Durability {
                crash_consistent_rename: true,
                durable_sync: true,
            },
        )
        .expect("endpoint"),
        outbox: fixture.actor.outbox.try_clone().expect("outbox"),
        inbox: fixture.actor.inbox.try_clone().expect("inbox"),
        staging: fixture.actor.staging.try_clone().expect("staging"),
        uid: fixture.actor.uid,
        group: fixture.actor.group,
        active: true,
    }
}
/// ´claim:loophome:mail-entry-refusal-code-uses-a-closed-allowlist´
/// ´test:unit:mail-entry-refusal-code-uses-a-closed-allowlist´
#[test]
fn mail_entry_refusal_code_uses_a_closed_allowlist() {
    for code in [
        "anchor-declaration",
        "anchor-missing",
        "anchor-transport",
        "anchor-owner",
        "anchor-mode",
        "anchor-kind",
        "anchor-identity",
        "anchor-escape",
        "anchor-exec",
        "anchor-io",
        "anchor-uid-map",
    ] {
        assert_eq!(
            refusal::code(&MailError::Entry(format!("{code}: operation=mail-binding"))),
            code
        );
    }
    for text in [
        "",
        "anchor-mode-extra: wrong",
        "io-failure: wrong",
        "untrusted\nanchor-mode:",
    ] {
        assert_eq!(
            refusal::code(&MailError::Entry(text.into())),
            "entry-refusal"
        );
    }
}

fn seed_anchor_decision(fixture: &Fixture) {
    let uid = nix::unistd::geteuid().as_raw();
    let registry = fixture.root.join(".config/loops/registry.toml");
    fs::write(
        &registry,
        format!(
            "namespace='org.superloop-tools.loophome.registry'\n\
        version=[1,0,0]\nloops=[{{name='alpha',uid={uid},launch='dev/alpha'}}]\n"
        ),
    )
    .expect("registry");
    fs::set_permissions(registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let private = fixture.root.join(".var/loops/alpha/private");
    fs::create_dir_all(private.join(".config/mail")).expect("configuration parents");
    for directory in [
        &private,
        &private.join(".config"),
        &private.join(".config/mail"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
        super::super::acl::install(&File::open(directory).expect("directory"), uid, true)
            .expect("configuration search grant");
    }
    let path = private.join(".config/mail/loop.toml");
    fs::write(
        &path,
        "workers=[{name='worker',state='active'}]\n[mail]\nversion=1\nallow=[]\n",
    )
    .expect("worker configuration");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    super::super::acl::install(&File::open(path).expect("file"), uid, false).expect("read grant");
}

fn anchored_service(fixture: &Fixture) -> (Service, std::path::PathBuf) {
    use crate::anchor::{
        HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement, Transport,
    };
    let config = fixture.root.join(".config/loops");
    fs::create_dir_all(&config).expect("configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("mode");
    let policy = Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(0o700),
    };
    let pin = HostVerifier::current()
        .expect("host")
        .pin(&config, "configuration", 0, policy)
        .expect("pin");
    let manifest = Manifest {
        version: 1,
        operation: "mail-serve".into(),
        loop_name: String::new(),
        transport: Transport::Rights,
        records: vec![pin.record()],
    };
    let mut anchors = Receiver::current()
        .expect("receiver")
        .validate(
            &manifest,
            vec![pin.into_fd()],
            "mail-serve",
            "",
            Transport::Rights,
            &[Requirement {
                purpose: "configuration".into(),
                alias_group: None,
                policy,
            }],
        )
        .expect("receipt");
    let service = Service::new(
        Directory {
            configuration: Some(std::sync::Arc::new(anchors.pop().expect("configuration"))),
            home: fixture.root.clone(),
            service: nix::unistd::geteuid().as_raw(),
            owner: nix::unistd::geteuid().as_raw(),
            durability: publication::Durability {
                crash_consistent_rename: true,
                durable_sync: true,
            },
        },
        fixture.journal(),
    );
    (service, config)
}
