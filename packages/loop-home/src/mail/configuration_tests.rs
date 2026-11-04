use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    root: PathBuf,
    row: LoopRecord,
    service: u32,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mail-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
        let uid = nix::unistd::geteuid().as_raw();
        let service = uid + 1;
        let home = root.join(".var/loops/alpha");
        fs::create_dir_all(home.join("private/.config/mail")).expect("mail config parents");
        for path in [
            home.join("private"),
            home.join("private/.config"),
            home.join("private/.config/mail"),
        ] {
            acl::install(&File::open(path).expect("ancestor"), service, true)
                .expect("search-only grant");
        }
        let fixture = Self {
            root,
            row: LoopRecord {
                name: "alpha".into(),
                uid,
                home,
                launch: PathBuf::from("/fixture"),
                session: None,
                door_floor: None,
            },
            service,
        };
        fixture.replace(
            b"workers=[{name='real',state='active'}]\n[mail]\nversion=1\nallow=[]\n",
            true,
        );
        fixture
    }
    fn path(&self) -> PathBuf {
        self.row.home.join("private/.config/mail/loop.toml")
    }
    fn replace(&self, bytes: &[u8], grant: bool) {
        let replacement = self.path().with_extension("replacement");
        fs::write(&replacement, bytes).expect("replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).expect("owner only");
        if grant {
            acl::install(
                &File::open(&replacement).expect("config"),
                self.service,
                false,
            )
            .expect("file-only read grant");
        }
        fs::rename(&replacement, self.path()).expect("atomic replacement");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.root);
    }
}

/// ´claim:loophome:mail-configuration-never-resolves-from-the-host-registry-directory´
/// ´test:unit:mail-configuration-never-resolves-from-the-host-registry-directory´
#[test]
fn mail_configuration_never_resolves_from_the_host_registry_directory() {
    let fixture = Fixture::new();
    let host = fixture.root.join(".config/loops");
    fs::create_dir_all(&host).expect("host config");
    fs::write(
        host.join("loop.toml"),
        b"workers=[{name='decoy',state='active'}]\n[mail]\nversion=1\nallow=[]\n",
    )
    .expect("decoy");
    let snapshot = Snapshot::open(&fixture.row, fixture.service).expect("loop-owned snapshot");
    assert!(snapshot.config.active("real").is_ok());
    assert!(snapshot.config.active("decoy").is_err());
    assert!(snapshot.current().is_ok());
    drop(snapshot);
    fs::remove_file(fixture.path()).expect("missing real config");
    assert!(
        Snapshot::open(&fixture.row, fixture.service).is_err(),
        "host decoy is never a fallback"
    );
}

/// ´claim:loophome:mail-decisions-recheck-config-replacement-and-effective-acl-mask´
/// ´test:unit:mail-decisions-recheck-config-replacement-and-effective-acl-mask´
#[test]
fn mail_decisions_recheck_config_replacement_and_effective_acl_mask() {
    let fixture = Fixture::new();
    let snapshot = Snapshot::open(&fixture.row, fixture.service).expect("snapshot");
    fixture.replace(
        b"workers=[{name='real',state='retired'}]\n[mail]\nversion=1\nallow=[]\n",
        true,
    );
    assert!(snapshot.current().is_err());
    drop(snapshot);
    let updated = Snapshot::open(&fixture.row, fixture.service).expect("fresh config");
    assert!(
        updated
            .config
            .active("real")
            .expect_err("retired")
            .to_string()
            .starts_with("retired-worker")
    );
    drop(updated);
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600))
        .expect("remove effective mask");
    assert!(Snapshot::open(&fixture.row, fixture.service).is_err());
    acl::install(
        &File::open(fixture.path()).expect("file"),
        fixture.service,
        false,
    )
    .expect("restore effective grant");
    assert!(Snapshot::open(&fixture.row, fixture.service).is_ok());
    fixture.replace(b"workers=[]\n[mail]\nversion=1\nallow=[]\n", false);
    assert!(
        Snapshot::open(&fixture.row, fixture.service).is_err(),
        "replacement loses access"
    );
}

/// ´claim:loophome:mail-service-identity-reservation-excludes-loop-and-worker-identities´
/// ´test:unit:mail-service-identity-reservation-excludes-loop-and-worker-identities´
#[test]
fn mail_service_identity_reservation_excludes_loop_and_worker_identities() {
    let mut allocations =
        Allocations::parse("letters_gid=65535\n[alpha]\nuids={base=65000,count=500}\n")
            .expect("ledger");
    let uid = allocations
        .ensure_mail_uid(&[65533])
        .expect("service identity");
    assert_eq!(uid, 65532);
    assert_eq!(allocations.ensure_mail_uid(&[65533]).expect("stable"), uid);
    let roundtrip = Allocations::parse(&allocations.to_toml()).expect("round trip");
    assert_eq!(roundtrip.mail_uid(), Some(uid));
    for invalid in [
        "mail_uid=65535\nletters_gid=65535",
        "mail_uid=65534",
        "mail_uid=3000\n[alpha]\nuids={base=3000,count=64}",
    ] {
        assert!(Allocations::parse(invalid).is_err());
    }
    let mut collision = Allocations::parse("mail_uid=41001").expect("reserved");
    assert!(collision.ensure_mail_uid(&[41001]).is_err());
}

/// ´claim:loophome:mail-groups-never-confer-a-private-actor-credential´
/// ´test:unit:mail-groups-never-confer-a-private-actor-credential´
#[test]
fn mail_groups_never_confer_a_private_actor_credential() {
    let mut allocations = Allocations::parse(
        "[alpha]\nuids={base=3000,count=64}\n[beta]\nuids={base=3064,count=64}\n",
    )
    .expect("ledger");
    let private = [1000, 1001];
    let service = allocations.ensure_mail_uid(&private).expect("service");
    for name in ["alpha", "beta"] {
        allocations
            .ensure_mail_groups(name, &private)
            .expect("mail groups");
    }
    let groups = allocations.mail_group_ids().collect::<BTreeSet<_>>();
    assert_eq!(groups.len(), 130);
    assert!(
        groups
            .iter()
            .all(|gid| !private.contains(gid) && *gid != service && !(3000..3128).contains(gid))
    );
    let group = allocations.mail_group("alpha", None).expect("loop group");
    assert_ne!(
        group,
        allocations
            .mail_group("alpha", Some(3000))
            .expect("worker group")
    );
    assert!(allocations.mail_group("alpha", Some(3064)).is_err());
    allocations
        .ensure_mail_groups("alpha", &private)
        .expect("stable");
    assert_eq!(
        allocations.mail_group("alpha", None).expect("same group"),
        group
    );
    let restored = Allocations::parse(&allocations.to_toml()).expect("roundtrip");
    assert_eq!(restored.mail_group_ids().collect::<BTreeSet<_>>(), groups);
    for source in [
        "[alpha]\nuids={base=3000,count=1}\nmail_gids={base=3000,count=2}",
        "mail_uid=41001\n[alpha]\nuids={base=3000,count=1}\nmail_gids={base=41000,count=2}",
        "[alpha]\nuids={base=3000,count=1}\nmail_gids={base=5000,count=1}",
    ] {
        assert!(Allocations::parse(source).is_err());
    }
}

/// ´claim:loophome:mail-configuration-and-registry-schemas-are-disjoint´
/// ´test:unit:mail-configuration-and-registry-schemas-are-disjoint´
#[test]
fn mail_configuration_and_registry_schemas_are_disjoint() {
    let registry =
        b"namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n";
    assert!(Configuration::parse(registry).is_err());
    let fixture = Fixture::new();
    assert!(crate::registry::load_registry(&fixture.path()).is_err());
}

/// ´claim:loophome:mail-configuration-reads-have-a-shared-bound´
/// ´test:unit:mail-configuration-reads-have-a-shared-bound´
#[test]
fn mail_configuration_reads_have_a_shared_bound() {
    let fixture = Fixture::new();
    let snapshot = Snapshot::open(&fixture.row, fixture.service).expect("snapshot");
    let mut oversized = b"workers=[]\n[mail]\nversion=1\nallow=[]\n#".to_vec();
    oversized.resize(
        usize::try_from(MAX_CONFIGURATION_BYTES).expect("bounded size") + 1,
        b'x',
    );
    assert!(
        Configuration::parse(&oversized).is_ok(),
        "valid schema beyond the transport bound"
    );
    fs::write(fixture.path(), &oversized).expect("same inode enlarged by its loop owner");
    assert!(
        snapshot
            .current()
            .expect_err("bounded recheck")
            .to_string()
            .starts_with("invalid-directory:")
    );
    assert!(
        Snapshot::open(&fixture.row, fixture.service)
            .err()
            .expect("bounded snapshot")
            .to_string()
            .starts_with("invalid-directory:")
    );
    drop(snapshot);
    assert!(
        super::super::configuration_store::ConfigurationStore::open(
            &fixture.row.home.join("private"),
            fixture.service
        )
        .is_err()
    );
}

/// ´claim:loophome:mail-configuration-contention-refuses-without-waiting´
/// ´test:unit:mail-configuration-contention-refuses-without-waiting´
#[test]
fn mail_configuration_contention_refuses_without_waiting() {
    let fixture = Fixture::new();
    let writer = super::super::configuration_store::ConfigurationStore::open(
        &fixture.row.home.join("private"),
        fixture.service,
    )
    .expect("loop writer");
    let started = std::time::Instant::now();
    let error = Snapshot::open(&fixture.row, fixture.service)
        .err()
        .expect("contended");
    assert!(error.to_string().starts_with("changed-source:"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    drop(writer);
    assert!(Snapshot::open(&fixture.row, fixture.service).is_ok());
}

/// ´claim:loophome:mail-directory-overflow-names-host-metadata´
/// ´test:unit:mail-directory-overflow-names-host-metadata´
#[test]
fn mail_directory_overflow_names_host_metadata() {
    let fixture = Fixture::new();
    let host = fixture.root.join(".config/loops");
    fs::create_dir_all(&host).expect("host config");
    let registry = host.join("registry.toml");
    fs::write(
        &registry,
        b"namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n",
    )
    .expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("mode");
    let directory = Directory {
        home: fixture.root.clone(),
        service: fixture.service,
        owner: nix::unistd::geteuid().as_raw(),
        durability: Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    };
    let (_, bytes, file) = directory.registry().expect("valid registry");
    let info = file.metadata().expect("identity");
    let decision = Decision {
        registry_digest: digest(&bytes),
        configs: Vec::new(),
        registry_path: registry.clone(),
        registry_identity: (info.dev(), info.ino()),
    };
    let oversized = format!("loops=[]\n#{}", "x".repeat(65_536));
    fs::write(&registry, oversized.as_bytes()).expect("same inode overflow");
    for error in [
        directory.registry().expect_err("registry bound"),
        decision.current().expect_err("recheck bound"),
    ] {
        assert_eq!(
            error.to_string(),
            "invalid-directory: loop registry exceeds its bound"
        );
    }
    let allocations = host.join("allocations.toml");
    fs::write(&allocations, oversized.as_bytes()).expect("allocation overflow");
    fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(
        directory
            .allocations()
            .expect_err("allocation bound")
            .to_string(),
        "invalid-directory: allocations ledger exceeds its bound"
    );
}
