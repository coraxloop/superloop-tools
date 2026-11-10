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
        configuration: None,
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
        configuration: None,
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

/// # Panics
/// Panics if scan-time configuration or its recheck reopens the absolute directory.
/// ´claim:loophome:mail-scan-configuration-retains-its-anchor´
/// ´test:unit:mail-scan-configuration-retains-its-anchor´
#[test]
fn mail_scan_configuration_retains_its_anchor() {
    use crate::anchor::{
        HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement, Transport,
    };
    let fixture = Fixture::new();
    let config = fixture.root.join(".config/loops");
    fs::create_dir_all(&config).expect("configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("private directory");
    for (name, source) in [
        (
            "registry.toml",
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n"
                .to_owned(),
        ),
        (
            "allocations.toml",
            format!("mail_uid={}\n", fixture.service),
        ),
    ] {
        let path = config.join(name);
        fs::write(&path, source).expect("configuration file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
    }
    let policy = Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(0o700),
    };
    let pin = HostVerifier::current()
        .expect("host map")
        .pin(&config, "configuration", 0, policy)
        .expect("host configuration");
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: "mail-serve".into(),
        loop_name: String::new(),
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
                policy,
                alias_group: None,
            }],
        )
        .expect("configuration handoff");
    let anchor = Arc::new(anchors.pop().expect("anchor"));
    let directory = Directory {
        configuration: Some(Arc::clone(&anchor)),
        home: fixture.root.clone(),
        service: fixture.service,
        owner: nix::unistd::Uid::effective().as_raw(),
        durability: Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    };
    let (_, bytes, file) = directory.registry().expect("registry");
    let info = file.metadata().expect("identity");
    let decision = Decision {
        configuration: Some(anchor),
        registry_digest: digest(&bytes),
        configs: Vec::new(),
        registry_path: config.join("registry.toml"),
        registry_identity: (info.dev(), info.ino()),
    };
    let moved = fixture.root.join("configuration-held");
    fs::rename(&config, &moved).expect("rename configuration");
    directory.registry().expect("held registry");
    directory.allocations().expect("held ledger and registry");
    decision.current().expect("held recheck");
    let replaced = moved.join("replacement");
    fs::write(&replaced, &bytes).expect("replacement");
    fs::set_permissions(&replaced, fs::Permissions::from_mode(0o600)).expect("replacement mode");
    fs::rename(replaced, moved.join("registry.toml")).expect("replace registry");
    assert!(
        decision
            .current()
            .expect_err("changed inode")
            .to_string()
            .starts_with("changed-source:")
    );
}

/// ´claim:loophome:mail-inventory-reports-skipped-loop-reason´
/// ´test:unit:mail-inventory-reports-skipped-loop-reason´
#[test]
fn mail_inventory_reports_skipped_loop_reason() {
    use std::sync::Mutex;

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let fixture = Fixture::new();
    let host = fixture.root.join(".config/loops");
    fs::create_dir_all(&host).expect("host config");
    fs::write(
        host.join("registry.toml"),
        "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=3000,launch='dev/alpha'}]\n",
    )
    .expect("registry");
    fs::write(host.join("allocations.toml"), "mail_uid=4000\n")
        .expect("service allocation without a loop mailbox group");
    for name in ["registry.toml", "allocations.toml"] {
        fs::set_permissions(host.join(name), fs::Permissions::from_mode(0o644))
            .expect("trusted metadata");
    }
    let directory = Directory {
        configuration: None,
        home: fixture.root.clone(),
        service: 4000,
        owner: nix::unistd::geteuid().as_raw(),
        durability: Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    };
    let captured = Capture(Arc::default());
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let inventory = tracing::subscriber::with_default(subscriber, || {
        directory
            .inventory()
            .expect("inventory skips only the loop")
    });
    let reason = "unsafe-storage: loop mailbox group is not reserved";
    assert_eq!(inventory.failures, [format!("alpha: {reason}")]);
    assert!(inventory.actors.is_empty());
    assert!(inventory.loops.contains("alpha"));
    let output = captured.0.lock().expect("capture").clone();
    let lines = std::str::from_utf8(&output).expect("UTF-8");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON event"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "routine refresh stays quiet at info");
    assert_eq!(events[0]["level"], "WARN");
    assert_eq!(events[0]["fields"]["message"], "loop skipped");
    assert_eq!(events[0]["fields"]["loop_name"], "alpha");
    assert_eq!(events[0]["fields"]["reason"], reason);
}

const INVENTORY_TEST: &str = "mail::directory::tests::binding_inventory_retains_storage";
const INVENTORY_PHASE: &str = "LOOP_HOME_INVENTORY_FIXTURE";
const INVENTORY_MARKER: &str = "loop-home-inventory-fixture";

/// A phase acts only on a home the parent created under the fixture name and marked.
fn inventory_home() -> PathBuf {
    let home = PathBuf::from(std::env::var_os("LOOP_HOME_INVENTORY_HOME").expect("fixture home"));
    let named = home
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("mail-inventory-"));
    let marker = fs::symlink_metadata(home.join(INVENTORY_MARKER));
    assert!(
        named && marker.is_ok_and(|info| info.is_file()),
        "unmarked fixture home: {}",
        home.display()
    );
    home
}
/// The skip reason a worker-refusal case reaches before its endpoint is unavailable.
fn inventory_skip(case: &str) -> &'static str {
    match case {
        "outbox-mode" => "unsafe-storage: actor outbox custody",
        "ancestor-mode" => "unsafe-storage: actor-replaceable mailbox ancestor",
        "linked-worker" => "(os error 40)",
        _ => "",
    }
}
fn inventory_command(home: &Path, phase: &str) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/podman");
    command
        .args(["unshare"])
        .arg(std::env::current_exe().expect("test image"))
        .args([INVENTORY_TEST, "--exact", "--nocapture"])
        .env(INVENTORY_PHASE, phase)
        .env("LOOP_HOME_INVENTORY_HOME", home)
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID")
        .env_remove("ENTER_LOOP_REGISTRY");
    command
}
fn inventory_owned(path: &Path, uid: u32, mode: u32) {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(uid)),
    )
    .expect("fixture owner");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}
fn inventory_seed(home: &Path) {
    let storage = home.join(".var/loops/alpha");
    for path in [home.join(".var"), home.join(".var/loops"), storage.clone()] {
        fs::create_dir(&path).expect("storage");
        inventory_owned(&path, 0, 0o711);
    }
    let root = File::open(&storage).expect("storage descriptor");
    super::super::provision::tree(&root, "mail", 64000, 64001, 64020).expect("principal");
    super::super::provision::directory(&root, ".mail-staging", 64001, 64001, 0o700)
        .expect("staging");
    let workers = super::super::provision::directory(&root, "workers", 0, 0, 0o711)
        .expect("workers")
        .0;
    acl::grant_ancestor(&workers, 64001, 5, 0o711).expect("service enumeration grant");
    let worker = super::super::provision::directory(&workers, "worker", 0, 0, 0o711)
        .expect("worker")
        .0;
    super::super::provision::tree(&worker, "mail", 64010, 64001, 64021).expect("worker mailbox");
    super::super::provision::directory(&worker, ".mail-staging", 64001, 64001, 0o700)
        .expect("worker staging");
    let private = storage.join("private");
    for path in [
        private.clone(),
        private.join(".config"),
        private.join(".config/mail"),
    ] {
        fs::create_dir(&path).expect("private");
        inventory_owned(&path, 64000, 0o700);
        acl::install(&File::open(&path).expect("private ACL"), 64001, true).expect("search grant");
    }
    let path = private.join(".config/mail/loop.toml");
    fs::write(
        &path,
        "workers=[{name='worker',state='active'}]\n[mail]\nversion=1\nallow=[]\n",
    )
    .expect("snapshot");
    inventory_owned(&path, 64000, 0o600);
    acl::install(&File::open(&path).expect("snapshot file"), 64001, false).expect("read grant");
}
fn inventory_policies() -> Vec<crate::anchor::Requirement> {
    use crate::anchor::{Kind, ModePolicy, Owner, Policy, Requirement};
    [
        ("configuration", Owner::Host, 0o700),
        ("loop-storage", Owner::Host, 0o711),
        ("private-storage", Owner::Mapped(64000), 0o700),
    ]
    .into_iter()
    .map(|(purpose, owner, mode)| Requirement {
        purpose: purpose.into(),
        alias_group: None,
        policy: Policy {
            kind: Kind::Directory,
            owner,
            mode: ModePolicy::Exact(mode),
        },
    })
    .collect()
}
fn inventory_receive(home: &Path) -> (crate::anchor::Configuration, Vec<crate::anchor::Anchor>) {
    use crate::anchor::{self, Manifest, Receiver, Transport};
    use std::os::fd::AsFd as _;
    assert_eq!(fs::metadata("/").expect("namespace root").uid(), 65534);
    let manifest =
        Manifest::parse(&std::env::var("LOOP_HOME_INVENTORY_MANIFEST").expect("manifest"))
            .expect("declaration");
    let socket = std::os::unix::net::UnixStream::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .expect("stdin"),
    );
    let fds =
        anchor::transport::receive(&socket, 3, std::time::Duration::from_secs(30)).expect("rights");
    drop(socket);
    anchor::transport::replace_stdin("mail-binding").expect("null stdin");
    let receiver = Receiver::current().expect("receiver");
    let configuration = receiver
        .configuration(
            &manifest,
            &fds,
            anchor::Entry {
                operation: "mail-binding",
                loop_name: "alpha",
                transport: Transport::Rights,
            },
            home,
            false,
        )
        .expect("configuration");
    let anchors = receiver
        .validate(
            &manifest,
            fds,
            "mail-binding",
            "alpha",
            Transport::Rights,
            &inventory_policies(),
        )
        .expect("anchors");
    (configuration, anchors)
}
fn inventory_case(home: &Path, case: &str) {
    let (configuration, mut anchors) = inventory_receive(home);
    let private = Arc::new(anchors.pop().expect("private"));
    let storage = Arc::new(anchors.pop().expect("storage"));
    if matches!(case, "scan-storage" | "scan-private" | "scan-private-acl") {
        inventory_anchor_refusal(home, case, &configuration, storage, private);
        return;
    }
    let held = home.join("held-storage");
    fs::rename(home.join(".var/loops/alpha"), &held).expect("retain storage");
    fs::rename(home.join(".config/loops"), home.join("held-configuration"))
        .expect("retain configuration");
    fs::rename(held.join("private"), home.join("held-private")).expect("retain private");
    for path in [
        home.join(".var/loops/alpha"),
        home.join(".config/loops"),
        held.join("private"),
    ] {
        fs::write(path, b"replacement is not a directory").expect("replacement");
    }
    inventory_mutate(home, &held, case);
    let snapshot_writer = fs::OpenOptions::new()
        .write(true)
        .open(home.join("held-private/.config/mail/loop.toml"))
        .expect("fixture writer");
    let mailbox = File::open(held.join("workers/worker/mail")).expect("fixture mailbox");
    let mut groups = vec![64001, 64020, 64021, 64022];
    if case == "other-private" {
        groups.push(64100);
    }
    nix::unistd::setgroups(
        &groups
            .into_iter()
            .map(nix::unistd::Gid::from_raw)
            .collect::<Vec<_>>(),
    )
    .expect("mail groups");
    let gid = nix::unistd::Gid::from_raw(64001);
    nix::unistd::setresgid(gid, gid, gid).expect("service group");
    let uid = nix::unistd::Uid::from_raw(64001);
    nix::unistd::setresuid(uid, uid, uid).expect("service owner");
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .finish();
    let _trace = tracing::subscriber::set_default(subscriber);
    let result = super::super::steering::BindingInventory::open_beneath(
        home,
        "alpha",
        &configuration,
        Arc::clone(&storage),
        Arc::clone(&private),
        Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    );
    let identity = super::super::birth::Identity {
        uid: 64010,
        name: "worker".into(),
        reservation: "fixture".into(),
    };
    let result = result.and_then(|inventory| {
        if case == "fresh-snapshot" {
            use std::io::Write as _;
            (&snapshot_writer)
                .write_all(b"#")
                .expect("change held snapshot after opening");
        }
        if case == "fresh-inbox" {
            nix::fcntl::renameat(&mailbox, "inbox", &mailbox, "old-inbox").expect("replace inbox");
            nix::sys::stat::mkdirat(
                &mailbox,
                "inbox",
                nix::sys::stat::Mode::from_bits_truncate(0o770),
            )
            .expect("new inbox");
        }
        inventory.verify_worker(&identity)
    });
    inventory_result(case, result);
}
fn inventory_result(case: &str, result: super::super::journal::Result<()>) {
    if case.starts_with("override-") {
        assert!(matches!(
            &result,
            Err(super::super::journal::MailError::Entry(_))
        ));
    }
    if case == "held" {
        result.expect("held inventory and freshness");
    } else {
        let error = result.expect_err("changed inventory refuses");
        assert!(
            error.to_string().contains(if case == "fresh-inbox" {
                "endpoint identity changed"
            } else if case == "fresh-snapshot" {
                "changed-source:"
            } else if case == "snapshot-mode" {
                "exact service ACL"
            } else if case.starts_with("override-") {
                "anchor-declaration: operation=mail-binding purpose=registry-override"
            } else if case == "other-private" {
                "unsafe-storage: service holds an actor private credential"
            } else if case == "anchor-mode" {
                "anchor-mode"
            } else {
                "binding endpoint unavailable"
            }),
            "{case}: {error}"
        );
    }
}

fn inventory_anchor_refusal(
    home: &Path,
    case: &str,
    configuration: &crate::anchor::Configuration,
    storage: Arc<crate::anchor::Anchor>,
    private: Arc<crate::anchor::Anchor>,
) {
    let path = home.join(if case == "scan-storage" {
        ".var/loops/alpha"
    } else {
        ".var/loops/alpha/private"
    });
    if case == "scan-private-acl" {
        acl::install(&File::open(&path).expect("private root"), 64101, true)
            .expect("replace service grant");
        private
            .revalidate()
            .expect("generic preserved mode still admits the ACL");
    } else {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777))
            .expect("change custody after receipt");
    }
    let directory = Directory {
        configuration: None,
        home: home.to_owned(),
        service: 64001,
        owner: 0,
        durability: Durability {
            crash_consistent_rename: true,
            durable_sync: true,
        },
    };
    // Drive the scan directly: BindingInventory's preflight must not mask a swallowed error.
    let result = directory.inventory_with(
        &configuration.registry,
        &configuration.allocations,
        Some(&LoopCustody {
            row: configuration.registry.row("alpha", home).expect("row"),
            storage,
            private,
        }),
    );
    if case == "scan-private-acl" {
        assert!(
            matches!(
                result,
                Err(super::super::journal::MailError::Invalid(
                    "unsafe-storage: exact service ACL required"
                ))
            ),
            "scan must preserve the snapshot refusal"
        );
        return;
    }
    let Err(super::super::journal::MailError::Entry(reason)) = result else {
        panic!("scan must preserve the entry refusal");
    };
    assert!(reason.starts_with("anchor-mode:"), "{case}: {reason}");
    assert!(reason.contains("operation=mail-binding"), "{reason}");
    let purpose = if case == "scan-storage" {
        "loop-storage"
    } else {
        "private-storage"
    };
    assert!(reason.contains(&format!("purpose={purpose}")), "{reason}");
}

fn inventory_mutate(home: &Path, storage: &Path, case: &str) {
    let worker = storage.join("workers/worker");
    match case {
        "held" | "fresh-inbox" | "fresh-snapshot" | "other-private" | "override-empty"
        | "override-canonical" => {}
        "anchor-mode" => {
            fs::set_permissions(storage, fs::Permissions::from_mode(0o731)).expect("widen anchor");
        }
        "snapshot-mode" => fs::set_permissions(
            home.join("held-private/.config/mail/loop.toml"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("mask grant"),
        "outbox-mode" => fs::set_permissions(
            worker.join("mail/outbox"),
            fs::Permissions::from_mode(0o777),
        )
        .expect("widen outbox"),
        "ancestor-mode" => {
            fs::set_permissions(&worker, fs::Permissions::from_mode(0o733))
                .expect("widen ancestor");
        }
        "linked-worker" => {
            fs::rename(&worker, storage.join("held-worker")).expect("rename worker");
            std::os::unix::fs::symlink("../held-worker", &worker).expect("linked worker");
        }
        _ => panic!("unknown inventory case"),
    }
}
struct InventoryFixture(PathBuf);
impl Drop for InventoryFixture {
    fn drop(&mut self) {
        let _cleanup = inventory_command(&self.0, "cleanup").output();
        let _removed = fs::remove_dir_all(&self.0);
    }
}
fn inventory_configuration(home: &Path) -> PathBuf {
    let config = home.join(".config/loops");
    fs::create_dir_all(&config).expect("config");
    for path in [home.to_path_buf(), home.join(".config"), config.clone()] {
        inventory_owned(&path, nix::unistd::geteuid().as_raw(), 0o700);
    }
    for (name, bytes) in [
        (
            "registry.toml",
            concat!(
                "namespace='org.superloop-tools.loophome.registry'\n",
                "version=[1,0,0]\n",
                "loops=[{name='alpha',uid=64000,launch='dev/alpha'},",
                "{name='beta',uid=64100,launch='dev/beta'}]\n",
            ),
        ),
        (
            "allocations.toml",
            "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n",
        ),
    ] {
        let path = config.join(name);
        fs::write(&path, bytes).expect("config file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
    config
}
fn inventory_parent(case: &str) {
    use crate::anchor::{HostVerifier, Manifest, Transport};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let home = std::env::temp_dir().join(format!(
        "mail-inventory-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&home).expect("fixture home");
    let temp = InventoryFixture(home);
    let home = temp.0.as_path();
    fs::write(home.join(INVENTORY_MARKER), b"").expect("fixture marker");
    let config = inventory_configuration(home);
    let output = inventory_command(home, "seed")
        .output()
        .expect("namespace seed");
    assert!(
        output.status.success(),
        "unmeasured namespace seed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verifier = HostVerifier::current().expect("host verifier");
    let paths = [
        config,
        home.join(".var/loops/alpha"),
        home.join(".var/loops/alpha/private"),
    ];
    let pins = paths
        .iter()
        .zip(inventory_policies())
        .enumerate()
        .map(|(i, (path, requirement))| {
            verifier
                .pin(
                    path,
                    &requirement.purpose,
                    u32::try_from(i).expect("slot"),
                    requirement.policy,
                )
                .expect("host pin")
        })
        .collect::<Vec<_>>();
    let manifest = Manifest {
        version: 1,
        operation: "mail-binding".into(),
        loop_name: "alpha".into(),
        transport: Transport::Rights,
        records: pins.iter().map(crate::anchor::HostPin::record).collect(),
    };
    let (send, receive) = std::os::unix::net::UnixStream::pair().expect("socket pair");
    let mut command = inventory_command(home, case);
    if case == "override-empty" {
        command.env("ENTER_LOOP_REGISTRY", "");
    } else if case == "override-canonical" {
        command.env(
            "ENTER_LOOP_REGISTRY",
            home.join(".config/loops/registry.toml"),
        );
    }
    let child = command
        .env(
            "LOOP_HOME_INVENTORY_MANIFEST",
            serde_json::to_string(&manifest).expect("render"),
        )
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            receive,
        )))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("namespace receiver");
    crate::anchor::transport::send(
        &send,
        &pins
            .into_iter()
            .map(crate::anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .expect("send rights");
    let output = child.wait_with_output().expect("measurement");
    let cleanup = inventory_command(home, "cleanup")
        .output()
        .expect("cleanup");
    assert!(
        cleanup.status.success(),
        "cleanup: {}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success()
            && stdout.contains("1 passed")
            && stdout.contains(inventory_skip(case)),
        "{case}: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
/// # Panics
/// Panics unless a real receiver retains inventory after all original directory paths are replaced.
/// ´claim:loophome:binding-inventory-retains-received-custody´
/// ´test:unit:binding-inventory-retains-storage´
#[test]
fn binding_inventory_retains_storage() {
    if let Ok(phase) = std::env::var(INVENTORY_PHASE) {
        let home = inventory_home();
        match phase.as_str() {
            "seed" => inventory_seed(&home),
            "cleanup" => {
                for name in [".var", "held-storage", "held-private"] {
                    let path = home.join(name);
                    if path.exists() {
                        fs::remove_dir_all(path).expect("fixture cleanup");
                    }
                }
            }
            case => inventory_case(&home, case),
        }
        return;
    }
    for case in [
        "held",
        "other-private",
        "override-empty",
        "override-canonical",
        "scan-storage",
        "scan-private",
        "scan-private-acl",
        "anchor-mode",
        "snapshot-mode",
        "outbox-mode",
        "ancestor-mode",
        "linked-worker",
        "fresh-snapshot",
        "fresh-inbox",
    ] {
        inventory_parent(case);
    }
}
