#[path = "support/bounded.rs"]
pub(crate) mod bounded;
use bounded::CommandOutput as _;
use loop_home::anchor::{
    self, Anchor, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement,
    Transport,
};
use loop_home::mail::{
    Address,
    birth::Identity,
    instant::Instant,
    journal,
    publication::{self, Durability, Endpoint},
    steering::{BindingCustody, BindingSelection, ReplyCustody, ReplySession},
    worker_provision,
};
use std::fs::{self, File};
use std::io::{Seek as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

const PHASE: &str = "LOOP_HOME_REPLY_PHASE";
const HOME: &str = "LOOP_HOME_REPLY_HOME";
const BODY: &[u8] = b"reply bytes\0\xff\n";

pub(crate) struct Fixture(pub(crate) PathBuf);
impl Fixture {
    pub(crate) fn new() -> Self {
        Self::at(&std::env::temp_dir(), "mail-reply")
    }
    fn at(root: &Path, prefix: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = root.join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("parent creates unique fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private fixture");
        fs::write(
            path.join(".reply-fixture"),
            b"owned by reply fixture parent\n",
        )
        .expect("fixture marker");
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // This path is the parent's create_dir result, never taken from an environment variable.
        let cleanup = std::process::Command::new("/usr/bin/podman")
            .args([
                "unshare",
                "/usr/bin/python3",
                "-I",
                "-c",
                "import shutil,sys; shutil.rmtree(sys.argv[1])",
            ])
            .arg(&self.0)
            .env_remove("_CONTAINERS_USERNS_CONFIGURED")
            .env_remove("_CONTAINERS_ROOTLESS_UID")
            .fixture_output("reply cleanup", Duration::from_secs(30));
        bounded::cleanup(&self.0, cleanup);
    }
}
pub(crate) fn child_command(home: &Path, phase: &str) -> std::process::Command {
    let reference = phase
        .starts_with("inbound-path-")
        .then(|| std::env::var_os("LOOP_HOME_PATH_REFERENCE"))
        .flatten();
    let entry = reference.map_or_else(
        || std::env::current_exe().expect("test image"),
        PathBuf::from,
    );
    assert!(entry.is_absolute(), "absolute pathname reference image");
    let mut command = std::process::Command::new("/usr/bin/podman");
    command.arg("unshare");
    if phase.starts_with("inbound-path-") || phase == "inbound-legacy-entry" {
        command.args(["/usr/bin/unshare", "--mount", "--propagation", "private"]);
    }
    command
        .arg(entry)
        .env(PHASE, phase)
        .env(HOME, home)
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    command
}
pub(crate) fn child_home() -> PathBuf {
    let home = PathBuf::from(std::env::var_os(HOME).expect("fixture home"));
    assert!(home.is_absolute());
    let name = home.file_name().expect("name").to_str().expect("UTF8");
    let temporary = std::env::temp_dir();
    assert!(name.starts_with("mail-reply-") || name.starts_with("mail-inbound-"));
    assert_eq!(home.parent(), Some(temporary.as_path()));
    assert!(
        !fs::symlink_metadata(&home)
            .expect("home")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(home.join(".reply-fixture")).expect("parent marker"),
        b"owned by reply fixture parent\n"
    );
    home
}
fn owned(path: &Path, uid: u32, mode: u32) {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(uid)),
    )
    .expect("owner");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}
fn seed(home: &Path) {
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    for (name, uid, mode) in [
        ("runs", 0, 0o700),
        (".var", 0, 0o711),
        (".var/loops", 0, 0o711),
        (".var/loops/alpha", 0, 0o711),
        (".var/loops/alpha/private", 64000, 0o700),
        (".var/loops/alpha/private/.config", 64000, 0o700),
        (".var/loops/alpha/private/.config/mail", 64000, 0o700),
        (".var/loops/.mail-service", 64001, 0o700),
    ] {
        let path = home.join(name);
        fs::create_dir(&path).expect("seed directory");
        owned(&path, uid, mode);
    }
    let path = home.join(".var/loops/alpha/private/.config/mail/loop.toml");
    fs::write(&path, "workers=[]\n[mail]\nversion=1\nallow=[]\n").expect("loop config");
    owned(&path, 64000, 0o600);
    seed_principal(home);
}
fn seed_principal(home: &Path) {
    let root = home.join(".var/loops/alpha");
    for (name, uid, gid, mode) in [
        ("mail", 64001, 64020, 0o750),
        ("mail/inbox", 64001, 64020, 0o770),
        ("mail/sent", 64001, 64020, 0o770),
        ("mail/draft", 64000, 64000, 0o700),
        ("mail/read", 64000, 64000, 0o700),
        ("mail/outbox", 64000, 64000, 0o700),
        (".mail-staging", 64001, 64001, 0o700),
    ] {
        let path = root.join(name);
        fs::create_dir(&path).expect("principal folder");
        owned(&path, uid, mode);
        nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(gid)))
            .expect("mailbox group");
    }
    let output = std::process::Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            r"
import os,struct,sys
entries=[(1,7,0xffffffff),(2,7,64001),(4,0,0xffffffff),(16,7,0xffffffff),(32,0,0xffffffff)]
encoded=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*row) for row in entries)
os.setxattr(sys.argv[1],'system.posix_acl_access',encoded)
",
        ])
        .arg(root.join("mail/outbox"))
        .fixture_output("reply principal ACL", Duration::from_secs(60))
        .expect("fixture ACL");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
pub(crate) fn configuration(home: &Path) {
    for name in [".config", ".config/loops"] {
        let path = home.join(name);
        fs::create_dir(&path).expect("configuration directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for (name, text) in [
        (
            "registry.toml",
            concat!(
                "namespace='org.superloop-tools.loophome.registry'\n",
                "version=[1,0,0]\n",
                "loops=[{name='alpha',uid=64000,launch='dev/alpha'}]\n"
            ),
        ),
        (
            "allocations.toml",
            "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n",
        ),
        (
            "mail-service.toml",
            "version=1\nuid=64001\ncrash_consistent_rename=true\ndurable_sync=true\n",
        ),
    ] {
        let path = home.join(".config/loops").join(name);
        fs::write(&path, text).expect("configuration");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
}
fn requirements() -> Vec<Requirement> {
    [
        (
            "owner-home",
            Owner::Host,
            Kind::Directory,
            ModePolicy::Exact(0o700),
        ),
        (
            "runs-root",
            Owner::Host,
            Kind::Directory,
            ModePolicy::Exact(0o700),
        ),
        (
            "entry-executable",
            Owner::Host,
            Kind::File,
            ModePolicy::Executable,
        ),
        (
            "configuration",
            Owner::Host,
            Kind::Directory,
            ModePolicy::Exact(0o700),
        ),
        (
            "loop-storage",
            Owner::Host,
            Kind::Directory,
            ModePolicy::Exact(0o711),
        ),
        (
            "private-storage",
            Owner::Mapped(64000),
            Kind::Directory,
            ModePolicy::Exact(0o700),
        ),
        (
            "identity-executable",
            Owner::RootFile,
            Kind::File,
            ModePolicy::Executable,
        ),
        (
            "journal",
            Owner::Mapped(64001),
            Kind::Directory,
            ModePolicy::Exact(0o700),
        ),
    ]
    .into_iter()
    .map(|(purpose, owner, kind, mode)| Requirement {
        purpose: purpose.into(),
        alias_group: None,
        policy: Policy { kind, owner, mode },
    })
    .collect()
}
fn refuse_cleanup(home: &Path) {
    let output = child_command(home, "cleanup")
        .fixture_output("reply cleanup refusal", Duration::from_secs(60))
        .expect("unsupported cleanup phase");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains("unsupported fixture phase cleanup"),
        "child must refuse environment-driven cleanup by phase: {stderr}"
    );
    assert_eq!(
        fs::read(home.join(".reply-fixture")).expect("parent directory survives"),
        b"owned by reply fixture parent\n"
    );
}
fn parent(case: &str) {
    let fixture = Fixture::new();
    let home = &fixture.0;
    configuration(home);
    if case == "held" {
        refuse_cleanup(home);
    }
    let output = child_command(home, "seed")
        .fixture_output("reply seed", Duration::from_secs(60))
        .expect("seed namespace");
    assert!(
        output.status.success(),
        "unmeasured seed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verifier = HostVerifier::current().expect("initial namespace verifier");
    let paths = [
        home.clone(),
        home.join("runs"),
        std::env::current_exe().expect("entry image"),
        home.join(".config/loops"),
        home.join(".var/loops/alpha"),
        home.join(".var/loops/alpha/private"),
        PathBuf::from("/usr/bin/setpriv"),
        home.join(".var/loops/.mail-service"),
    ];
    let pins = paths
        .iter()
        .zip(requirements())
        .enumerate()
        .map(|(slot, (path, required))| {
            verifier
                .pin(
                    path,
                    &required.purpose,
                    u32::try_from(slot).expect("slot"),
                    required.policy,
                )
                .expect("pin")
        })
        .collect::<Vec<_>>();
    let manifest = Manifest {
        version: 1,
        operation: "mail-binding".into(),
        loop_name: "alpha".into(),
        transport: Transport::Rights,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let (send, receive) = std::os::unix::net::UnixStream::pair().expect("rights socket");
    let mut command = child_command(home, case);
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
            "LOOP_HOME_REPLY_MANIFEST",
            serde_json::to_string(&manifest).expect("manifest"),
        )
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            receive,
        )))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .fixture_spawn("reply receipt", Duration::from_secs(120))
        .expect("receiver");
    anchor::transport::send(
        &send,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .expect("rights");
    let output = child.wait().expect("measurement");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("reply custody passed"),
        "{case}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn receive() -> (Manifest, Vec<std::os::fd::OwnedFd>) {
    assert_eq!(fs::metadata("/").expect("namespace root").uid(), 65534);
    let manifest = Manifest::parse(&std::env::var("LOOP_HOME_REPLY_MANIFEST").expect("manifest"))
        .expect("parse");
    let socket = std::os::unix::net::UnixStream::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .expect("stdin"),
    );
    let fds =
        anchor::transport::receive(&socket, 8, std::time::Duration::from_secs(30)).expect("frame");
    drop(socket);
    anchor::transport::replace_stdin("mail-binding").expect("null stdin");
    (manifest, fds)
}
fn fixture_anchors(
    home: &Path,
    manifest: &Manifest,
    fds: Vec<std::os::fd::OwnedFd>,
) -> (anchor::Configuration, Vec<Anchor>) {
    let receiver = Receiver::current().expect("receiver");
    let configuration = receiver
        .configuration(
            manifest,
            &fds,
            anchor::Entry {
                operation: &manifest.operation,
                loop_name: "alpha",
                transport: Transport::Rights,
            },
            home,
            false,
        )
        .expect("configuration");
    let anchors = receiver
        .validate(
            manifest,
            fds,
            &manifest.operation,
            "alpha",
            Transport::Rights,
            &requirements(),
        )
        .expect("capabilities");
    (configuration, anchors)
}
fn package_seed(
    home: &Path,
    custody: ReplyCustody,
    identity: &Identity,
    configuration: &anchor::Configuration,
    storage: &Arc<Anchor>,
    journal: &Arc<Anchor>,
    reply: bool,
) {
    let row = configuration.registry.row("alpha", home).expect("row");
    let driver = home.join("runs/R");
    fs::create_dir(&driver).expect("driver directory");
    owned(&driver, 64000, 0o700);
    let _session = custody.enter(identity, false).expect("service");
    let body = if identity.reservation == "superloop-lane:R" {
        b"Continue the synthetic round.\n".as_slice()
    } else {
        BODY
    };
    let (_writer, instant) = delivery_for_name(storage, journal, &row, reply, &identity.name, body);
    writeln!(std::io::stdout().lock(), "PACKAGE-DELIVERY {instant}").expect("seed result");
}

fn complete_birth(
    home: &Path,
    identity: &Identity,
    configuration: &anchor::Configuration,
    anchors: (&Anchor, &Anchor, &Anchor),
) {
    for phase in ["reserve", "finish"] {
        worker_provision::creation_beneath(
            home,
            "alpha",
            identity,
            phase,
            configuration,
            anchors.0,
            anchors.1,
            anchors.2,
        )
        .expect("production birth");
    }
}

fn child(home: &Path, case: &str) {
    let (manifest, fds) = receive();
    let receiver = Receiver::current().expect("receiver");
    if case == "declarations" {
        declaration_refusals(home, &manifest, &fds, &receiver);
        return;
    }
    let custody = ReplyCustody::receive(&receiver, &manifest, duplicate(&fds), "alpha");
    let (configuration, mut anchors) = fixture_anchors(home, &manifest, fds);
    let journal = Arc::new(anchors.pop().expect("journal"));
    let executor = anchors.pop().expect("executor");
    let private = Arc::new(anchors.pop().expect("private"));
    let storage = Arc::new(anchors.pop().expect("storage"));
    let _config = anchors.pop().expect("config");
    let identity = if case == "package-canonical-inbound-seed" {
        Identity::for_reservation(64010, "superloop-lane:R".into())
    } else {
        Identity {
            uid: 64010,
            name: "worker".into(),
            reservation: "reply-fixture".into(),
        }
    };
    if case.starts_with("override-") {
        lifetime_override(
            home,
            &identity,
            &configuration,
            (&storage, &private, &executor),
            &custody.err().expect("override at receiving constructor"),
        );
        return;
    }
    complete_birth(
        home,
        &identity,
        &configuration,
        (&storage, &private, &executor),
    );
    if matches!(
        case,
        "package-seed" | "package-inbound-seed" | "package-canonical-inbound-seed"
    ) {
        package_seed(
            home,
            custody.expect("custody"),
            &identity,
            &configuration,
            &storage,
            &journal,
            case == "package-seed",
        );
        return;
    }
    post_lock_check(
        home,
        &identity,
        &configuration,
        &storage,
        &private,
        &executor,
    );
    let probe = File::open(home.join(".var/loops/alpha/.mail-births"))
        .expect("independent lock description");
    replace_received_paths(home);
    let row = configuration.registry.row("alpha", home).expect("row");
    let shared_storage = Arc::clone(&storage);
    let shared_journal = Arc::clone(&journal);
    let mutator = Mutator::new(home);
    let session = custody
        .expect("receiving constructor")
        .enter(&identity, case != "repair")
        .expect("production session and identity drop");
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 64001);
    let (probe, error) =
        nix::fcntl::Flock::lock(probe, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect_err("lease survives drop");
    assert_eq!(error, nix::errno::Errno::EWOULDBLOCK);
    if case.starts_with("outbox-") || case.starts_with("admission-") {
        admission_case(
            session,
            &shared_storage,
            &shared_journal,
            &row,
            case,
            mutator,
        );
    } else {
        measure(&session, &shared_storage, &shared_journal, &row, case);
        drop(session);
        drop(mutator);
    }
    drop(
        nix::fcntl::Flock::lock(probe, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect("session drop releases lease"),
    );
}
fn lifetime_override(
    home: &Path,
    identity: &Identity,
    configuration: &anchor::Configuration,
    anchors: (&Anchor, &Anchor, &Anchor),
    error: &journal::MailError,
) {
    assert_entry_override(error);
    for verify_only in [false, true] {
        let error = worker_provision::verify_active_beneath(
            home,
            "alpha",
            identity,
            verify_only,
            configuration,
            anchors.0,
            anchors.1,
            anchors.2,
        )
        .err()
        .expect("direct lifetime override");
        assert_entry_override(&error);
    }
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    assert!(!home.join(".var/loops/alpha/.mail-births").exists());
}
fn duplicate(fds: &[std::os::fd::OwnedFd]) -> Vec<std::os::fd::OwnedFd> {
    fds.iter()
        .map(|fd| fd.try_clone().expect("fixture duplicate"))
        .collect()
}
fn assert_entry_override(error: &journal::MailError) {
    assert!(matches!(error, journal::MailError::Entry(_)), "{error}");
    assert_eq!(
        error.to_string(),
        "anchor-declaration: operation=mail-binding purpose=registry-override"
    );
}

fn post_lock_check(
    home: &Path,
    identity: &Identity,
    configuration: &anchor::Configuration,
    root: &Anchor,
    private: &Anchor,
    executor: &Anchor,
) {
    use nix::fcntl::{Flock, FlockArg};
    let verified = worker_provision::verify_active_beneath(
        home,
        "alpha",
        identity,
        true,
        configuration,
        root,
        private,
        executor,
    )
    .expect("first phase");
    let path = home.join(".var/loops/alpha");
    let file = File::open(path.join(".mail-births")).expect("independent receipt lock");
    let info = file.metadata().expect("lock identity");
    let lock_id = format!(
        "{:02x}:{:02x}:{}",
        nix::sys::stat::major(info.dev()),
        nix::sys::stat::minor(info.dev()),
        info.ino()
    );
    let guard = Flock::lock(file, FlockArg::LockExclusive).expect("hold receipt lock");
    std::thread::scope(|scope| {
        let waiter = scope.spawn(move || verified.hold());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let blocked = loop {
            if fs::read_to_string("/proc/locks")
                .expect("lock census")
                .lines()
                .any(|line| {
                    line.contains("->") && line.split_whitespace().any(|word| word == lock_id)
                })
            {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::yield_now();
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o731))
            .expect("change during receipt-lock wait");
        drop(guard);
        let result = waiter.join().expect("waiter");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711))
            .expect("restore before assertion");
        assert!(blocked, "lock wait was not measured");
        let error = result.expect_err("root revalidated after lock wait");
        assert!(error.to_string().contains("anchor-mode"), "{error}");
    });
}
fn beneath(anchor: &Anchor, path: &str) -> File {
    let (_, root) = anchor.relay().expect("held anchor");
    let fd = nix::fcntl::openat2(
        &root,
        path,
        nix::fcntl::OpenHow::new()
            .flags(
                nix::fcntl::OFlag::O_RDONLY
                    | nix::fcntl::OFlag::O_DIRECTORY
                    | nix::fcntl::OFlag::O_CLOEXEC,
            )
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    )
    .expect("fixture directory beneath anchor");
    File::from(fd)
}
fn delivery(
    storage: &Arc<Anchor>,
    journal_anchor: &Anchor,
    row: &loop_home::LoopRecord,
) -> (journal::Journal, Instant) {
    delivery_for(storage, journal_anchor, row, true)
}
fn delivery_for(
    storage: &Arc<Anchor>,
    journal_anchor: &Anchor,
    row: &loop_home::LoopRecord,
    reply: bool,
) -> (journal::Journal, Instant) {
    delivery_for_name(storage, journal_anchor, row, reply, "worker", BODY)
}
fn delivery_for_name(
    storage: &Arc<Anchor>,
    journal_anchor: &Anchor,
    row: &loop_home::LoopRecord,
    reply: bool,
    worker: &str,
    body: &[u8],
) -> (journal::Journal, Instant) {
    let address = format!("alpha+{worker}");
    let mut journal =
        journal::Journal::create(beneath(journal_anchor, ".")).expect("journal create");
    let durable = Durability {
        crash_consistent_rename: true,
        durable_sync: true,
    };
    let sender = Endpoint::open_shared_beneath(
        storage,
        row,
        Address::parse(if reply { &address } else { "alpha" }).expect("sender"),
        if reply { 64021 } else { 64020 },
        durable,
    )
    .expect("sender endpoint");
    let recipient = Endpoint::open_shared_beneath(
        storage,
        row,
        Address::parse(if reply { "alpha" } else { &address }).expect("recipient"),
        if reply { 64020 } else { 64021 },
        durable,
    )
    .expect("recipient endpoint");
    let worker_staging = format!("workers/{worker}/.mail-staging");
    let staging = beneath(
        storage,
        if reply {
            &worker_staging
        } else {
            ".mail-staging"
        },
    );
    let outgoing_name = format!("{address}.01.letter");
    let outgoing = if reply {
        "alpha.01.letter"
    } else {
        &outgoing_name
    };
    let fd = nix::fcntl::openat(
        &staging,
        outgoing,
        nix::fcntl::OFlag::O_WRONLY
            | nix::fcntl::OFlag::O_CREAT
            | nix::fcntl::OFlag::O_EXCL
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .expect("fixture source");
    File::from(fd).write_all(body).expect("source bytes");
    let now = Instant::parse("2026-01-01T00:00:00.001Z").expect("instant");
    let record = publication::prepare(&journal, &sender, &recipient, outgoing)
        .expect("prepare")
        .accept(
            &mut journal,
            now,
            journal::digest(b"registry"),
            vec![journal::digest(b"config")],
        )
        .expect("accept");
    publication::publish(&mut journal, &sender, &recipient, &record.delivery).expect("publish");
    publication::cleanup_source(
        &sender,
        &recipient,
        &journal.record(&record.delivery).expect("published record"),
    )
    .expect("source cleanup");
    journal
        .advance(
            &record.delivery,
            journal::Phase::Complete,
            &journal::Witness::Absent,
            record.delivery.clone(),
        )
        .expect("complete delivery");
    (journal, record.delivery)
}
fn measure(
    session: &ReplySession,
    storage: &Arc<Anchor>,
    journal: &Anchor,
    row: &loop_home::LoopRecord,
    case: &str,
) {
    let (_writer, instant) = delivery(storage, journal, row);
    let result = session
        .reply("review", &instant)
        .expect("held reply binding with writer active");
    assert_eq!(result.1, BODY);
    assert_eq!(
        session
            .verify_reply("review", &instant)
            .expect("verify existing pin")
            .1,
        BODY
    );
    let error = session
        .verify_reply("absent", &instant)
        .expect_err("absent pin refuses");
    assert!(error.to_string().contains("reservation"), "{error}");
    assert!(
        session
            .reply("../escape", &instant)
            .expect_err("step escape")
            .to_string()
            .contains("invalid-name: round step")
    );
    if case == "payload" {
        changed_payload(session, storage, &result.0);
    }
    if case == "journal-mode" {
        let (_, fd) = journal.relay().expect("journal root");
        nix::sys::stat::fchmodat(
            File::from(fd),
            ".",
            nix::sys::stat::Mode::from_bits_truncate(0o750),
            nix::sys::stat::FchmodatFlags::FollowSymlink,
        )
        .expect("widen held journal");
        let error = session
            .verify_reply("review", &instant)
            .expect_err("journal revalidated");
        assert!(error.to_string().contains("anchor-mode"), "{error}");
    }
}
fn changed_payload(session: &ReplySession, storage: &Anchor, record: &journal::Record) {
    let inbox = beneath(storage, "mail/inbox");
    let fd = nix::fcntl::openat(
        &inbox,
        record.inbox_name.as_str(),
        nix::fcntl::OFlag::O_WRONLY
            | nix::fcntl::OFlag::O_TRUNC
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .expect("fixture inbox writer");
    let mut file = File::from(fd);
    file.write_all(b"changed payload")
        .expect("change delivered bytes");
    let result = session.reply("changed", &record.delivery);
    file.set_len(0).expect("truncate for restoration");
    file.rewind().expect("rewind");
    file.write_all(BODY).expect("restore delivered bytes");
    let error = result.expect_err("changed delivered bytes refuse");
    assert!(error.to_string().contains("changed-source:"), "{error}");
    session
        .verify_reply("review", &record.delivery)
        .expect("restored delivery verifies");
    session
        .verify_reply("changed", &record.delivery)
        .expect_err("refusal did not publish a new pin");
}
// The custom main below executes this fixture; it is not a libtest census entry.
fn reply_session_retains_custody() {
    if let Ok(phase) = std::env::var(PHASE) {
        let home = child_home();
        if phase.starts_with("inbound-") {
            inbound_child(&home, &phase);
            return;
        }
        if phase == "seed" {
            seed(&home);
        } else {
            assert!(
                [
                    "held",
                    "repair",
                    "journal-mode",
                    "payload",
                    "override-empty",
                    "override-canonical",
                    "declarations",
                    "outbox-uid",
                    "outbox-mode",
                    "outbox-acl",
                    "outbox-wait",
                    "admission-bind",
                    "admission-verify",
                    "admission-acl",
                    "package-seed",
                    "package-inbound-seed",
                    "package-canonical-inbound-seed"
                ]
                .contains(&phase.as_str()),
                "unsupported fixture phase {phase}"
            );
            child(&home, &phase);
        }
        return;
    }
    for case in [
        "held",
        "repair",
        "journal-mode",
        "payload",
        "override-empty",
        "override-canonical",
        "declarations",
        "outbox-uid",
        "outbox-mode",
        "outbox-acl",
        "outbox-wait",
        "admission-bind",
        "admission-verify",
        "admission-acl",
    ] {
        parent(case);
        writeln!(std::io::stdout().lock(), "reply custody case {case} passed")
            .expect("case result");
    }
    inbound_parent();
    writeln!(
        std::io::stdout().lock(),
        "reply custody case inbound-continuity passed"
    )
    .expect("inbound result");
}

const TEST_NAME: &str = "reply_session_retains_custody";
// The libtest options whose value follows as the next word or after `=` in the same word.
const VALUED_OPTIONS: [&str; 4] = ["--skip", "--format", "--color", "--test-threads"];

#[derive(Default)]
pub(crate) struct TestArguments {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    pub(crate) list: bool,
    ignored: bool,
}
impl TestArguments {
    pub(crate) fn parse(args: &[std::ffi::OsString]) -> Result<Self, String> {
        let mut result = Self::default();
        let mut words = args.iter();
        while let Some(word) = words.next() {
            let word = word.to_str().ok_or("non-UTF-8 test argument")?;
            let (option, attached) = word
                .split_once('=')
                .filter(|(option, _)| option.starts_with("--"))
                .map_or((word, None), |(option, value)| (option, Some(value)));
            let value = match (VALUED_OPTIONS.contains(&option), attached) {
                (true, Some(value)) => Some(value),
                (true, None) => words.next().and_then(|word| word.to_str()),
                (false, Some(_)) => return Err(format!("unsupported test argument {word}")),
                (false, None) => None,
            };
            match option {
                "--list" => result.list = true,
                "--exact" => result.exact = true,
                "--ignored" => result.ignored = true,
                "--quiet" | "-q" | "--nocapture" | "--show-output" | "--include-ignored" => {}
                "--skip" => {
                    let filter = value.ok_or("--skip requires a filter")?;
                    result.skips.push(filter.to_owned());
                }
                "--format" => {
                    if !matches!(value, Some("pretty" | "terse")) {
                        return Err("--format requires pretty or terse".into());
                    }
                }
                "--color" => {
                    if !matches!(value, Some("auto" | "always" | "never")) {
                        return Err("--color requires auto, always or never".into());
                    }
                }
                "--test-threads" => {
                    let count = value.and_then(|word| word.parse::<usize>().ok());
                    if count.is_none_or(|count| count == 0) {
                        return Err("--test-threads requires a positive count".into());
                    }
                }
                _ if word.starts_with('-') => {
                    return Err(format!("unsupported test argument {word}"));
                }
                _ => result.filters.push(word.to_owned()),
            }
        }
        Ok(result)
    }
    fn selected(&self) -> bool {
        self.selected_for(TEST_NAME)
    }
    pub(crate) fn selected_for(&self, name: &str) -> bool {
        let matches = |filter: &String| {
            if self.exact {
                name == filter
            } else {
                name.contains(filter)
            }
        };
        !self.ignored
            && (self.filters.is_empty() || self.filters.iter().any(matches))
            && !self.skips.iter().any(matches)
    }
}

fn argument_checks() {
    for (args, text) in [
        (vec!["--list"], "reply_session_retains_custody: test"),
        (
            vec!["--list", "--format", "terse", "-q"],
            "reply_session_retains_custody: test",
        ),
        (vec!["unrelated-filter"], "0 passed"),
        (vec!["retains", "--exact"], "0 passed"),
        (vec![TEST_NAME, "--skip", "retains"], "0 passed"),
        (vec!["--ignored", "--quiet"], "0 passed"),
        (
            vec!["unrelated-filter", "--test-threads", "1", "--nocapture"],
            "0 passed",
        ),
        (
            vec!["--list", "--format=terse", "--color", "never"],
            "reply_session_retains_custody: test",
        ),
        (
            vec![TEST_NAME, "--skip=retains", "--test-threads=1"],
            "0 passed",
        ),
    ] {
        let output = argument_probe(&args);
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(text),
            "{output:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("reply custody passed"));
    }
    for args in [
        vec!["retains", "--quiet"],
        vec![TEST_NAME, "--exact", "-q"],
        vec!["no-match", TEST_NAME],
        vec![TEST_NAME, "--skip=no-match", "--test-threads=1"],
    ] {
        let output = argument_probe(&args);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("fixture home"),
            "{output:?}"
        );
    }
    for args in [["--unsupported"], ["--exact=yes"]] {
        let output = argument_probe(&args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported test argument"));
    }
}
fn argument_probe(args: &[&str]) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().expect("reply fixture executable"))
        .args(args)
        .env(PHASE, "cleanup")
        .env_remove(HOME)
        .fixture_output("reply argument admission", Duration::from_secs(10))
        .expect("bounded argument probe")
}

pub(crate) fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|word| {
        word.to_str()
            .is_some_and(|word| word.starts_with("_mail-worker-"))
    }) {
        return std::process::ExitCode::from(worker_provision::entry(
            &args,
            &mut std::io::stderr().lock(),
        ));
    }
    let selection = match TestArguments::parse(&args) {
        Ok(selection) => selection,
        Err(error) => {
            let _reported = writeln!(std::io::stderr().lock(), "reply-custody: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    if selection.list {
        if selection.selected() {
            writeln!(std::io::stdout().lock(), "{TEST_NAME}: test").expect("list result");
        }
        return std::process::ExitCode::SUCCESS;
    }
    if !selection.selected() {
        writeln!(
            std::io::stdout().lock(),
            "test result: ok. 0 passed; 0 failed; 1 filtered out"
        )
        .expect("filtered result");
        return std::process::ExitCode::SUCCESS;
    }
    if std::env::var_os(PHASE).is_none() {
        argument_checks();
    }
    reply_session_retains_custody();
    std::io::stdout()
        .write_all(b"reply custody passed\n")
        .expect("fixture result");
    std::process::ExitCode::SUCCESS
}

fn repair_state(home: &Path) -> Vec<u8> {
    let output = std::process::Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            r"import os,sys,json,stat,errno
root=sys.argv[1]; rows=[]
for parent,dirs,files in os.walk(root):
 for path in [parent]+[os.path.join(parent,n) for n in sorted(files)]:
  s=os.lstat(path)
  try: acl=os.getxattr(path,'system.posix_acl_access').hex()
  except OSError as e:
   if e.errno!=errno.ENODATA: raise
   acl=None
  data=open(path,'rb').read().hex() if stat.S_ISREG(s.st_mode) else None
  rows.append([path,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,
               s.st_mtime_ns,s.st_ctime_ns,acl,data])
print(json.dumps(sorted(rows)))",
        ])
        .arg(home.join(".var/loops"))
        .fixture_output("pre-repair snapshot", Duration::from_secs(20))
        .expect("snapshot");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn declaration_refusals(
    home: &Path,
    manifest: &Manifest,
    fds: &[std::os::fd::OwnedFd],
    receiver: &Receiver,
) {
    let identity = Identity {
        uid: 64010,
        name: "worker".into(),
        reservation: "reply-fixture".into(),
    };
    for (case, kind, purpose) in [
        ("count", "anchor-declaration", "count"),
        ("purpose", "anchor-declaration", "purposes"),
        ("operation", "anchor-declaration", "bundle"),
        ("loop", "anchor-declaration", "bundle"),
        ("slot", "anchor-declaration", "manifest"),
        ("owner", "anchor-owner", "private-storage"),
        ("kind", "anchor-declaration", "identity-executable"),
        ("alias", "anchor-owner", "journal"),
        ("roots-alias", "anchor-declaration", "runs-root"),
        ("short", "anchor-missing", "configuration"),
        ("excess", "anchor-transport", "configuration"),
    ] {
        let mut changed = manifest.clone();
        let mut descriptors = duplicate(fds);
        match case {
            "count" => {
                changed.records.pop();
            }
            "purpose" => changed.records[5].purpose = "unrelated".into(),
            "operation" => changed.operation = "other-operation".into(),
            "loop" => changed.loop_name = "beta".into(),
            "slot" => changed.records[5].slot = 1,
            "owner" => changed.records[5].owner_uid += 1,
            "kind" => changed.records[6].kind = Kind::Directory,
            "roots-alias" => {
                changed.records[1] = changed.records[0].clone();
                changed.records[1].purpose = "runs-root".into();
                changed.records[1].slot = 1;
                descriptors[1] = fds[0].try_clone().expect("root alias");
            }
            "alias" => {
                changed.records[7] = changed.records[3].clone();
                changed.records[7].purpose = "journal".into();
                changed.records[7].slot = 7;
                descriptors[7] = fds[3].try_clone().expect("alias");
            }
            "short" => {
                descriptors.pop();
            }
            "excess" => descriptors.push(fds[3].try_clone().expect("excess")),
            _ => unreachable!(),
        }
        received_refusal(
            home,
            &changed,
            descriptors,
            receiver,
            &identity,
            (kind, purpose),
        );
    }
    live_bundle_refusals(home, manifest, fds, receiver, &identity);
    assert!(!home.join(".var/loops/alpha/.mail-births").exists());
}

fn received_refusal(
    home: &Path,
    manifest: &Manifest,
    descriptors: Vec<std::os::fd::OwnedFd>,
    receiver: &Receiver,
    identity: &Identity,
    expected: (&str, &str),
) {
    let before = repair_state(home);
    let result = ReplyCustody::receive(receiver, manifest, descriptors, "alpha")
        .and_then(|custody| custody.enter(identity, false));
    let error = result.err().expect("invalid received bundle");
    let text = error.to_string();
    assert!(
        text.starts_with(expected.0) && text.contains(&format!("purpose={}", expected.1)),
        "{expected:?}: {error}"
    );
    assert_eq!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "no identity drop"
    );
    assert_eq!(
        repair_state(home),
        before,
        "{expected:?}: no repair or service write"
    );
}
fn live_bundle_refusals(
    home: &Path,
    manifest: &Manifest,
    fds: &[std::os::fd::OwnedFd],
    receiver: &Receiver,
    identity: &Identity,
) {
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::{Gid, Uid, fchown};
    let private = File::open(home.join(".var/loops/alpha/private")).expect("mutation fd");
    fchmod(&private, Mode::from_bits_truncate(0o750)).expect("widen private root");
    received_refusal(
        home,
        manifest,
        duplicate(fds),
        receiver,
        identity,
        ("anchor-mode", "private-storage"),
    );
    fchmod(&private, Mode::from_bits_truncate(0o700)).expect("restore private mode");
    fchown(
        &private,
        Some(Uid::from_raw(64011)),
        Some(Gid::from_raw(64011)),
    )
    .expect("change live private owner");
    received_refusal(
        home,
        manifest,
        duplicate(fds),
        receiver,
        identity,
        ("anchor-owner", "private-storage"),
    );
    fchown(
        &private,
        Some(Uid::from_raw(64000)),
        Some(Gid::from_raw(64000)),
    )
    .expect("restore private owner");
    let settings = home.join(".config/loops/mail-service.toml");
    let original = fs::read_to_string(&settings).expect("settings");
    let changed = original.replace("64001", "64002");
    assert_ne!(original, changed);
    fs::write(&settings, changed).expect("wrong reserved service");
    received_refusal(
        home,
        manifest,
        duplicate(fds),
        receiver,
        identity,
        ("anchor-declaration", "service"),
    );
    fs::write(settings, original).expect("restore service settings");
}

struct Mutator {
    process: std::process::Child,
    input: std::process::ChildStdin,
    replies: std::sync::mpsc::Receiver<String>,
}
impl Mutator {
    fn new(home: &Path) -> Self {
        use std::os::unix::process::CommandExt as _;
        let mut process = std::process::Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                r"import os,sys,fcntl,struct,errno
root=sys.argv[1]; journal=root+'/held-journal'
outbox=root+'/held-storage/workers/worker/mail/outbox'
f=os.open(journal,os.O_RDONLY|os.O_DIRECTORY)
s=os.stat(outbox); original=os.getxattr(outbox,'system.posix_acl_access')
# The service can kill this child by its real UID after its own permanent drop.
os.setresuid(64001,0,64001)
assert os.getresuid()==(64001,0,64001)
print('ready',flush=True)
for command in sys.stdin:
 command=command.strip()
 if command=='lock': fcntl.flock(f,fcntl.LOCK_EX)
 elif command=='release': fcntl.flock(f,fcntl.LOCK_UN)
 elif command=='journal-mode': os.chmod(journal,0)
 elif command=='journal-acl':
  entries=[(1,7,0xffffffff),(2,4,64002),(4,0,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)]
  acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*entry) for entry in entries)
  os.setxattr(journal,'system.posix_acl_access',acl)
 elif command=='outbox-uid': os.chown(outbox,64011,s.st_gid)
 elif command=='outbox-mode': os.chmod(outbox,0o777)
 elif command=='outbox-acl':
  changed=original[:20]+struct.pack('<HHI',2,1,64002)+original[20:]
  os.setxattr(outbox,'system.posix_acl_access',changed)
 elif command=='restore':
  try: os.removexattr(journal,'system.posix_acl_access')
  except OSError as e:
   if e.errno!=errno.ENODATA: raise
  os.chmod(journal,0o700); os.chown(outbox,s.st_uid,s.st_gid)
  os.chmod(outbox,s.st_mode & 0o7777); os.setxattr(outbox,'system.posix_acl_access',original)
 else: raise RuntimeError(command)
 print(command,flush=True)",
            ])
            .arg(home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .process_group(0)
            .spawn()
            .expect("root custody mutator");
        let input = process.stdin.take().expect("control pipe");
        let output = process.stdout.take().expect("ack pipe");
        let (send, replies) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{BufRead as _, Read as _};
            for line in std::io::BufReader::new(output).take(16_384).lines() {
                if send.send(line.expect("mutator acknowledgement")).is_err() {
                    break;
                }
            }
        });
        let guard = Self {
            process,
            input,
            replies,
        };
        assert_eq!(
            guard
                .replies
                .recv_timeout(Duration::from_secs(10))
                .expect("ready"),
            "ready"
        );
        guard
    }
    fn command(&mut self, word: &str) {
        writeln!(self.input, "{word}").expect("release/control pipe");
        self.input.flush().expect("flush command");
        assert_eq!(
            self.replies
                .recv_timeout(Duration::from_secs(10))
                .expect("bounded mutator acknowledgement"),
            word
        );
    }
}
impl Drop for Mutator {
    fn drop(&mut self) {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(self.process.id()).expect("PID"));
        if let Err(error) = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL) {
            assert_eq!(
                error,
                nix::errno::Errno::ESRCH,
                "kill lock-holder child {pid}"
            );
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while self.process.try_wait().expect("reap lock holder").is_none() {
            if std::time::Instant::now() >= deadline {
                let _reported = writeln!(
                    std::io::stderr().lock(),
                    "lock-holder reap timed out; pid {pid} remains unmeasured"
                );
                assert!(
                    std::thread::panicking(),
                    "lock-holder reap timed out: {pid}"
                );
                break;
            }
            std::thread::yield_now();
        }
    }
}
fn blocked_on(file: &File) {
    let info = file.metadata().expect("admission identity");
    let key = format!(
        "{:02x}:{:02x}:{}",
        nix::sys::stat::major(info.dev()),
        nix::sys::stat::minor(info.dev()),
        info.ino()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if fs::read_to_string("/proc/locks")
            .expect("lock census")
            .lines()
            .any(|line| line.contains("->") && line.split_whitespace().any(|word| word == key))
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "waiter did not block on admission"
        );
        std::thread::yield_now();
    }
}
fn journal_state(file: &File) -> (Vec<u8>, Vec<std::ffi::OsString>, (i64, i64)) {
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(file)
    ));
    let mut entries = fs::read_dir(&path)
        .expect("held entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    entries.sort();
    let info = file.metadata().expect("root metadata");
    (
        fs::read(path.join("reservation-pins.toml")).expect("pin bytes"),
        entries,
        (info.mtime(), info.mtime_nsec()),
    )
}
fn admission_case(
    session: ReplySession,
    storage: &Arc<Anchor>,
    journal: &Arc<Anchor>,
    row: &loop_home::LoopRecord,
    case: &str,
    mut mutator: Mutator,
) {
    let (_writer, instant) = delivery(storage, journal, row);
    session.reply("review", &instant).expect("initial pin");
    let root = File::from(journal.relay().expect("journal").1);
    let before = journal_state(&root);
    let session = if case.starts_with("admission-") || case == "outbox-wait" {
        waiting_case(session, journal, &instant, &root, case, &mut mutator)
    } else {
        mutator.command(case);
        for verify in [false, true] {
            let result = if verify {
                session.verify_reply("review", &instant)
            } else {
                session.reply("review", &instant)
            };
            let error = result.expect_err("live outbox custody");
            let expected = if case == "outbox-acl" {
                "outbox service ACL"
            } else {
                "actor outbox custody"
            };
            assert!(error.to_string().contains(expected), "{case}: {error}");
        }
        session
    };
    mutator.command("restore");
    assert_eq!(journal_state(&root), before, "no pin or directory mutation");
    session
        .verify_reply("review", &instant)
        .expect("restored custody verifies");
    drop(session);
}
fn waiting_case(
    session: ReplySession,
    journal: &Arc<Anchor>,
    instant: &Instant,
    root: &File,
    case: &str,
    mutator: &mut Mutator,
) -> ReplySession {
    let verify_only = case == "admission-verify";
    let outbox = case == "outbox-wait";
    let anchor = Arc::clone(journal);
    let instant = instant.clone();
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback = Arc::clone(&called);
    mutator.command("lock");
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = if outbox {
            session.verify_reply("review", &instant).map(|_| ())
        } else {
            let inspect = |_: &journal::Record| {
                callback.store(true, Ordering::SeqCst);
                Ok(())
            };
            if verify_only {
                journal::verify_reservation_beneath(&anchor, "fixture", "ref", &instant, inspect)
            } else {
                journal::bind_reservation_beneath(&anchor, "fixture", "ref", &instant, inspect)
            }
        };
        send.send((session, result)).expect("waiter receiver");
    });
    blocked_on(root);
    mutator.command(if outbox {
        "outbox-mode"
    } else if case == "admission-acl" {
        "journal-acl"
    } else {
        "journal-mode"
    });
    mutator.command("release");
    let (session, result) = receive
        .recv_timeout(Duration::from_secs(15))
        .expect("bounded admission waiter; process remains killable by fixture parent");
    let error = result.expect_err("custody changed while admission blocked");
    let expected = if outbox {
        "unsafe-storage: actor outbox custody"
    } else if case == "admission-acl" {
        "unsafe-storage: service-private object required"
    } else {
        "anchor-mode:"
    };
    assert!(error.to_string().starts_with(expected), "{case}: {error}");
    assert!(
        !called.load(Ordering::SeqCst),
        "journal callback must not run"
    );
    session
}

fn replace_received_paths(home: &Path) {
    for (from, to) in [
        (".config/loops", "held-configuration"),
        (".var/loops/alpha", "held-storage"),
        (".var/loops/.mail-service", "held-journal"),
    ] {
        fs::rename(home.join(from), home.join(to)).expect("retain original");
        fs::write(home.join(from), b"replacement").expect("substitute pathname");
    }
}

fn inbound_selection(phase: &str) -> BindingSelection {
    if phase == "inbound-reply-mismatch" {
        BindingSelection::Reply
    } else if phase.contains("verify") || phase == "inbound-unborn" {
        BindingSelection::InboundVerify
    } else {
        BindingSelection::InboundBind
    }
}
fn inbound_command(home: &Path, phase: &str) -> std::process::Output {
    let mut command = child_command(home, phase);
    if phase == "seed" || phase == "inbound-state" || phase.starts_with("inbound-path-") {
        return command
            .fixture_output("inbound reference", Duration::from_secs(60))
            .expect("bounded reference");
    }
    let selection = inbound_selection(phase);
    let entry = std::env::current_exe().expect("entry");
    let home_fd = File::open(home).expect("home");
    let runs = home.join("runs");
    let runs_fd = File::open(&runs).expect("runs");
    let pins = loop_home::mail::reply_entry::pins_for(
        (home, &home_fd.into()),
        (&runs, &runs_fd.into()),
        &entry,
        "alpha",
        selection,
    )
    .expect("selected composer");
    let manifest = Manifest {
        version: 1,
        operation: selection.operation().into(),
        loop_name: "alpha".into(),
        transport: Transport::Rights,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights");
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .expect("selected transfer");
    command
        .env(
            "LOOP_HOME_REPLY_MANIFEST",
            serde_json::to_string(&manifest).expect("frame"),
        )
        .stdin(std::os::fd::OwnedFd::from(input))
        .fixture_spawn("inbound entry", Duration::from_secs(60))
        .expect("bounded entry")
        .wait()
        .expect("inbound output")
}
fn inbound_run(home: &Path, phase: &str) -> Vec<u8> {
    let output = inbound_command(home, phase);
    assert!(output.status.success(), "{phase}: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("reply custody passed"),
        "{phase}: {output:?}"
    );
    output.stdout
}
fn inbound_parent() {
    // The legacy pathname reference must traverse every ancestor as the service identity.
    // Own this exact create_dir result; the existing bounded parent cleanup removes it.
    let fixture = Fixture::at(&std::env::temp_dir(), "mail-inbound");
    let home = &fixture.0;
    configuration(home);
    let seed = inbound_command(home, "seed");
    assert!(seed.status.success(), "{seed:?}");
    let state = inbound_run(home, "inbound-state");
    inbound_run(home, "inbound-unborn");
    inbound_run(home, "inbound-mismatch");
    assert_eq!(inbound_run(home, "inbound-state"), state, "before repair");
    inbound_run(home, "inbound-seed");
    let path_binding = inbound_run(home, "inbound-path-bind");
    let before = inbound_run(home, "inbound-state");
    assert_eq!(inbound_run(home, "inbound-verify-path"), path_binding);
    inbound_run(home, "inbound-verify-missing");
    assert_eq!(
        inbound_run(home, "inbound-state"),
        before,
        "verify-only snapshot"
    );
    let held_binding = inbound_run(home, "inbound-bind");
    assert_eq!(inbound_run(home, "inbound-path-verify"), held_binding);
    assert_eq!(
        path_binding, held_binding,
        "both routes preserve the complete record and bytes"
    );
    inbound_run(home, "inbound-reply-mismatch");
    assert_eq!(inbound_run(home, "inbound-replaced"), path_binding);
}
// Only the legacy reference enters this private mount namespace. Keep the stored
// absolute home name, but replace its unsearchable ancestors with empty directories.
// All fixture data remains on the parent's disk-backed filesystem through the bind.
pub(crate) fn searchable_reference(home: &Path) {
    use nix::mount::{MsFlags, mount};
    use std::os::fd::AsRawFd as _;
    let held = File::open(home).expect("hold parent-created home before overlay");
    let mut ancestors: Vec<_> = home.ancestors().skip(1).collect();
    ancestors.reverse();
    let blocked = ancestors.into_iter().find(|path| {
        fs::metadata(path)
            .expect("reference ancestor status")
            .mode()
            & 0o001
            == 0
    });
    let Some(blocked) = blocked else { return };
    assert_ne!(blocked, Path::new("/"), "reference root must be searchable");
    mount(
        Some("tmpfs"),
        blocked,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755,size=1m"),
    )
    .expect("private searchable ancestor overlay");
    fs::create_dir_all(home).expect("private namespace mountpoint");
    for ancestor in home.ancestors().take_while(|path| *path != blocked) {
        fs::set_permissions(ancestor, fs::Permissions::from_mode(0o755))
            .expect("searchable namespace-only ancestor");
    }
    let source = format!("/proc/self/fd/{}", held.as_raw_fd());
    mount(
        Some(source.as_str()),
        home,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .expect("bind original fixture beneath searchable namespace ancestors");
}
fn inbound_child(home: &Path, phase: &str) {
    let identity = Identity {
        uid: 64010,
        name: "worker".into(),
        reservation: "reply-fixture".into(),
    };
    let instant = Instant::parse("2026-01-01T00:00:00.001Z").expect("instant");
    if phase == "inbound-state" {
        std::io::stdout()
            .write_all(&repair_state(home))
            .expect("state");
        return;
    }
    if phase.starts_with("inbound-path-") {
        searchable_reference(home);
        let result = if phase == "inbound-path-bind" {
            loop_home::mail::steering::bind(home, "alpha", &identity, "path", &instant)
        } else {
            loop_home::mail::steering::verify(home, "alpha", &identity, "held", &instant)
        }
        .expect("pathname reference");
        inbound_result(&result);
        return;
    }
    let (manifest, fds) = receive();
    let receiver = Receiver::current().expect("receiver");
    if phase == "inbound-mismatch" {
        inbound_mismatches(home, &manifest, &fds, &receiver, &identity);
        return;
    }
    let selection = inbound_selection(phase);
    let custody =
        BindingCustody::receive(&receiver, &manifest, duplicate(&fds), "alpha", selection)
            .expect("selected receipt");
    if phase == "inbound-unborn" {
        let error = custody
            .enter(&identity)
            .err()
            .expect("verification cannot repair");
        assert!(
            matches!(&error, journal::MailError::Io(cause)
            if cause.kind() == std::io::ErrorKind::NotFound),
            "{error}"
        );
        assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
        assert!(!home.join(".var/loops/alpha/.mail-births").exists());
        return;
    }
    if phase == "inbound-seed" {
        inbound_seed(home, &manifest, fds, custody, &identity);
        return;
    }
    if phase == "inbound-replaced" {
        replace_received_paths(home);
    }
    let session = custody.enter(&identity).expect("selected entry");
    assert_eq!(session.selection(), selection);
    let step = if phase == "inbound-verify-path" {
        "path"
    } else {
        "held"
    };
    if phase == "inbound-verify-missing" || phase == "inbound-reply-mismatch" {
        let error = session
            .resolve("absent", &instant)
            .expect_err("selected refusal");
        let expected = if selection.verify_only() {
            "reservation"
        } else {
            "delivery principals differ"
        };
        assert!(error.to_string().contains(expected), "{error}");
    } else {
        inbound_result(&session.resolve(step, &instant).expect("selected delivery"));
    }
}
fn inbound_result(result: &(journal::Record, Vec<u8>)) {
    assert_eq!(result.1, BODY);
    assert_eq!(result.0.sender, "alpha");
    assert_eq!(result.0.recipient, "alpha+worker");
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string(result).expect("record and bytes")
    )
    .expect("continuity result");
}
fn inbound_seed(
    home: &Path,
    manifest: &Manifest,
    fds: Vec<std::os::fd::OwnedFd>,
    custody: BindingCustody,
    identity: &Identity,
) {
    let (configuration, mut anchors) = fixture_anchors(home, manifest, fds);
    let journal = Arc::new(anchors.pop().expect("journal"));
    let executor = anchors.pop().expect("executor");
    let private = anchors.pop().expect("private");
    let storage = Arc::new(anchors.pop().expect("storage"));
    complete_birth(
        home,
        identity,
        &configuration,
        (&storage, &private, &executor),
    );
    for name in ["", ".config", ".config/loops"] {
        loop_home::mail::acl::install(
            &File::open(home.join(name)).expect("directory"),
            64001,
            true,
        )
        .expect("reference search grant");
    }
    for name in ["registry.toml", "allocations.toml", "mail-service.toml"] {
        loop_home::mail::acl::install(
            &File::open(home.join(".config/loops").join(name)).expect("file"),
            64001,
            false,
        )
        .expect("reference read grant");
    }
    // The pathname endpoint opens the loops root for reading; held endpoints
    // start below it. Supply the reference route's non-writable listing root.
    fs::set_permissions(home.join(".var/loops"), fs::Permissions::from_mode(0o755))
        .expect("reference listing root");
    let row = configuration.registry.row("alpha", home).expect("row");
    let _session = custody.enter(identity).expect("seed session");
    let (_writer, _) = delivery_for(&storage, &journal, &row, false);
}
fn inbound_mismatches(
    home: &Path,
    manifest: &Manifest,
    fds: &[std::os::fd::OwnedFd],
    receiver: &Receiver,
    identity: &Identity,
) {
    for selection in [BindingSelection::Reply, BindingSelection::InboundVerify] {
        let before = repair_state(home);
        let error = BindingCustody::receive(receiver, manifest, duplicate(fds), "alpha", selection)
            .and_then(|custody| custody.enter(identity))
            .err()
            .expect("operation mismatch");
        assert!(error.to_string().contains("anchor-declaration"), "{error}");
        assert!(error.to_string().contains(selection.operation()), "{error}");
        assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
        assert_eq!(repair_state(home), before);
    }
}
