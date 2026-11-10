#[path = "support/bounded.rs"]
mod bounded;
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
    steering::{ReplyCustody, ReplySession},
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

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mail-reply-{}-{}",
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
fn child_command(home: &Path, phase: &str) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/podman");
    command
        .args(["unshare"])
        .arg(std::env::current_exe().expect("test image"))
        .env(PHASE, phase)
        .env(HOME, home)
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    command
}
fn child_home() -> PathBuf {
    let home = PathBuf::from(std::env::var_os(HOME).expect("fixture home"));
    assert!(home.is_absolute());
    assert_eq!(home.parent(), Some(std::env::temp_dir().as_path()));
    assert!(
        home.file_name()
            .expect("name")
            .to_str()
            .expect("UTF8")
            .starts_with("mail-reply-")
    );
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
fn configuration(home: &Path) {
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
    let child = child_command(home, case)
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
fn receive(home: &Path) -> (anchor::Configuration, Vec<Anchor>) {
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
        anchor::transport::receive(&socket, 5, std::time::Duration::from_secs(30)).expect("frame");
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
            &requirements(),
        )
        .expect("capabilities");
    (configuration, anchors)
}
fn child(home: &Path, case: &str) {
    let (configuration, mut anchors) = receive(home);
    let journal = Arc::new(anchors.pop().expect("journal"));
    let executor = anchors.pop().expect("executor");
    let private = Arc::new(anchors.pop().expect("private"));
    let storage = Arc::new(anchors.pop().expect("storage"));
    let config = anchors.pop().expect("config");
    let identity = Identity {
        uid: 64010,
        name: "worker".into(),
        reservation: "reply-fixture".into(),
    };
    for phase in ["reserve", "finish"] {
        worker_provision::creation_beneath(
            home,
            "alpha",
            &identity,
            phase,
            &configuration,
            &storage,
            &private,
            &executor,
        )
        .expect("production birth");
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
    for (from, to) in [
        (".config/loops", "held-configuration"),
        (".var/loops/alpha", "held-storage"),
        (".var/loops/.mail-service", "held-journal"),
    ] {
        fs::rename(home.join(from), home.join(to)).expect("retain original");
        fs::write(home.join(from), b"replacement").expect("substitute pathname");
    }
    let row = configuration.registry.row("alpha", home).expect("row");
    let shared_storage = Arc::clone(&storage);
    let shared_journal = Arc::clone(&journal);
    let custody = ReplyCustody {
        configuration: &configuration,
        configuration_directory: &config,
        loop_storage: storage,
        private_storage: private,
        identity_executable: &executor,
        journal,
    };
    let session = custody
        .enter(home, "alpha", &identity, case != "repair")
        .expect("production session and identity drop");
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 64001);
    let (probe, error) =
        nix::fcntl::Flock::lock(probe, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect_err("lease survives drop");
    assert_eq!(error, nix::errno::Errno::EWOULDBLOCK);
    measure(&session, &shared_storage, &shared_journal, &row, case);
    drop(session);
    drop(
        nix::fcntl::Flock::lock(probe, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect("session drop releases lease"),
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
            std::thread::sleep(std::time::Duration::from_millis(5));
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
    let mut journal =
        journal::Journal::create(beneath(journal_anchor, ".")).expect("journal create");
    let durable = Durability {
        crash_consistent_rename: true,
        durable_sync: true,
    };
    let sender = Endpoint::open_shared_beneath(
        storage,
        row,
        Address::parse("alpha+worker").expect("sender"),
        64021,
        durable,
    )
    .expect("sender endpoint");
    let recipient = Endpoint::open_shared_beneath(
        storage,
        row,
        Address::parse("alpha").expect("recipient"),
        64020,
        durable,
    )
    .expect("recipient endpoint");
    let staging = beneath(storage, "workers/worker/.mail-staging");
    let outgoing = "alpha.01.letter";
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
    File::from(fd).write_all(BODY).expect("source bytes");
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
        if phase == "seed" {
            seed(&home);
        } else {
            assert!(
                ["held", "repair", "journal-mode", "payload"].contains(&phase.as_str()),
                "unsupported fixture phase {phase}"
            );
            child(&home, &phase);
        }
        return;
    }
    for case in ["held", "repair", "journal-mode", "payload"] {
        parent(case);
    }
}

fn argument_checks() {
    for (args, success, text) in [
        (vec!["--list"], true, "reply_session_retains_custody: test"),
        (
            vec!["unrelated-filter"],
            false,
            "reply-custody: unsupported test arguments",
        ),
        (
            vec!["--exact"],
            false,
            "reply-custody: unsupported test arguments",
        ),
    ] {
        let output =
            std::process::Command::new(std::env::current_exe().expect("reply fixture executable"))
                .args(args)
                .env(PHASE, "cleanup")
                .env_remove(HOME)
                .fixture_output("reply argument admission", Duration::from_secs(10))
                .expect("bounded argument probe");
        assert_eq!(output.status.success(), success);
        if !success {
            assert_eq!(output.status.code(), Some(2));
        }
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(report.contains(text), "{report}");
        assert!(!report.contains("reply custody passed"), "{report}");
    }
}

fn main() -> std::process::ExitCode {
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
    if args.len() == 1 && args[0] == "--list" {
        std::io::stdout()
            .write_all(b"reply_session_retains_custody: test\n")
            .expect("list result");
        return std::process::ExitCode::SUCCESS;
    }
    if !args.iter().all(|arg| arg == "--nocapture") {
        let _reported = writeln!(
            std::io::stderr().lock(),
            "reply-custody: unsupported test arguments; use no filter or --list"
        );
        return std::process::ExitCode::from(2);
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
