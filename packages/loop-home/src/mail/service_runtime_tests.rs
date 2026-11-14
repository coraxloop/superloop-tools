//! Service-boundary regressions with real distinct namespace identities.
use super::*;
use crate::mail::directory::bounded;
use crate::mail::{notify, provision};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
const SERVICE: u32 = 65535;
const BODY: &[u8] = b"self-addressed opaque bytes\n";

fn owned(path: &Path, uid: u32, gid: u32, mode: u32) {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .expect("fixture ownership");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}
fn seed(home: &Path) {
    for name in [".config", ".config/loops", ".var", ".var/loops"] {
        fs::create_dir(home.join(name)).expect("fixture directory");
        owned(&home.join(name), 0, 0, 0o711);
    }
    owned(&home.join(".var/loops"), 0, 0, 0o755);
    for (name, uid, group) in [("alpha", 1000, 2000), ("beta", 1001, 2010)] {
        let path = home.join(".var/loops").join(name);
        fs::create_dir(&path).expect("loop home");
        owned(&path, 0, 0, 0o711);
        let root = File::open(&path).expect("loop descriptor");
        provision::tree(&root, "mail", uid, SERVICE, group)
            .expect("production mailbox provisioning");
        provision::directory(&root, ".mail-staging", SERVICE, SERVICE, 0o700).expect("staging");
        for letter in [
            path.join("mail/outbox").join(format!("{name}.self.letter")),
            path.join(".mail-staging/held"),
        ] {
            fs::write(&letter, BODY).expect("actor source");
            owned(&letter, uid, uid, 0o600);
            crate::mail::acl::install(&File::open(&letter).expect("source ACL"), SERVICE, false)
                .expect("service source read grant");
        }
    }
    let config = home.join(".config/loops");
    fs::write(config.join("registry.toml"), "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=1000,launch='dev/alpha'},{name='beta',uid=1001,launch='dev/beta'}]\n").expect("registry");
    fs::write(config.join("allocations.toml"), "mail_uid=65535\n[alpha]\nuids={base=3000,count=1}\nmail_gids={base=2000,count=2}\n[beta]\nuids={base=3010,count=1}\nmail_gids={base=2010,count=2}\n").expect("allocations");
    for name in ["registry.toml", "allocations.toml"] {
        owned(&config.join(name), 0, 0, 0o644);
    }
    provision::directory(
        &File::open(home.join(".var/loops")).expect("loops"),
        ".mail-service",
        SERVICE,
        SERVICE,
        0o700,
    )
    .expect("journal directory");
}
// Keep the parent's disk-backed fixture while making only this child's ancestors
// searchable by the synthetic service identity; no host permissions are changed.
#[allow(unsafe_code)]
fn searchable(home: &Path) {
    use nix::mount::{MsFlags, mount};
    use std::os::fd::AsRawFd as _;
    let mut ancestors: Vec<_> = home.ancestors().skip(1).collect();
    ancestors.reverse();
    let blocked = ancestors.into_iter().find(|path| {
        fs::metadata(path)
            .expect("ancestor metadata")
            .permissions()
            .mode()
            & 0o001
            == 0
    });
    let Some(blocked) = blocked else { return };
    assert_ne!(blocked, Path::new("/"));
    // SAFETY: the fixed mount-namespace flag contains no pointers.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        0,
        "private fixture mounts"
    );
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .expect("private propagation");
    let held = File::open(home).expect("hold fixture before private overlay");
    mount(
        Some("tmpfs"),
        blocked,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755,size=1m"),
    )
    .expect("searchable private ancestors");
    fs::create_dir_all(home).expect("private fixture mountpoint");
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
    .expect("bind original fixture data");
}
fn entered(home: &Path) -> Service {
    assert_eq!(
        nix::unistd::geteuid().as_raw(),
        0,
        "fixture provisioning requires namespace root"
    );
    searchable(home);
    seed(home);
    nix::unistd::setgroups(&[SERVICE, 2000, 2010].map(nix::unistd::Gid::from_raw))
        .expect("service mailbox groups");
    let gid = nix::unistd::Gid::from_raw(SERVICE);
    nix::unistd::setresgid(gid, gid, gid).expect("service gid");
    let uid = nix::unistd::Uid::from_raw(SERVICE);
    nix::unistd::setresuid(uid, uid, uid).expect("service uid");
    Service::new(
        Directory {
            configuration: None,
            home: home.to_owned(),
            service: SERVICE,
            owner: 0,
            durability: publication::Durability {
                crash_consistent_rename: true,
                durable_sync: true,
            },
        },
        Journal::create(File::open(home.join(".var/loops/.mail-service")).expect("journal"))
            .expect("initialize"),
    )
}
fn fixture(case: &str, exercise: fn(&mut Service, &Path)) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    if let Some(phase) = std::env::var_os("LOOP_HOME_SERVICE_TEST_PHASE") {
        let home =
            PathBuf::from(std::env::var_os("LOOP_HOME_SERVICE_TEST_HOME").expect("fixture home"));
        assert!(
            home.parent() == Some(std::env::temp_dir().as_path())
                && home
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("mail-service-test-"))
                && home.join("fixture-marker").is_file()
        );
        if phase == "cleanup" {
            fs::remove_dir_all(home).expect("fixture cleanup");
        } else {
            let subscriber = tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::with_default(subscriber, || exercise(&mut entered(&home), &home));
        }
        return;
    }
    let home = std::env::temp_dir().join(format!(
        "mail-service-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&home).expect("fixture root");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o711)).expect("searchable fixture");
    fs::write(home.join("fixture-marker"), b"synthetic mail service test").expect("marker");
    let invoke = |phase| {
        let mut command = Command::new("/usr/bin/podman");
        command
            .arg("unshare")
            .arg(std::env::current_exe().expect("test image"))
            .args([
                format!("mail::service::runtime_tests::{case}"),
                "--exact".into(),
                "--nocapture".into(),
            ])
            .env("LOOP_HOME_SERVICE_TEST_PHASE", phase)
            .env("LOOP_HOME_SERVICE_TEST_HOME", &home)
            .env_remove("_CONTAINERS_USERNS_CONFIGURED")
            .env_remove("_CONTAINERS_ROOTLESS_UID");
        bounded::output(&mut command, case, Duration::from_secs(90)).expect("bounded fixture child")
    };
    let output = invoke("run");
    let cleanup = invoke("cleanup");
    assert!(
        cleanup.status.success(),
        "cleanup: {}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn delivered(home: &Path, actor: &str, count: usize) {
    for folder in ["inbox", "sent"] {
        let files = fs::read_dir(
            home.join(".var/loops")
                .join(actor)
                .join("mail")
                .join(folder),
        )
        .expect("folder")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("entries");
        assert_eq!(files.len(), count);
        for file in files {
            assert_eq!(fs::read(file.path()).expect("payload"), BODY);
        }
    }
}
/// ´claim:loophome:mail-service-scan-delivers-a-self-addressed-letter´
/// ´test:unit:mail-service-scan-delivers-a-self-addressed-letter´
#[test]
fn mail_service_scan_delivers_a_self_addressed_letter() {
    fixture(
        "mail_service_scan_delivers_a_self_addressed_letter",
        |service, home| {
            assert_eq!(service.scan().expect("scan"), Vec::<String>::new());
            delivered(home, "alpha", 1);
            assert!(
                !home
                    .join(".var/loops/alpha/mail/outbox/alpha.self.letter")
                    .exists()
            );
            assert!(
                service
                    .journal
                    .records()
                    .expect("records")
                    .iter()
                    .all(|record| record.completed.is_some())
            );
        },
    );
}
/// ´claim:loophome:mail-watch-registration-failure-is-local-to-one-mailbox´
/// ´test:unit:mail-watch-registration-failure-is-local-to-one-mailbox´
#[test]
fn mail_watch_registration_failure_is_local_to_one_mailbox() {
    fixture(
        "mail_watch_registration_failure_is_local_to_one_mailbox",
        |service, home| {
            let path = home.join(".var/loops/alpha/mail/outbox");
            notify::ADD_ERROR.with(|error| *error.borrow_mut() = Some((path, libc::EACCES)));
            let mut notifications = notify::Notifications::new();
            let failures = service
                .scan_watching(&mut notifications)
                .expect("other mail continues");
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.starts_with("alpha: notification registration:"))
            );
            delivered(home, "beta", 1);
            assert!(
                home.join(".var/loops/alpha/mail/outbox/alpha.self.letter")
                    .exists()
            );
            assert!(notifications.degraded());
            notify::ADD_ERROR.with(|error| *error.borrow_mut() = None);
            assert_eq!(
                service.scan_watching(&mut notifications).expect("repair"),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 1);
        },
    );
}
/// ´claim:loophome:mail-instance-limit-at-start-keeps-delivering´
/// ´test:unit:mail-instance-limit-at-start-keeps-delivering´
#[test]
fn mail_instance_limit_at_start_keeps_delivering() {
    fixture(
        "mail_instance_limit_at_start_keeps_delivering",
        |service, home| {
            notify::INIT_ERROR.with(|error| error.set(Some(libc::EMFILE)));
            let mut notifications = notify::Notifications::new();
            assert_eq!(
                service
                    .scan_watching(&mut notifications)
                    .expect("polling admission"),
                Vec::<String>::new()
            );
            assert!(notifications.degraded());
            assert!(service.maintenance_wait(&notifications) <= FALLBACK_INTERVAL);
            delivered(home, "alpha", 1);
            delivered(home, "beta", 1);
            service.last_scan = Some(
                Monotonic::now()
                    .checked_sub(FALLBACK_INTERVAL)
                    .expect("elapsed fallback period"),
            );
            assert!(matches!(
                service
                    .wait_for_change(&mut notifications)
                    .expect("periodic fallback wake"),
                Wake::Scan
            ));
            notify::INIT_ERROR.with(|error| error.set(None));
            notifications.begin_scan();
            assert!(!notifications.degraded());
        },
    );
}
/// ´claim:loophome:mail-watch-limit-while-running-falls-back-without-losing-mail´
/// ´test:unit:mail-watch-limit-while-running-falls-back-without-losing-mail´
#[test]
fn mail_watch_limit_while_running_falls_back_without_losing_mail() {
    fixture(
        "mail_watch_limit_while_running_falls_back_without_losing_mail",
        |service, home| {
            let mut notifications = notify::Notifications::new();
            service
                .scan_watching(&mut notifications)
                .expect("initial scan");
            let mailbox = home.join(".var/loops/alpha/mail");
            fs::rename(mailbox.join("inbox"), mailbox.join("sent/old-inbox"))
                .expect("replace watched directory");
            fs::create_dir(mailbox.join("inbox")).expect("new inbox");
            owned(&mailbox.join("inbox"), SERVICE, 2000, 0o770);
            fs::rename(
                home.join(".var/loops/alpha/.mail-staging/held"),
                mailbox.join("outbox/alpha.later.letter"),
            )
            .expect("new arrival");
            notify::ADD_ERROR
                .with(|error| *error.borrow_mut() = Some((mailbox.join("inbox"), libc::ENOSPC)));
            assert_eq!(
                service
                    .scan_watching(&mut notifications)
                    .expect("fallback scan"),
                Vec::<String>::new()
            );
            assert!(notifications.degraded());
            assert!(!mailbox.join("outbox/alpha.later.letter").exists());
            assert_eq!(
                fs::read_dir(mailbox.join("inbox")).expect("inbox").count(),
                1
            );
            notify::ADD_ERROR.with(|error| *error.borrow_mut() = None);
            service
                .scan_watching(&mut notifications)
                .expect("watch restored");
            assert!(!notifications.degraded());
        },
    );
}
/// ´claim:loophome:mail-retry-clock-delivers-only-known-unfinished-letters´
/// ´test:unit:mail-retry-clock-delivers-only-known-unfinished-letters´
#[test]
fn mail_retry_clock_delivers_only_known_unfinished_letters() {
    fixture(
        "mail_retry_clock_delivers_only_known_unfinished_letters",
        |service, home| {
            publication::STOP.with(|stop| stop.set(Some(0)));
            assert_ne!(
                service.scan().expect("post-claim refusal"),
                Vec::<String>::new()
            );
            assert!(
                home.join(".var/loops/alpha/mail/outbox/alpha.self.letter")
                    .exists()
            );
            fs::rename(
                home.join(".var/loops/beta/.mail-staging/held"),
                home.join(".var/loops/beta/mail/outbox/beta.unrelated.letter"),
            )
            .expect("unrelated arrival");
            assert_eq!(
                service.retry_due_at(Monotonic::now() + Duration::from_secs(1)),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 1);
            assert!(
                home.join(".var/loops/beta/mail/outbox/beta.unrelated.letter")
                    .exists(),
                "retry does not discover an unrelated sender's new mail"
            );
            assert!(service.retries.wait(Monotonic::now()).is_none());
        },
    );
}
/// ´claim:loophome:mail-retry-clock-finishes-accepted-publication-without-a-wake´
/// ´test:unit:mail-retry-clock-finishes-accepted-publication-without-a-wake´
#[test]
fn mail_retry_clock_finishes_accepted_publication_without_a_wake() {
    fixture(
        "mail_retry_clock_finishes_accepted_publication_without_a_wake",
        |service, home| {
            publication::STOP.with(|stop| stop.set(Some(5)));
            assert_ne!(
                service.scan().expect("pending publication"),
                Vec::<String>::new()
            );
            assert!(
                service
                    .journal
                    .records()
                    .expect("records")
                    .iter()
                    .any(|record| record.completed.is_none())
            );
            assert_eq!(
                service.retry_due_at(Monotonic::now() + Duration::from_secs(1)),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 1);
            assert!(
                service
                    .journal
                    .records()
                    .expect("records")
                    .iter()
                    .all(|record| record.completed.is_some())
            );
            fs::rename(
                home.join(".var/loops/alpha/.mail-staging/held"),
                home.join(".var/loops/alpha/mail/outbox/alpha.after-acceptance.letter"),
            )
            .expect("second submission");
            publication::STOP.with(|stop| stop.set(Some(17)));
            assert_ne!(
                service.scan().expect("accepted intent remains"),
                Vec::<String>::new()
            );
            assert_eq!(
                publication::pending_preparations(&service.journal)
                    .expect("intent")
                    .len(),
                1
            );
            assert_eq!(
                service.retry_due_at(Monotonic::now() + Duration::from_secs(1)),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 2);
            assert_eq!(
                publication::pending_preparations(&service.journal).expect("reconciled intent"),
                Vec::<(Address, Address, String)>::new()
            );
        },
    );
}
