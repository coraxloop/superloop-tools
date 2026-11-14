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
    fixture_prepared(case, |_| (), |service, home, ()| exercise(service, home));
}
fn fixture_prepared<T>(
    case: &str,
    prepare: impl Fn(&Path) -> T,
    exercise: impl Fn(&mut Service, &Path, T),
) {
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
        if phase == "repair" {
            repair_loop(&home);
        } else if phase == "cleanup" {
            fs::remove_dir_all(home).expect("fixture cleanup");
        } else {
            let subscriber = tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(
                    if case == "mail_hourly_refusals_use_bounded_letter_deadlines" {
                        tracing::Level::ERROR
                    } else {
                        tracing::Level::DEBUG
                    },
                )
                .finish();
            let prepared = prepare(&home);
            tracing::subscriber::with_default(subscriber, || {
                exercise(&mut entered(&home), &home, prepared);
            });
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
            delivered(home, "beta", 1);
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
            service.last_full_scan = Some(
                Monotonic::now()
                    .checked_sub(FALLBACK_INTERVAL)
                    .expect("elapsed fallback period"),
            );
            service.last_scan = Some(Monotonic::now());
            assert_eq!(service.maintenance_wait(&notifications), Duration::ZERO);
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

struct ControlledClock {
    base: Monotonic,
    seconds: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl Clock for ControlledClock {
    fn now(&mut self) -> Result<Instant> {
        Instant::now()
    }
    fn wait(&mut self) {
        std::thread::sleep(Duration::from_millis(1));
    }
    fn monotonic(&self) -> Monotonic {
        self.base + Duration::from_secs(self.seconds.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// ´claim:loophome:mail-refusal-identity-gates-scans-until-change-or-deadline´
/// ´test:unit:mail-refusal-identity-gates-scans-until-change-or-deadline´
#[test]
fn mail_refusal_identity_gates_scans_until_change_or_deadline() {
    fixture(
        "mail_refusal_identity_gates_scans_until_change_or_deadline",
        |service, home| {
            let seconds = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: Monotonic::now(),
                seconds: seconds.clone(),
            });
            fs::remove_file(home.join(".var/loops/beta/mail/outbox/beta.self.letter"))
                .expect("one source");
            let records = home.join(".var/loops/.mail-service/deliveries");
            fs::set_permissions(&records, fs::Permissions::from_mode(0o500))
                .expect("persistent post-claim failure");
            let source = home.join(".var/loops/alpha/mail/outbox/alpha.self.letter");
            let original = source.metadata().expect("original identity").ino();
            for second in 0..=60 {
                seconds.store(second, std::sync::atomic::Ordering::Relaxed);
                if second == 3 || second == 15 {
                    assert_eq!(
                        service.retry_due().len(),
                        1,
                        "timer retries without an event"
                    );
                }
                service.scan().expect("scan with a refused candidate");
                assert_eq!(
                    service.retry_due(),
                    Vec::<String>::new(),
                    "scan consumes its due source deadline"
                );
            }
            assert_eq!(
                service.attempts, 6,
                "attempts only at 0, 1, 3, 7, 15 and 31 seconds"
            );
            assert_eq!(source.metadata().expect("restored source").ino(), original);
            let before = service.attempts;
            let mut notifications = notify::Notifications::new();
            notifications.invalidate_configuration();
            service.configuration_changed(&notifications);
            service.scan().expect("configuration wake");
            assert_eq!(
                service.attempts,
                before + 1,
                "configuration retries unchanged source"
            );
            let replacement = source.with_file_name("replacement");
            fs::copy(&source, &replacement).expect("new inode with equal size");
            fs::rename(&replacement, &source).expect("replace source");
            service.scan().expect("inode change");
            assert_eq!(
                service.attempts,
                before + 2,
                "replacement retries without waiting"
            );
            fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .expect("fixture-owned replacement")
                .write_all(b"longer")
                .expect("size change");
            service.scan().expect("size change");
            assert_eq!(
                service.attempts,
                before + 3,
                "same inode with new size retries"
            );
            service.scan().expect("unchanged permanent refusal");
            assert_eq!(service.attempts, before + 3);
        },
    );
}

/// ´claim:loophome:mail-refusal-timer-drops-a-source-that-becomes-permanent´
/// ´test:unit:mail-refusal-timer-drops-a-source-that-becomes-permanent´
#[test]
fn mail_refusal_timer_drops_a_source_that_becomes_permanent() {
    fixture(
        "mail_refusal_timer_drops_a_source_that_becomes_permanent",
        |service, home| {
            let sender = Address::parse("alpha").expect("sender");
            let name = OsStr::new("malformed");
            let source = home.join(".var/loops/alpha/mail/outbox/malformed");
            fs::write(&source, b"invalid fixture source").expect("source");
            let base = Monotonic::now();
            service.clock = Box::new(ControlledClock {
                base,
                seconds: std::sync::Arc::new(AtomicU64::new(0)),
            });
            service
                .retries
                .schedule((sender.clone(), name.to_owned()), retry::Work::Source, base);
            assert_eq!(service.retry_due_at(base + Duration::from_secs(1)).len(), 1);
            assert_eq!(
                service.retries.wait(base + Duration::from_secs(100)),
                Some(Duration::from_secs(3500))
            );
            assert!(!service.source_ready(&sender, name, base + Duration::from_secs(100)));
        },
    );
}

/// ´claim:loophome:mail-selected-scan-leaves-unrelated-outboxes-queued´
/// ´test:unit:mail-selected-scan-leaves-unrelated-outboxes-queued´
#[test]
fn mail_selected_scan_leaves_unrelated_outboxes_queued() {
    fixture(
        "mail_selected_scan_leaves_unrelated_outboxes_queued",
        |service, home| {
            for name in ["alpha", "beta"] {
                let base = home.join(".var/loops").join(name);
                fs::rename(
                    base.join(format!("mail/outbox/{name}.self.letter")),
                    base.join(".mail-staging/selected-held"),
                )
                .expect("hold until startup ends");
            }
            let mut notifications = notify::Notifications::new();
            service
                .scan_watching(&mut notifications)
                .expect("empty startup");
            for name in ["alpha", "beta"] {
                let base = home.join(".var/loops").join(name);
                fs::rename(
                    base.join(".mail-staging/selected-held"),
                    base.join(format!("mail/outbox/{name}.self.letter")),
                )
                .expect("arrive after startup");
            }
            super::super::journal::RECORD_SCANS.with(|count| count.set(0));
            assert_eq!(
                service
                    .scan_selected(
                        &mut notifications,
                        [Address::parse("alpha").expect("sender")].into()
                    )
                    .expect("selected scan"),
                Vec::<String>::new()
            );
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                2,
                "admission retention and preparation checks read history"
            );
            delivered(home, "alpha", 1);
            delivered(home, "beta", 0);
            assert!(
                home.join(".var/loops/beta/mail/outbox/beta.self.letter")
                    .exists()
            );
            let seconds = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let now = Monotonic::now();
            service.clock = Box::new(ControlledClock {
                base: now,
                seconds: seconds.clone(),
            });
            service.retries.schedule(
                (
                    Address::parse("beta").expect("pending sender"),
                    "beta.self.letter".into(),
                ),
                retry::Work::Source,
                now,
            );
            assert_eq!(
                service
                    .scan_selected(
                        &mut notifications,
                        [Address::parse("alpha").expect("event sender")].into()
                    )
                    .expect("known retry sender"),
                Vec::<String>::new()
            );
            delivered(home, "beta", 0);
            seconds.store(1, Ordering::Relaxed);
            service
                .scan_selected(&mut notifications, BTreeSet::new())
                .expect("due sender");
            delivered(home, "beta", 1);
        },
    );
}

/// ´claim:loophome:mail-selected-scan-includes-known-work-in-round-robin-order´
/// ´test:unit:mail-selected-scan-includes-known-work-in-round-robin-order´
#[test]
fn mail_selected_scan_includes_known_work_in_round_robin_order() {
    fixture(
        "mail_selected_scan_includes_known_work_in_round_robin_order",
        |service, home| {
            for name in ["alpha", "beta"] {
                let base = home.join(".var/loops").join(name);
                fs::rename(
                    base.join(format!("mail/outbox/{name}.self.letter")),
                    base.join(".mail-staging/second"),
                )
                .expect("hold source");
            }
            let malformed = home.join(".var/loops/beta/mail/outbox/alpha.zz.letter");
            fs::write(&malformed, b"permanent refusal").expect("source");
            let mut notifications = notify::Notifications::new();
            service
                .scan_watching(&mut notifications)
                .expect("initial refusal");
            let before = service.attempts;
            for name in ["alpha", "beta"] {
                let base = home.join(".var/loops").join(name);
                fs::rename(
                    base.join(".mail-staging/held"),
                    base.join("mail/outbox/beta.01.letter"),
                )
                .expect("first slug");
                fs::rename(
                    base.join(".mail-staging/second"),
                    base.join("mail/outbox/alpha.02.letter"),
                )
                .expect("second slug");
            }
            let now = Monotonic::now();
            let seconds = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: now,
                seconds: seconds.clone(),
            });
            service
                .scan_selected(&mut notifications, BTreeSet::new())
                .expect("no due work");
            assert_eq!(
                service.attempts, before,
                "a permanent refusal does not select its sender"
            );
            service.retries.schedule(
                (
                    Address::parse("beta").expect("sender"),
                    "beta.01.letter".into(),
                ),
                retry::Work::Source,
                now,
            );
            seconds.store(1, Ordering::Relaxed);
            assert_eq!(
                service
                    .scan_selected(
                        &mut notifications,
                        [Address::parse("alpha").expect("sender")].into()
                    )
                    .expect("selected known work"),
                Vec::<String>::new()
            );
            assert_eq!(
                service.attempts,
                before + 4,
                "unchanged refusal is not reattempted"
            );
            let records = service.journal.records().expect("records");
            let order = records
                .iter()
                .map(|record| (record.sender.as_str(), record.outgoing.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(
                order,
                [
                    ("alpha", "beta.01.letter"),
                    ("beta", "beta.01.letter"),
                    ("alpha", "alpha.02.letter"),
                    ("beta", "alpha.02.letter")
                ]
            );
            delivered(home, "alpha", 2);
            delivered(home, "beta", 2);
        },
    );
}

/// ´claim:loophome:mail-retention-clock-does-not-enumerate-outbox-work´
/// ´test:unit:mail-retention-clock-does-not-enumerate-outbox-work´
#[test]
fn mail_retention_clock_does_not_enumerate_outbox_work() {
    fixture(
        "mail_retention_clock_does_not_enumerate_outbox_work",
        |service, home| {
            let mut notifications = notify::Notifications::new();
            let mut inventory = service.directory.inventory().expect("endpoints");
            service.watch_inventory(&mut notifications, &mut inventory, None);
            service.configuration_changed(&notifications);
            drop(inventory);
            notifications.invalidate_configuration();
            service.last_maintenance = Some(
                Monotonic::now()
                    .checked_sub(Duration::from_secs(PRUNE_INTERVAL_SECONDS))
                    .expect("elapsed maintenance"),
            );
            service.last_prune = Some(Monotonic::now());
            assert_eq!(
                service.maintenance_wait(&notifications),
                Duration::ZERO,
                "admission pruning cannot postpone watch repair"
            );
            super::super::journal::RECORD_SCANS.with(|count| count.set(0));
            service.maintain(&mut notifications).expect("retention");
            assert_eq!(service.attempts, 0);
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                1
            );
            assert!(
                home.join(".var/loops/alpha/mail/outbox/alpha.self.letter")
                    .exists()
            );
            assert!(!service.maintenance_due());
            service.last_maintenance = Some(
                Monotonic::now()
                    .checked_sub(Duration::from_secs(PRUNE_INTERVAL_SECONDS))
                    .expect("elapsed maintenance again"),
            );
            service
                .scan_selected(&mut notifications, BTreeSet::new())
                .expect("events cannot postpone maintenance");
            assert_eq!(service.attempts, 0);
            assert!(!service.maintenance_due());
            assert!(matches!(
                notifications
                    .wait(Duration::ZERO)
                    .expect("new endpoints reconcile")
                    .as_slice(),
                [notify::Change::Reconcile]
            ));
        },
    );
}

/// ´claim:loophome:mail-withdrawn-refusal-cleans-only-its-known-key´
/// ´test:unit:mail-withdrawn-refusal-cleans-only-its-known-key´
#[test]
fn mail_withdrawn_refusal_cleans_only_its_known_key() {
    fixture(
        "mail_withdrawn_refusal_cleans_only_its_known_key",
        |service, home| {
            let sender = Address::parse("alpha").expect("sender");
            let name = OsStr::new("malformed");
            let outbox = home.join(".var/loops/alpha/mail/outbox");
            fs::write(outbox.join(name), b"refused").expect("source");
            service.scan().expect("initial recovery and refusal");
            let sidecars = fs::read_dir(&outbox)
                .expect("outbox")
                .map(|entry| entry.expect("entry").path())
                .filter(|path| path.file_name() != Some(name))
                .collect::<Vec<_>>();
            assert_eq!(sidecars.len(), 1);
            fs::remove_file(outbox.join(name)).expect("withdraw source");
            assert!(service.source_ready(&sender, name, Monotonic::now()));
            super::super::journal::RECORD_SCANS.with(|count| count.set(0));
            assert_eq!(
                service.retry_due_at(Monotonic::now() + Duration::from_secs(2)),
                Vec::<String>::new()
            );
            assert!(!sidecars[0].exists());
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                0,
                "exact-key cleanup needs no history scan"
            );
            assert_eq!(service.retries.wait(Monotonic::now()), None);
            fs::write(outbox.join(name), b"another refusal").expect("source");
            service.scan().expect("refusal observed");
            assert!(
                service
                    .refused
                    .contains_key(&(sender.clone(), name.to_owned()))
            );
            fs::remove_file(outbox.join(name)).expect("withdraw without an event");
            service.scan().expect("fallback reconciliation");
            assert!(!service.refused.contains_key(&(sender, name.to_owned())));
        },
    );
}

/// ´claim:loophome:mail-event-batch-selects-all-senders-without-inbox-reconciliation´
/// ´test:unit:mail-event-batch-selects-all-senders-without-inbox-reconciliation´
#[test]
fn mail_event_batch_selects_all_senders_without_inbox_reconciliation() {
    fixture(
        "mail_event_batch_selects_all_senders_without_inbox_reconciliation",
        |service, home| {
            let mut notifications = notify::Notifications::new();
            service.scan_watching(&mut notifications).expect("startup");
            for name in ["alpha", "beta"] {
                let base = home.join(".var/loops").join(name);
                fs::rename(
                    base.join(".mail-staging/held"),
                    base.join(format!("mail/outbox/{name}.next.letter")),
                )
                .expect("arrive before reading events");
            }
            let Wake::Senders(selected) = service
                .wait_for_change(&mut notifications)
                .expect("event batch")
            else {
                panic!("inbox content or absent successful sources forced reconciliation");
            };
            assert_eq!(
                selected,
                [
                    Address::parse("alpha").expect("alpha"),
                    Address::parse("beta").expect("beta")
                ]
                .into()
            );
            service
                .scan_selected(&mut notifications, selected)
                .expect("selected delivery");
            delivered(home, "alpha", 2);
            delivered(home, "beta", 2);
        },
    );
}

/// ´claim:loophome:mail-claimed-retry-survives-unavailable-refusal-history´
/// ´test:unit:mail-claimed-retry-survives-unavailable-refusal-history´
#[test]
fn mail_claimed_retry_survives_unavailable_refusal_history() {
    fixture(
        "mail_claimed_retry_survives_unavailable_refusal_history",
        |service, home| {
            let seconds = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: Monotonic::now(),
                seconds: seconds.clone(),
            });
            let mut notifications = notify::Notifications::new();
            let senders = BTreeSet::from([Address::parse("alpha").expect("sender")]);
            publication::STOP.with(|stop| stop.set(Some(17)));
            REFUSAL_HISTORY_FAILURE.with(|failure| failure.set(true));
            assert_eq!(
                service
                    .scan_selected(&mut notifications, senders.clone())
                    .expect("accepted classification failure")
                    .len(),
                1
            );
            assert!(
                service
                    .journal
                    .records()
                    .expect("accepted")
                    .iter()
                    .any(|record| record.completed.is_none())
            );
            seconds.store(1, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                service
                    .scan_selected(&mut notifications, BTreeSet::new())
                    .expect("events also advance due claimed work"),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 1);
            assert_eq!(
                service.attempts, 1,
                "accepted work finishes without another claim"
            );
            assert!(
                !service.refused.contains_key(&(
                    Address::parse("alpha").expect("sender"),
                    "alpha.self.letter".into()
                )),
                "completed work must not select its sender"
            );
            let base = home.join(".var/loops/alpha");
            fs::rename(
                base.join(".mail-staging/held"),
                base.join("mail/outbox/alpha.unaccepted.letter"),
            )
            .expect("new source");
            let records = home.join(".var/loops/.mail-service/deliveries");
            fs::set_permissions(&records, fs::Permissions::from_mode(0o500))
                .expect("post-claim failure");
            REFUSAL_HISTORY_FAILURE.with(|failure| failure.set(true));
            assert_eq!(
                service
                    .scan_selected(&mut notifications, senders)
                    .expect("unaccepted classification failure")
                    .len(),
                1
            );
            fs::set_permissions(&records, fs::Permissions::from_mode(0o700))
                .expect("repair fixture journal");
            seconds.store(2, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                service
                    .scan_selected(&mut notifications, BTreeSet::new())
                    .expect("events also advance due claimed work"),
                Vec::<String>::new()
            );
            delivered(home, "alpha", 2);
            assert_eq!(service.journal.records().expect("records").len(), 2);
            assert_eq!(service.retries.wait(Monotonic::now()), None);
            assert!(
                home.join(".var/loops/beta/mail/outbox/beta.self.letter")
                    .exists()
            );
        },
    );
}

struct Repairer {
    child: std::process::Child,
    output: std::io::BufReader<std::process::ChildStdout>,
}
impl Repairer {
    fn new(case: &str, home: &Path) -> Self {
        let mut child = Command::new(std::env::current_exe().expect("test image"))
            .args([
                format!("mail::service::runtime_tests::{case}"),
                "--exact".into(),
                "--nocapture".into(),
            ])
            .env("LOOP_HOME_SERVICE_TEST_PHASE", "repair")
            .env("LOOP_HOME_SERVICE_TEST_HOME", home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("namespace-root fixture repairer");
        let output = std::io::BufReader::new(child.stdout.take().expect("repair replies"));
        let mut result = Self { child, output };
        result.reply("REPAIR-READY");
        result
    }
    fn reply(&mut self, expected: &str) {
        use std::io::BufRead as _;
        loop {
            let mut line = String::new();
            assert_ne!(
                self.output.read_line(&mut line).expect("repair reply"),
                0,
                "repairer exited"
            );
            if line.trim() == expected {
                break;
            }
        }
    }
    fn change(&mut self, action: &str) {
        writeln!(
            self.child.stdin.as_mut().expect("repair channel"),
            "{action}"
        )
        .expect("repair request");
        self.reply("REPAIR-DONE");
    }
}
impl Drop for Repairer {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _status = self.child.wait();
    }
}
fn worker_collision(home: &Path) {
    let base = home.join(".var/loops/beta");
    fs::create_dir(base.join("workers")).expect("workers");
    owned(&base.join("workers"), 0, 0, 0o755);
    let worker = base.join("workers/collision");
    fs::create_dir(&worker).expect("worker home");
    owned(&worker, 0, 0, 0o711);
    let descriptor = File::open(&worker).expect("worker descriptor");
    provision::tree(&descriptor, "mail", 1000, SERVICE, 2011).expect("colliding worker mailbox");
    provision::directory(&descriptor, ".mail-staging", SERVICE, SERVICE, 0o700)
        .expect("worker staging");
    let source = worker.join("mail/outbox/beta.collision.letter");
    fs::write(&source, BODY).expect("worker letter");
    owned(&source, 1000, 1000, 0o600);
    crate::mail::acl::install(&File::open(&source).expect("source"), SERVICE, false)
        .expect("read grant");
    for component in ["private", "private/.config", "private/.config/mail"] {
        let path = base.join(component);
        fs::create_dir(&path).expect("configuration ancestor");
        owned(&path, 1001, 1001, 0o700);
        crate::mail::acl::install(&File::open(&path).expect("ancestor"), SERVICE, true)
            .expect("search grant");
    }
    let config = base.join("private/.config/mail/loop.toml");
    fs::write(
        &config,
        "workers=[{name='collision',state='active'}]\n[mail]\nversion=1\nallow=[]\n",
    )
    .expect("worker registration");
    owned(&config, 1001, 1001, 0o600);
    crate::mail::acl::install(&File::open(&config).expect("configuration"), SERVICE, false)
        .expect("configuration grant");
    let allocations = home.join(".config/loops/allocations.toml");
    let text = fs::read_to_string(&allocations)
        .expect("allocations")
        .replace("base=3010", "base=1000");
    fs::write(allocations, text).expect("colliding actor reservation");
}
fn replace_outbox(home: &Path) {
    let mailbox = home.join(".var/loops/alpha/mail");
    fs::rename(mailbox.join("outbox"), home.join("held-outbox")).expect("retain old inode");
    let (outbox, _) = provision::directory(
        &File::open(&mailbox).expect("mailbox"),
        "outbox",
        1000,
        1000,
        0o700,
    )
    .expect("replacement");
    crate::mail::acl::grant_outbox(&outbox, SERVICE).expect("replacement ACL");
}
fn repair_loop(home: &Path) {
    use std::io::BufRead as _;
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    let path = home.join(".var/loops/alpha/mail/outbox/alpha.self.letter");
    let alias = home.join("repair-alias");
    let mut output = std::io::stdout().lock();
    writeln!(output, "REPAIR-READY").expect("ready");
    output.flush().expect("flush");
    for action in std::io::stdin().lock().lines() {
        match action.expect("action").as_str() {
            "worker-collision" => worker_collision(home),
            "reassign-beta" => {
                let mailbox = home.join(".var/loops/beta/mail");
                for name in ["draft", "read", "outbox"] {
                    owned(&mailbox.join(name), 1002, 1002, 0o700);
                }
                crate::mail::acl::grant_outbox(
                    &File::open(mailbox.join("outbox")).expect("outbox"),
                    SERVICE,
                )
                .expect("service grant");
                let registry = home.join(".config/loops/registry.toml");
                let text = fs::read_to_string(&registry)
                    .expect("registry")
                    .replace("name='beta',uid=1001", "name='beta',uid=1002");
                fs::write(registry, text).expect("new beta identity");
            }
            "replace-outbox" => replace_outbox(home),
            "reset" => {
                fs::remove_file(&path).expect("old source");
                fs::write(&path, BODY).expect("plain source");
                owned(&path, 1001, 2000, 0o640);
                File::open(&path)
                    .expect("source")
                    .set_times(
                        std::fs::FileTimes::new()
                            .set_modified(std::time::UNIX_EPOCH + Duration::new(100, 42)),
                    )
                    .expect("fixed timestamp");
            }
            "owner" => nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(1000)), None)
                .expect("owner repair"),
            "alias" => fs::hard_link(&path, &alias).expect("alias"),
            "unlink" => fs::remove_file(&alias).expect("alias removal"),
            "bad-group" => nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(0)))
                .expect("wrong group"),
            "group" => nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(2000)))
                .expect("group repair"),
            "bad-mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).expect("unreadable");
            }
            "mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode repair");
            }
            "rewrite" => {
                fs::write(&path, vec![b'x'; BODY.len()]).expect("same-size rewrite");
                File::open(&path)
                    .expect("source")
                    .set_times(
                        std::fs::FileTimes::new()
                            .set_modified(std::time::UNIX_EPOCH + Duration::new(100, 43)),
                    )
                    .expect("nanoseconds only");
            }
            "seconds" => File::open(&path)
                .expect("source")
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + Duration::new(101, 42)),
                )
                .expect("seconds only"),
            "withdraw" => {
                fs::rename(&path, &alias).expect("withdraw");
                fs::rename(&alias, &path).expect("resubmit same inode and name");
            }
            other => panic!("unknown fixture action: {other}"),
        }
        writeln!(output, "REPAIR-DONE").expect("done");
        output.flush().expect("flush");
    }
}
fn repaired_source(case: &str, repair: &str) {
    fixture_prepared(
        case,
        |home| Repairer::new(case, home),
        |service, home, mut root| {
            let seconds = std::sync::Arc::new(AtomicU64::new(0));
            let base = Monotonic::now();
            service.clock = Box::new(ControlledClock {
                base,
                seconds: seconds.clone(),
            });
            service.last_maintenance = Some(base);
            fs::remove_file(home.join(".var/loops/beta/mail/outbox/beta.self.letter"))
                .expect("only tested source");
            root.change("reset");
            if matches!(repair, "unlink" | "group" | "mode") {
                root.change("owner");
            }
            match repair {
                "unlink" => root.change("alias"),
                "group" => root.change("bad-group"),
                "mode" => root.change("bad-mode"),
                _ => {}
            }
            assert_eq!(service.scan().expect("initial refusal").len(), 1);
            assert_eq!(service.attempts, 1);
            service.scan().expect("unchanged refusal");
            assert_eq!(service.attempts, 1);
            let sender = Address::parse("alpha").expect("sender");
            let name = OsStr::new("alpha.self.letter");
            let before = service
                .source_identity(&sender, name)
                .expect("observed source");
            root.change(repair);
            let after = service
                .source_identity(&sender, name)
                .expect("repaired source");
            assert_eq!(
                (before.device, before.inode, before.size),
                (after.device, after.inode, after.size)
            );
            if repair == "withdraw" {
                assert_eq!(
                    before, after,
                    "rename alone leaves the observation unchanged"
                );
                seconds.store(3599, Ordering::Relaxed);
                service.scan().expect("before hourly sweep");
                assert_eq!(service.attempts, 1);
                assert!(!service.maintenance_due());
                seconds.store(3600, Ordering::Relaxed);
                assert!(service.maintenance_due());
                service
                    .maintain(&mut notify::Notifications::new())
                    .expect("hourly reconsideration");
            } else {
                service.scan().expect("repair without elapsed clock");
            }
            assert_eq!(
                service.attempts, 2,
                "repair or hourly reconsideration admits exactly one attempt"
            );
            service.scan().expect("no repeated attempt");
            assert_eq!(service.attempts, 2);
            if matches!(repair, "unlink" | "owner" | "group" | "mode") {
                delivered(home, "alpha", 1);
            }
        },
    );
}

/// ´claim:loophome:mail-refusal-observes-alias-removal´
/// ´test:unit:mail-refusal-observes-alias-removal´
#[test]
fn mail_refusal_observes_alias_removal() {
    repaired_source("mail_refusal_observes_alias_removal", "unlink");
}

/// ´claim:loophome:mail-refusal-observes-owner-repair´
/// ´test:unit:mail-refusal-observes-owner-repair´
#[test]
fn mail_refusal_observes_owner_repair() {
    repaired_source("mail_refusal_observes_owner_repair", "owner");
}

/// ´claim:loophome:mail-refusal-observes-group-repair´
/// ´test:unit:mail-refusal-observes-group-repair´
#[test]
fn mail_refusal_observes_group_repair() {
    repaired_source("mail_refusal_observes_group_repair", "group");
}

/// ´claim:loophome:mail-refusal-observes-mode-repair´
/// ´test:unit:mail-refusal-observes-mode-repair´
#[test]
fn mail_refusal_observes_mode_repair() {
    repaired_source("mail_refusal_observes_mode_repair", "mode");
}

/// ´claim:loophome:mail-refusal-observes-same-size-rewrite´
/// ´test:unit:mail-refusal-observes-same-size-rewrite´
#[test]
fn mail_refusal_observes_same_size_rewrite() {
    repaired_source("mail_refusal_observes_same_size_rewrite", "rewrite");
}

/// ´claim:loophome:mail-refusal-observes-mtime-seconds´
/// ´test:unit:mail-refusal-observes-mtime-seconds´
#[test]
fn mail_refusal_observes_mtime_seconds() {
    repaired_source("mail_refusal_observes_mtime_seconds", "seconds");
}

/// ´claim:loophome:mail-refusal-observes-same-batch-resubmission´
/// ´test:unit:mail-refusal-observes-same-batch-resubmission´
#[test]
fn mail_refusal_observes_same_batch_resubmission() {
    repaired_source("mail_refusal_observes_same_batch_resubmission", "withdraw");
}

/// ´claim:loophome:mail-targeted-resolution-does-not-discover-unrelated-mailboxes´
/// ´test:unit:mail-targeted-resolution-does-not-discover-unrelated-mailboxes´
#[test]
fn mail_targeted_resolution_does_not_discover_unrelated_mailboxes() {
    fixture(
        "mail_targeted_resolution_does_not_discover_unrelated_mailboxes",
        |service, _home| {
            let alpha = Address::parse("alpha").expect("sender");
            io::NAME_SCANS.with(|count| count.set(0));
            let empty = service
                .directory
                .resolve(&BTreeSet::new())
                .expect("empty selection");
            assert!(empty.actors.is_empty());
            assert_eq!(io::NAME_SCANS.with(std::cell::Cell::get), 0);
            let selected = service
                .directory
                .resolve(&BTreeSet::from([alpha.clone()]))
                .expect("one target");
            assert_eq!(selected.actors.keys().collect::<Vec<_>>(), vec![&alpha]);
            // Exactly the selected mailbox's five fixed folder names, no workers or letter folders.
            assert_eq!(io::NAME_SCANS.with(std::cell::Cell::get), 1);
            let accounting = service
                .directory
                .inventory()
                .expect("global accounting remains separate");
            assert_eq!(accounting.actors.len(), 2);
            admitted_actor(&selected, &accounting, &alpha).expect("same pinned endpoint");
        },
    );
}

/// ´claim:loophome:mail-targeted-admission-retains-global-identity-exclusions´
/// ´test:unit:mail-targeted-admission-retains-global-identity-exclusions´
#[test]
fn mail_targeted_admission_retains_global_identity_exclusions() {
    fixture_prepared(
        "mail_targeted_admission_retains_global_identity_exclusions",
        |home| {
            Repairer::new(
                "mail_targeted_admission_retains_global_identity_exclusions",
                home,
            )
        },
        |service, home, mut root| {
            root.change("worker-collision");
            io::NAME_SCANS.with(|count| count.set(0));
            let principal = service
                .directory
                .resolve(&BTreeSet::from(
                    [Address::parse("beta").expect("principal")],
                ))
                .expect("principal only");
            assert_eq!(
                principal.actors.len(),
                1,
                "sibling workers are not resolved"
            );
            assert_eq!(
                io::NAME_SCANS.with(std::cell::Cell::get),
                1,
                "no workers-directory census for a principal"
            );

            let sender = Address::parse("beta+collision").expect("worker");
            let local = service
                .directory
                .resolve(&BTreeSet::from([sender.clone()]))
                .expect("target custody");
            assert!(
                local.actors.contains_key(&sender),
                "local custody alone cannot establish global uniqueness"
            );
            let accounting = service
                .directory
                .inventory()
                .expect("global identity admission");
            assert!(!accounting.actors.contains_key(&sender));
            let error = service
                .candidate(&sender, OsStr::new("beta.collision.letter"))
                .expect_err("collision must refuse before reading or claiming source");
            assert!(
                error
                    .to_string()
                    .contains("unavailable endpoint beta+collision"),
                "{error}"
            );
            assert!(
                home.join(".var/loops/beta/workers/collision/mail/outbox/beta.collision.letter")
                    .is_file()
            );
            assert!(
                !home
                    .join(".var/loops/beta/workers/collision/.mail-staging/beta.collision.letter")
                    .exists()
            );
            assert_eq!(service.journal.records().expect("no acceptance").len(), 0);
        },
    );
}

/// ´claim:loophome:mail-targeted-admission-detects-replacement-between-views´
/// ´test:unit:mail-targeted-admission-detects-replacement-between-views´
#[test]
fn mail_targeted_admission_detects_replacement_between_views() {
    fixture_prepared(
        "mail_targeted_admission_detects_replacement_between_views",
        |home| {
            Repairer::new(
                "mail_targeted_admission_detects_replacement_between_views",
                home,
            )
        },
        |service, _home, mut root| {
            let address = Address::parse("alpha").expect("sender");
            let targets = service
                .directory
                .resolve(&BTreeSet::from([address.clone()]))
                .expect("held target");
            root.change("replace-outbox");
            let accounting = service.directory.inventory().expect("fresh census");
            let error = admitted_actor(&targets, &accounting, &address)
                .err()
                .expect("replacement refuses");
            assert!(
                error
                    .to_string()
                    .contains("changed-source: endpoint replaced during admission"),
                "{error}"
            );
        },
    );
}

/// ´claim:loophome:mail-targeted-admission-rechecks-actor-policy´
/// ´test:unit:mail-targeted-admission-rechecks-actor-policy´
#[test]
fn mail_targeted_admission_rechecks_actor_policy() {
    fixture_prepared(
        "mail_targeted_admission_rechecks_actor_policy",
        |home| Repairer::new("mail_targeted_admission_rechecks_actor_policy", home),
        |service, _home, mut root| {
            let address = Address::parse("beta").expect("sender");
            let targets = service
                .directory
                .resolve(&BTreeSet::from([address.clone()]))
                .expect("held target");
            root.change("reassign-beta");
            let accounting = service
                .directory
                .inventory()
                .expect("fresh custody after identity change");
            let held = targets.actors[&address]
                .outbox
                .metadata()
                .expect("held outbox");
            let current = accounting.actors[&address]
                .outbox
                .metadata()
                .expect("current outbox");
            assert_eq!(
                (held.dev(), held.ino()),
                (current.dev(), current.ino()),
                "the inode did not change"
            );
            let error = admitted_actor(&targets, &accounting, &address)
                .err()
                .expect("actor change refuses");
            assert!(
                error
                    .to_string()
                    .contains("changed-source: endpoint admission changed"),
                "{error}"
            );
        },
    );
}

/// ´claim:loophome:mail-full-scans-do-not-postpone-refusal-reconsideration´
/// ´test:unit:mail-full-scans-do-not-postpone-refusal-reconsideration´
#[test]
fn mail_full_scans_do_not_postpone_refusal_reconsideration() {
    fixture_prepared(
        "mail_full_scans_do_not_postpone_refusal_reconsideration",
        |home| {
            Repairer::new(
                "mail_full_scans_do_not_postpone_refusal_reconsideration",
                home,
            )
        },
        |service, home, mut root| {
            let seconds = std::sync::Arc::new(AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: Monotonic::now(),
                seconds: seconds.clone(),
            });
            fs::remove_file(home.join(".var/loops/beta/mail/outbox/beta.self.letter"))
                .expect("only tested source");
            root.change("reset");
            let mut notifications = notify::Notifications::new();
            service
                .scan_watching(&mut notifications)
                .expect("initial refusal");
            assert_eq!(service.attempts, 1);
            root.change("withdraw");
            for second in [
                300, 600, 900, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300, 3599,
            ] {
                seconds.store(second, Ordering::Relaxed);
                service
                    .scan_watching(&mut notifications)
                    .expect("full fallback or invalidation scan");
                assert_eq!(
                    service.attempts, 1,
                    "a full scan before the deadline does not retry unchanged refusals"
                );
            }
            seconds.store(3600, Ordering::Relaxed);
            service
                .scan_watching(&mut notifications)
                .expect("full scan at the hourly deadline");
            assert_eq!(
                service.attempts, 2,
                "full scans cannot keep postponing an invisible resubmission"
            );
            service
                .scan_watching(&mut notifications)
                .expect("same clock after the sweep");
            assert_eq!(service.attempts, 2, "one reconsideration per interval");
        },
    );
}

/// ´claim:loophome:mail-hourly-refusals-use-bounded-letter-deadlines´
/// ´test:unit:mail-hourly-refusals-use-bounded-letter-deadlines´
#[test]
fn mail_hourly_refusals_use_bounded_letter_deadlines() {
    fixture(
        "mail_hourly_refusals_use_bounded_letter_deadlines",
        |service, home| {
            let seconds = std::sync::Arc::new(AtomicU64::new(0));
            let base = Monotonic::now();
            service.clock = Box::new(ControlledClock {
                base,
                seconds: seconds.clone(),
            });
            let mut notifications = notify::Notifications::new();
            service
                .scan_watching(&mut notifications)
                .expect("initial deliveries");
            let outbox = home.join(".var/loops/alpha/mail/outbox");
            for n in 0..130 {
                fs::write(outbox.join(format!("invalid-{n:03}")), b"refused").expect("source");
            }
            service.scan().expect("record refusals");
            let initial = service.attempts;
            seconds.store(3599, Ordering::Relaxed);
            assert_eq!(service.retry_due(), Vec::<String>::new());
            assert_eq!(service.attempts, initial);
            for hour in 1..=3 {
                let initial = service.attempts;
                seconds.store(hour * 3600, Ordering::Relaxed);
                match hour {
                    1 => {
                        service
                            .scan_watching(&mut notifications)
                            .expect("full scan drains one batch");
                    }
                    2 => {
                        service
                            .scan_selected(&mut notifications, BTreeSet::new())
                            .expect("selected scan drains one batch");
                    }
                    _ => {
                        service
                            .maintain(&mut notifications)
                            .expect("maintenance drains one batch");
                    }
                }
                assert_eq!(service.attempts, initial + 64);
                assert_eq!(service.retry_due().len(), 64);
                assert_eq!(service.attempts, initial + 128);
                assert_eq!(service.retry_due().len(), 2);
                assert_eq!(service.attempts, initial + 130);
                assert_eq!(
                    service
                        .retries
                        .wait(base + Duration::from_secs(hour * 3600)),
                    Some(Duration::from_secs(3600))
                );
                assert_eq!(service.retry_due(), Vec::<String>::new());
            }
        },
    );
}

/// ´claim:loophome:mail-activity-counts-unwritten-refusals-and-stays-quiet´
/// ´test:unit:mail-activity-counts-unwritten-refusals-and-stays-quiet´
#[test]
fn mail_activity_counts_unwritten_refusals_and_stays_quiet() {
    fixture(
        "mail_activity_counts_unwritten_refusals_and_stays_quiet",
        |service, home| {
            let seconds = std::sync::Arc::new(AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: Monotonic::now(),
                seconds: seconds.clone(),
            });
            service.scan().expect("deliver");
            service.publish_activity();
            let path = home.join(".var/loops/.mail-service/activity.toml");
            let original = fs::read(&path).expect("operator counters");
            let data: toml::Value =
                toml::from_str(std::str::from_utf8(&original).expect("utf8")).expect("toml");
            assert_eq!(data["counters"]["scans_started"].as_integer(), Some(1));
            assert_eq!(data["counters"]["candidate_attempts"].as_integer(), Some(2));
            assert_eq!(data["counters"]["deliveries"].as_integer(), Some(2));
            let missing = Address::parse("alpha+absent").expect("sender");
            assert!(
                service
                    .candidate(&missing, OsStr::new("alpha.missing.letter"))
                    .is_err()
            );
            assert_eq!(service.activity.counters.refusals_unwritten, 1);
            seconds.store(1, Ordering::Relaxed);
            assert_eq!(service.retry_due().len(), 1);
            assert_eq!(service.activity.counters.due_retries, 1);
            assert_eq!(service.activity.counters.refusals_unwritten, 2);
            fs::write(
                home.join(".var/loops/alpha/mail/outbox/invalid"),
                b"refused",
            )
            .expect("source");
            service.scan().expect("refuse");
            assert_eq!(service.activity.counters.refusals_written, 1);
            seconds.store(59, Ordering::Relaxed);
            service.publish_activity();
            assert_eq!(fs::read(&path).expect("unchanged"), original);
            seconds.store(60, Ordering::Relaxed);
            service.publish_activity();
            let changed = fs::read(&path).expect("updated");
            assert_ne!(changed, original);
            let data: toml::Value =
                toml::from_str(std::str::from_utf8(&changed).expect("utf8")).expect("toml");
            assert_eq!(data["counters"]["refusals_unwritten"].as_integer(), Some(2));
            let inode = fs::metadata(&path).expect("published").ino();
            seconds.store(3600, Ordering::Relaxed);
            service.publish_activity();
            assert_eq!(fs::metadata(&path).expect("quiet").ino(), inode);
            assert_eq!(service.activity.wait(service.clock.monotonic()), None);
            service.activity.counters.scans_started += 1;
            let root = home.join(".var/loops/.mail-service");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o0))
                .expect("deny counters write");
            service.publish_activity();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore root");
            assert_eq!(
                service.activity.wait(service.clock.monotonic()),
                Some(Duration::from_secs(60))
            );
            seconds.store(3660, Ordering::Relaxed);
            service.publish_activity();
            assert_eq!(service.activity.wait(service.clock.monotonic()), None);
        },
    );
}

/// ´claim:loophome:mail-prunes-on-pressure-or-controlled-hourly-deadline´
/// ´test:unit:mail-prunes-on-pressure-or-controlled-hourly-deadline´
#[test]
fn mail_prunes_on_pressure_or_controlled_hourly_deadline() {
    use super::super::journal::{
        JOURNAL_MAX_BYTES, RECORD_MAX_BYTES, RESERVATION_PINS_MAX_BYTES, SUMMARY_MAX_BYTES,
    };

    fixture(
        "mail_prunes_on_pressure_or_controlled_hourly_deadline",
        |service, home| {
            let seconds = std::sync::Arc::new(AtomicU64::new(0));
            service.clock = Box::new(ControlledClock {
                base: Monotonic::now(),
                seconds: seconds.clone(),
            });
            service.scan().expect("startup");
            let inventory = service.directory.inventory().expect("accounting");
            super::super::journal::RECORD_SCANS.with(|count| count.set(0));
            service.admit_capacity(&inventory).expect("room remains");
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                0,
                "ordinary admission does not prune history"
            );
            seconds.store(3599, Ordering::Relaxed);
            service.admit_capacity(&inventory).expect("before deadline");
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                0
            );
            seconds.store(3600, Ordering::Relaxed);
            service.admit_capacity(&inventory).expect("hourly prune");
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                1
            );
            let padding = home.join(".var/loops/.mail-service/fixture-capacity");
            let file = File::create(&padding).expect("fixture-only outside writer");
            fs::set_permissions(&padding, fs::Permissions::from_mode(0o600))
                .expect("private padding");
            file.set_len(
                JOURNAL_MAX_BYTES
                    - service.journal.journal_bytes().expect("bytes")
                    - 3 * RECORD_MAX_BYTES
                    - 3 * SUMMARY_MAX_BYTES
                    - RESERVATION_PINS_MAX_BYTES
                    + 1,
            )
            .expect("pressure");
            service
                .journal
                .remeasure()
                .expect("observe fixture-only outside write");
            super::super::journal::RECORD_SCANS.with(|count| count.set(0));
            assert!(matches!(
                service.admit_capacity(&inventory),
                Err(MailError::Capacity)
            ));
            assert_eq!(
                super::super::journal::RECORD_SCANS.with(std::cell::Cell::get),
                1,
                "pressure gets one prune then refuses without evicting recent history"
            );
            fs::remove_file(&padding).expect("remove fixture-only outside padding");
            let mut notifications = notify::Notifications::new();
            for second in [7200, 10800] {
                seconds.store(second, Ordering::Relaxed);
                super::super::store::SIZE_SCANS.with(|count| count.set(0));
                if second == 7200 {
                    service
                        .maintain(&mut notifications)
                        .expect("hourly accounting");
                } else {
                    service
                        .scan_watching(&mut notifications)
                        .expect("full scan hourly accounting");
                }
                assert!(
                    super::super::store::SIZE_SCANS.with(std::cell::Cell::get) >= 2,
                    "hourly maintenance remeasures the root and retained records"
                );
            }

            assert_eq!(
                service
                    .journal
                    .records()
                    .expect("retained recent history")
                    .len(),
                2
            );
        },
    );
}
