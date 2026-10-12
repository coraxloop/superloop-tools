use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::rc::Rc;

use nix::sys::signal::{Signal, raise};

use super::{Fixture, identity};
use crate::letters::store::{RACE, command};

fn hook(phase: &'static str, action: impl FnOnce() + 'static) {
    RACE.with(|race| *race.borrow_mut() = Some((phase, Box::new(action))));
}

fn stop() {
    raise(Signal::SIGTERM).expect("thread-directed termination");
}

#[allow(unsafe_code)]
fn bounded_follow(f: &Fixture, arguments: &[&str]) -> (Vec<u8>, std::time::Duration) {
    let (cancel, timeout) = std::sync::mpsc::channel();
    // SAFETY: the caller thread stays alive until the guard has been joined.
    let caller = unsafe { libc::pthread_self() };
    let guard = std::thread::spawn(move || {
        if timeout
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            // SAFETY: caller is still running this fixture; TERM is blocked by
            // the helper. This bounds a broken wake without killing other tests.
            let _sent = unsafe { libc::pthread_kill(caller, libc::SIGTERM) };
        }
    });
    let start = std::time::Instant::now();
    let result = f.run(41002, arguments, b"");
    let elapsed = start.elapsed();
    let _cancelled = cancel.send(());
    guard.join().expect("timeout guard");
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "notice did not wake: {elapsed:?}"
    );
    (result.expect("bounded follower"), elapsed)
}

#[derive(Default)]
struct Events {
    bytes: Vec<u8>,
    flushes: Vec<usize>,
}

impl Write for Events {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        assert_eq!(self.bytes.last(), Some(&b'\n'));
        self.flushes.push(self.bytes.len());
        Ok(())
    }
}

/// ´claim:entry:letters-follow-observes-a-later-post-once-and-flushes´
/// ´test:unit:letters-follow-observes-a-later-post-once-and-flushes´
#[test]
fn letters_follow_observes_a_later_post_once_and_flushes() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-wait", move || {
        posting.post();
        // Poll twice after the post, proving that rewind and the seen set both
        // work. Thread-local injection runs the real sender command mid-follow.
        hook("follow-wait", || hook("follow-wait", stop));
    });
    let mut output = Events::default();
    let args = ["follow", "--peer", "alpha", "--interval", "1"].map(String::from);
    assert_eq!(
        command(&f.context(41002), &args, &mut io::empty(), &mut output).expect("follow"),
        0
    );
    let text = String::from_utf8(output.bytes.clone()).expect("events");
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("alpha."));
    assert!(text.contains(" sender=alpha bytes="));
    assert!(text.contains(" posted_ns="));
    assert!(text.contains("subject=\"operations\""));
    assert!(!text.contains("report"));
    assert_eq!(output.flushes, [output.bytes.len()]);
}

/// ´claim:entry:letters-follow-once-is-read-only-and-reports-zero-actions´
/// ´test:unit:letters-follow-once-is-read-only-and-reports-zero-actions´
#[test]
fn letters_follow_once_is_read_only_and_reports_zero_actions() {
    let f = Fixture::new();
    let name = f.post();
    let before = fs::read(f.new_file(&name)).expect("posted bytes");
    let args = ["follow", "--once"].map(String::from);
    let mut output = Events::default();
    assert_eq!(
        command(&f.context(41002), &args, &mut io::empty(), &mut output).expect("once"),
        0
    );
    assert_eq!(
        output.bytes,
        String::from_utf8(f.run(41002, &["list"], b"").expect("listing"))
            .expect("line")
            .trim_start_matches("new/")
            .as_bytes()
    );
    assert_eq!(output.flushes.len(), 1);
    assert_eq!(fs::read(f.new_file(&name)).expect("still new"), before);
    assert_eq!(
        f.run(41002, &["follow", "--once", "--peer", "beta"], b"")
            .expect("filtered"),
        b""
    );
}

/// ´claim:entry:letters-follow-skips-retracted-and-taken-entries-at-both-probes´
/// ´test:unit:letters-follow-skips-retracted-and-taken-entries-at-both-probes´
#[test]
fn letters_follow_skips_retracted_and_taken_entries_at_both_probes() {
    for phase in ["listing", "observing"] {
        for take in [false, true] {
            let f = Rc::new(Fixture::new());
            let name = f.post();
            let changing = Rc::clone(&f);
            hook(phase, move || {
                if take {
                    changing
                        .run(41002, &["read", &name], b"")
                        .expect("concurrent take");
                } else {
                    fs::remove_file(changing.new_file(&name)).expect("retraction");
                }
            });
            assert_eq!(f.run(41002, &["follow", "--once"], b"").expect("gone"), b"");
            assert_eq!(
                f.run(41002, &["follow", "--once"], b"")
                    .expect("still gone"),
                b""
            );
        }
    }
}

/// ´claim:entry:letters-follow-reports-each-name-once-even-after-inode-replacement´
/// ´test:unit:letters-follow-reports-each-name-once-even-after-inode-replacement´
#[test]
fn letters_follow_reports_each_name_once_even_after_inode_replacement() {
    let f = Rc::new(Fixture::new());
    let name = f.post();
    let changing = Rc::clone(&f);
    hook("follow-wait", move || {
        let path = changing.new_file(&name);
        let parked = changing.directory.path.join("held-original");
        fs::rename(&path, &parked).expect("keep original inode allocated");
        fs::copy(&parked, &path).expect("same name, different inode");
        identity(&path, 41001, 3001);
        hook("follow-wait", move || {
            fs::remove_file(&path).expect("remove replacement");
            fs::rename(&parked, &path).expect("original name and inode return");
            hook("follow-wait", stop);
        });
    });
    let output = f
        .run(41002, &["follow", "--interval", "1"], b"")
        .expect("follow replacements");
    let output = String::from_utf8(output).expect("lines");
    assert_eq!(output.lines().count(), 1);
}

/// ´claim:entry:letters-list-and-follow-escape-malformed-entries-and-continue´
/// ´test:unit:letters-list-and-follow-escape-malformed-entries-and-continue´
#[test]
fn letters_list_and_follow_escape_malformed_entries_and_continue() {
    let f = Fixture::new();
    let good = f.post();
    let bad_record = f.post();
    f.replace(&bad_record, b"not a record\nbody never printed");
    let directory = f
        .new_file(&good)
        .parent()
        .expect("new directory")
        .to_owned();
    for name in [
        std::ffi::OsString::from("bad\n\"name"),
        std::ffi::OsString::from_vec(b"bad\xffname".to_vec()),
    ] {
        fs::write(directory.join(name), b"never printed").expect("malformed name");
    }
    for args in [&["list"][..], &["follow", "--once"][..]] {
        let text =
            String::from_utf8(f.run(41002, args, b"").expect("continue")).expect("escaped lines");
        assert_eq!(text.lines().count(), 4);
        assert_eq!(text.matches(" refused reason=").count(), 3);
        assert!(text.contains("bad\\n\\\"name refused reason=\"letters malformed letter\""));
        assert!(text.contains("bad\\xffname refused reason=\"letters malformed letter\""));
        assert!(text.contains(&format!("{good} sender=alpha")));
        assert!(!text.contains("never printed"));
    }
    f.run(41002, &["read", &good], b"").expect("take good");
    let listing =
        String::from_utf8(f.run(41002, &["list"], b"").expect("both boxes")).expect("listing");
    assert!(listing.contains(&format!("cur/{good} sender=alpha")));
    assert_eq!(listing.matches(" refused reason=").count(), 3);
}

/// ´claim:entry:letters-follow-refusals-name-peer-interval-and-inbox´
/// ´test:unit:letters-follow-refusals-name-peer-interval-and-inbox´
#[test]
fn letters_follow_refusals_name_peer_interval_and_inbox() {
    let f = Fixture::new();
    f.refused(
        41002,
        &["follow", "--peer", "missing", "--once"],
        b"",
        "letters unknown loop: missing",
    );
    assert!(
        crate::letters::build_context("missing", &f.directory.path)
            .err()
            .expect("unknown loop")
            .message()
            .contains("unknown loop")
    );
    for interval in [
        "0",
        "86401",
        "-1",
        "+1",
        "1.5",
        "NaN",
        "18446744073709551616",
        "\n",
    ] {
        f.refused(
            41002,
            &["follow", "--interval", interval, "--once"],
            b"",
            "letters interval out of range:",
        );
    }
    for interval in ["1", "30", "86400"] {
        assert_eq!(
            f.run(41002, &["follow", "--interval", interval, "--once"], b"")
                .expect("bounds"),
            b""
        );
    }
    for args in [
        vec!["follow", "--interval"],
        vec!["follow", "--peer"],
        vec!["follow", "--once", "--once"],
        vec!["follow", "--interval", "1", "--interval", "2"],
        vec!["follow", "--peer", "alpha", "--peer", "beta"],
        vec!["follow", "--dry-run"],
    ] {
        f.refused(41002, &args, b"", "usage: letters");
    }
    for (suffix, mode) in [("inbox", 0o710), ("inbox/new", 0o1730)] {
        let path = f.directory.path.join(".var/loops/beta").join(suffix);
        for (uid, gid, changed_mode) in [
            (41001, 3001, mode),
            (41002, 3002, mode),
            (41002, 3001, 0o700),
        ] {
            identity(&path, uid, gid);
            fs::set_permissions(&path, fs::Permissions::from_mode(changed_mode))
                .expect("wrong inbox");
            let error = f
                .run(41002, &["follow", "--once"], b"")
                .expect_err("inbox refusal");
            assert_eq!(error.status(), 2);
            assert!(
                error
                    .message()
                    .contains("letters inbox owner, group or mode mismatch:")
            );
            assert!(error.message().contains(&format!(
                "observed uid={uid} gid={gid} mode={changed_mode:04o}"
            )));
            assert!(error.message().contains(&format!(
                "expected directory uid=41002 gid=3001 mode={mode:04o}"
            )));
        }
        identity(&path, 41002, 3001);
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("restore inbox");
    }
}

/// ´claim:entry:letters-follow-sigterm-ends-the-default-wait-and-restores-mask´
/// ´test:unit:letters-follow-sigterm-ends-the-default-wait-and-restores-mask´
#[test]
fn letters_follow_sigterm_ends_the_default_wait_and_restores_mask() {
    let f = Fixture::new();
    let before = nix::sys::signal::SigSet::thread_get_mask().expect("mask");
    hook("follow-wait", stop);
    let started = std::time::Instant::now();
    assert_eq!(
        f.run(41002, &["follow"], b"").expect("clean termination"),
        b""
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let after = nix::sys::signal::SigSet::thread_get_mask().expect("restored mask");
    assert!(after.contains(Signal::SIGTERM));
    drop(f);
    assert_eq!(
        before.contains(Signal::SIGTERM),
        nix::sys::signal::SigSet::thread_get_mask()
            .expect("fixture restored mask")
            .contains(Signal::SIGTERM)
    );
}

/// ´claim:entry:letters-follow-output-and-flush-failures-are-runtime-errors´
/// ´test:unit:letters-follow-output-and-flush-failures-are-runtime-errors´
#[test]
fn letters_follow_output_and_flush_failures_are_runtime_errors() {
    struct Failure(bool);
    impl Write for Failure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("fixture write"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fixture flush"))
        }
    }
    let f = Fixture::new();
    f.post();
    let args = ["follow", "--once"].map(String::from);
    for flush in [false, true] {
        let error = command(
            &f.context(41002),
            &args,
            &mut io::empty(),
            &mut Failure(flush),
        )
        .expect_err("output failure");
        assert_eq!(error.status(), 1);
        assert!(error.message().contains(if flush {
            "fixture flush"
        } else {
            "fixture write"
        }));
    }
}

/// ´claim:entry:letters-follow-refuses-a-malformed-inode-once-and-keeps-the-held-directory´
/// ´test:unit:letters-follow-refuses-a-malformed-inode-once-and-keeps-the-held-directory´
#[test]
fn letters_follow_refuses_a_malformed_inode_once_and_keeps_the_held_directory() {
    let f = Rc::new(Fixture::new());
    let good = f.post();
    let bad = f.post();
    f.replace(&bad, b"malformed body");
    let moving = Rc::clone(&f);
    hook("follow-wait", move || {
        let new = moving.new_file(&good).parent().expect("new").to_owned();
        let parked = moving.directory.path.join("held-new");
        fs::rename(&new, &parked).expect("move directory after first observation");
        fs::create_dir(&new).expect("substitute directory");
        fs::set_permissions(&new, fs::Permissions::from_mode(0o1730)).expect("mode");
        identity(&new, 41002, 3001);
        moving.post(); // A reopen would print this replacement-directory letter.
        hook("follow-wait", stop);
    });
    let output = String::from_utf8(
        f.run(41002, &["follow", "--interval", "1"], b"")
            .expect("held follower"),
    )
    .expect("events");
    assert_eq!(output.lines().count(), 3);
    assert_eq!(output.matches(" refused reason=").count(), 1);
    assert_eq!(output.matches(" sender=alpha ").count(), 1);
    assert!(!output.contains("malformed body"));
    assert!(output.ends_with("LETTERS follow name=inbox/new detached actions=0\n"));
}

/// ´claim:entry:letters-list-and-follow-skip-inodes-replaced-during-observation´
/// ´test:unit:letters-list-and-follow-skip-inodes-replaced-during-observation´
#[test]
fn letters_list_and_follow_skip_inodes_replaced_during_observation() {
    for verb in ["list", "follow"] {
        let f = Rc::new(Fixture::new());
        let name = f.post();
        let replacing = Rc::clone(&f);
        hook("observing", move || {
            let path = replacing.new_file(&name);
            let parked = replacing.directory.path.join("original");
            fs::rename(&path, &parked).expect("park original");
            fs::copy(&parked, &path).expect("replace inode");
            identity(&path, 41001, 3001);
        });
        let mut args = vec![verb];
        if verb == "follow" {
            args.push("--once");
        }
        assert_eq!(f.run(41002, &args, b"").expect("skip changed inode"), b"");
        assert_ne!(f.run(41002, &args, b"").expect("next observation"), b"");
    }
}

/// ´claim:entry:letters-follow-kernel-notice-wakes-a-day-long-interval´
/// ´test:unit:letters-follow-kernel-notice-wakes-a-day-long-interval´
#[test]
fn letters_follow_kernel_notice_wakes_a_day_long_interval() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-wait", move || {
        posting.post();
        hook("follow-wait", stop);
    });
    let (output, _) = bounded_follow(&f, &["follow", "--interval", "86400"]);
    assert_eq!(String::from_utf8(output).expect("line").lines().count(), 1);
}

/// ´claim:entry:letters-follow-arms-before-the-first-scan´
/// ´test:unit:letters-follow-arms-before-the-first-scan´
#[test]
fn letters_follow_arms_before_the_first_scan() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-armed", move || {
        posting.post();
        hook("follow-wait", stop);
    });
    let output = f.run(41002, &["follow"], b"").expect("armed follower");
    assert_eq!(String::from_utf8(output).expect("line").lines().count(), 1);
}

/// ´claim:entry:letters-follow-suppressed-notice-falls-back-to-the-poll´
/// ´test:unit:letters-follow-suppressed-notice-falls-back-to-the-poll´
#[test]
fn letters_follow_suppressed_notice_falls_back_to_the_poll() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-wait", move || {
        posting.post();
        crate::letters::wake::SUPPRESS_NOTICE.set(true);
        hook("follow-wait", stop);
    });
    let (output, elapsed) = bounded_follow(&f, &["follow", "--interval", "1"]);
    assert!(elapsed >= std::time::Duration::from_millis(900));
    assert_eq!(String::from_utf8(output).expect("line").lines().count(), 1);
}

/// ´claim:entry:letters-follow-overflow-notice-rescans-without-counting-events´
/// ´test:unit:letters-follow-overflow-notice-rescans-without-counting-events´
#[test]
fn letters_follow_overflow_notice_rescans_without_counting_events() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-wait", move || {
        posting.post();
        posting.post();
        // SIGIO is the coalesced/overflow notification. Inject its indication,
        // not a full kernel queue; the scan must find both records regardless.
        raise(Signal::SIGIO).expect("overflow indication");
        hook("follow-wait", stop);
    });
    let (output, _) = bounded_follow(&f, &["follow", "--interval", "86400"]);
    assert_eq!(String::from_utf8(output).expect("lines").lines().count(), 2);
}

/// ´claim:entry:letters-follow-temporary-and-retracted-notices-print-nothing´
/// ´test:unit:letters-follow-temporary-and-retracted-notices-print-nothing´
#[test]
fn letters_follow_temporary_and_retracted_notices_print_nothing() {
    for retract in [false, true] {
        let f = Rc::new(Fixture::new());
        let posting = Rc::clone(&f);
        hook("follow-wait", move || {
            if retract {
                let name = posting.post();
                fs::remove_file(posting.new_file(&name)).expect("retract before observation");
            } else {
                fs::write(posting.new_file(".tmp-unpublished"), b"never printed")
                    .expect("temporary publication");
            }
            hook("follow-wait", stop);
        });
        let (output, _) = bounded_follow(&f, &["follow", "--interval", "86400"]);
        assert_eq!(output, b"");
    }
}

/// ´claim:entry:letters-follow-detached-directory-ends-by-name´
/// ´test:unit:letters-follow-detached-directory-ends-by-name´
#[test]
fn letters_follow_detached_directory_ends_by_name() {
    for replace in [false, true] {
        let f = Rc::new(Fixture::new());
        let moving = Rc::clone(&f);
        hook("follow-wait", move || {
            let new = moving.new_file("unused").parent().expect("new").to_owned();
            if replace {
                fs::rename(&new, moving.directory.path.join("detached-new")).expect("move new");
                fs::create_dir(&new).expect("replacement");
            } else {
                fs::remove_dir(&new).expect("delete empty new");
            }
        });
        let (output, _) = bounded_follow(&f, &["follow", "--interval", "86400"]);
        assert_eq!(
            output,
            b"LETTERS follow name=inbox/new detached actions=0\n"
        );
    }
}

/// ´claim:entry:letters-follow-drains-termination-during-scan-once-and-shutdown´
/// ´test:unit:letters-follow-drains-termination-during-scan-once-and-shutdown´
#[test]
fn letters_follow_drains_termination_during_scan_once_and_shutdown() {
    for once in [false, true] {
        let f = Fixture::new();
        f.post();
        hook("observing", || {
            stop();
            hook("follow-stopping", stop); // Another TERM after the wait consumed the first.
        });
        let mut args = vec!["follow"];
        if once {
            args.push("--once");
        }
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            command(&f.context(41002), &args, &mut io::empty(), &mut Vec::new())
                .expect("TERM success"),
            0
        );
        assert!(
            nix::sys::signal::SigSet::thread_get_mask()
                .expect("exit mask")
                .contains(Signal::SIGTERM)
        );
        // Even a TERM after cleanup cannot signal-kill the helper before its report.
        stop();
        let mut term = nix::sys::signal::SigSet::empty();
        term.add(Signal::SIGTERM);
        assert_eq!(
            term.wait().expect("drain final fixture signal"),
            Signal::SIGTERM
        );
    }
}

/// ´claim:entry:letters-list-and-follow-names-cannot-inject-fields´
/// ´test:unit:letters-list-and-follow-names-cannot-inject-fields´
#[test]
fn letters_list_and_follow_names_cannot_inject_fields() {
    let f = Fixture::new();
    f.post();
    fs::write(
        f.new_file("crafted sender=forged bytes=999"),
        b"not content",
    )
    .expect("crafted name");
    for args in [&["list"][..], &["follow", "--once"][..]] {
        let output =
            String::from_utf8(f.run(41002, args, b"").expect("escaped listing")).expect("lines");
        let refused = output
            .lines()
            .find(|line| line.contains(" refused "))
            .expect("refusal");
        assert!(
            refused
                .trim_start_matches("new/")
                .starts_with("crafted\\x20sender\\x3dforged\\x20bytes\\x3d999 refused reason=")
        );
        assert!(!refused.contains(" sender="));
        assert!(!refused.contains(" bytes="));
        assert_eq!(output.lines().count(), 2);
    }
}

/// ´claim:entry:letters-follow-watch-failure-names-the-held-object´
/// ´test:unit:letters-follow-watch-failure-names-the-held-object´
#[test]
fn letters_follow_watch_failure_names_the_held_object() {
    let f = Fixture::new();
    let name = f.post();
    let file: std::os::fd::OwnedFd = fs::File::open(f.new_file(&name))
        .expect("regular file")
        .into();
    let error =
        crate::letters::wake::arm(&file, "fixture-file").expect_err("not a watchable directory");
    assert_eq!(error.status(), 1);
    assert!(
        error
            .message()
            .contains("letters follow watch fixture-file:")
    );
}

/// ´claim:entry:letters-follow-once-never-arms-a-directory-watch´
/// ´test:unit:letters-follow-once-never-arms-a-directory-watch´
#[test]
fn letters_follow_once_never_arms_a_directory_watch() {
    let f = Fixture::new();
    f.post();
    let before = crate::letters::wake::ARM_COUNT.get();
    hook("follow-armed", || panic!("once must not arm"));
    let output = f.run(41002, &["follow", "--once"], b"").expect("scan only");
    assert_eq!(String::from_utf8(output).expect("line").lines().count(), 1);
    assert_eq!(crate::letters::wake::ARM_COUNT.get(), before);
    RACE.with(|slot| *slot.borrow_mut() = None);
}

fn entry_next(f: &Fixture, options: &[&str]) -> (u8, String, String) {
    let mut arguments = vec!["follow", "--next"];
    arguments.extend_from_slice(options);
    entry_command(f, &arguments)
}

/// # Panics
/// Panics only if fixture setup fails or a notification is duplicated or fails to return.
/// ´claim:entry:letters-next-entry-returns-on-notice-and-fallback´
/// ´test:unit:letters-next-entry-returns-on-notice-and-fallback´
#[test]
fn letters_next_entry_returns_on_notice_and_fallback() {
    for fallback in [false, true] {
        let f = Rc::new(Fixture::new());
        let posting = Rc::clone(&f);
        let name = Rc::new(std::cell::RefCell::new(String::new()));
        let posted = Rc::clone(&name);
        hook("follow-wait", move || {
            *posted.borrow_mut() = posting.post();
            raise(Signal::SIGIO).expect("publication notice");
            crate::letters::wake::SUPPRESS_NOTICE.set(fallback);
            // If next waits again after printing, stop it and make its nonzero
            // entry status fail below. No outer timeout can conceal the print.
            hook("follow-wait", stop);
        });
        let started = std::time::Instant::now();
        let (status, output, report) = entry_next(&f, &["--interval", "1"]);
        assert_eq!(status, 0, "fallback={fallback}: {report}");
        assert_eq!(output.lines().count(), 1);
        assert!(output.starts_with(&format!("{} ", name.borrow())));
        assert_eq!(report, "LETTERS actions=0\n");
        assert!(f.new_file(&name.borrow()).exists());
        assert!(!crate::letters::wake::SUPPRESS_NOTICE.get());
        if fallback {
            assert!(started.elapsed() >= std::time::Duration::from_millis(900));
        }
        RACE.with(|slot| *slot.borrow_mut() = None);
    }
}

/// # Panics
/// Panics only if fixture setup fails or notice and interval scans duplicate a name.
/// ´claim:entry:letters-entry-notice-and-interval-share-seen-names´
/// ´test:unit:letters-entry-notice-and-interval-share-seen-names´
#[test]
fn letters_entry_notice_and_interval_share_seen_names() {
    let f = Rc::new(Fixture::new());
    let posting = Rc::clone(&f);
    hook("follow-wait", move || {
        posting.post();
        raise(Signal::SIGIO).expect("notice before interval expires");
        hook("follow-wait", || {
            // The notice scan has printed the name. Suppress this redundant
            // notice so the interval rescan sees that same unread letter.
            raise(Signal::SIGIO).expect("redundant notice");
            crate::letters::wake::SUPPRESS_NOTICE.set(true);
            hook("follow-wait", stop);
        });
    });
    let (status, output, report) = entry_command(&f, &["follow", "--interval", "1"]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 1);
    assert_eq!(report, "LETTERS actions=0\n");
    assert!(!crate::letters::wake::SUPPRESS_NOTICE.get());
}

///
/// # Panics
/// Panics only if fixture setup fails or the follower violates its output contract.
/// ´claim:entry:letters-follow-preexisting-name-is-reported-once-across-notices´
/// ´test:unit:letters-follow-preexisting-name-is-reported-once-across-notices´
#[test]
fn letters_follow_preexisting_name_is_reported_once_across_notices() {
    let f = Fixture::new();
    let name = f.post();
    hook("follow-wait", || {
        raise(Signal::SIGIO).expect("notice for existing letter");
        hook("follow-wait", stop);
    });
    let (output, _) = bounded_follow(&f, &["follow", "--interval", "1"]);
    let output = String::from_utf8(output).expect("metadata");
    assert_eq!(output.lines().count(), 1);
    assert!(output.starts_with(&format!("{name} ")));
    let (status, output, _) = entry_next(&f, &[]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 1);
    let printed_name = output.split_whitespace().next().expect("bare name");
    let (status, output, report) = entry_next(&f, &["--exclude", printed_name, "--wall", "1"]);
    assert_eq!(status, 124);
    assert_eq!(output, "");
    assert!(report.contains("letters follow wall expired"));
}

///
/// # Panics
/// Panics only if fixture setup fails or the follower violates its deadline contract.
/// ´claim:entry:letters-follow-wall-bounds-a-long-poll-and-validates-arguments´
/// ´test:unit:letters-follow-wall-bounds-a-long-poll-and-validates-arguments´
#[test]
fn letters_follow_wall_bounds_a_long_poll_and_validates_arguments() {
    let f = Fixture::new();
    let start = std::time::Instant::now();
    let (status, output, report) = entry_next(&f, &["--wall", "1", "--interval", "86400"]);
    assert_eq!(status, 124);
    assert_eq!(output, "");
    assert!(report.contains("letters follow wall expired"));
    assert!(start.elapsed() >= std::time::Duration::from_secs(1));
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(entry_command(&f, &["follow", "--wall", "1"]).0, 2);
    for value in ["0", "86401", "-1", "1.5", "word"] {
        let (status, _, report) = entry_next(&f, &["--wall", value]);
        assert_eq!(status, 2);
        assert!(report.contains("letters wall out of range"));
    }
    for options in [
        &["--wall"][..],
        &["--wall", "1", "--wall", "2"],
        &["--once", "--wall", "1"],
    ] {
        assert_eq!(entry_next(&f, options).0, 2);
    }
}

fn entry_command(f: &Fixture, options: &[&str]) -> (u8, String, String) {
    struct NoCommands;
    impl crate::Runner for NoCommands {
        fn run(&mut self, _: &crate::CommandSpec) -> Result<crate::CommandOutput, crate::RunError> {
            panic!("private letters entry must not launch another command");
        }
    }
    let mut arguments = vec![
        std::ffi::OsString::from("letters-private"),
        "beta".into(),
        f.directory.path.as_os_str().to_owned(),
    ];
    arguments.extend(options.iter().map(std::ffi::OsString::from));
    let mut output = Vec::new();
    let mut report = Vec::new();
    let status = crate::enter_loop_entry(
        std::ffi::OsStr::new("superloop"),
        arguments,
        &mut NoCommands,
        &mut output,
        &mut report,
    );
    (
        status,
        String::from_utf8(output).expect("metadata"),
        String::from_utf8(report).expect("report"),
    )
}

/// # Panics
/// Panics only if fixture setup fails or a snapshot omits a stable unread letter.
/// ´claim:entry:letters-once-entry-repeats-three-old-unread-letters´
/// ´test:unit:letters-once-entry-repeats-three-old-unread-letters´
#[test]
fn letters_once_entry_repeats_three_old_unread_letters() {
    let f = Fixture::new();
    let read = f.post();
    f.run(41002, &["read", &read], b"")
        .expect("one read letter");
    let mut unread = Vec::new();
    for instant in 1..=3 {
        let original = f.post();
        let bytes = fs::read(f.new_file(&original)).expect("posted record");
        let mut record = crate::letters::record::LetterRecord::decode(&bytes).expect("record");
        // Epoch posting instants exercise age without a minute-long sleep.
        record.posted_ns = instant;
        let bytes = record.encode().expect("old record");
        f.replace(&original, &bytes);
        let suffix = original.rsplit('.').next().expect("suffix");
        let name = format!("alpha.{instant:020}.{suffix}");
        fs::rename(f.new_file(&original), f.new_file(&name)).expect("old name");
        unread.push((name, bytes));
    }
    let (status, baseline, report) = entry_command(&f, &["list"]);
    assert_eq!(status, 0);
    assert_eq!(report, "LETTERS actions=0\n");
    assert_eq!(baseline.lines().count(), 4);
    let expected = baseline
        .lines()
        .filter_map(|line| line.strip_prefix("new/"))
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 3);
    for sample in 0..3 {
        let started = std::time::Instant::now();
        let (status, output, report) = entry_command(&f, &["follow", "--once"]);
        let elapsed = started.elapsed();
        assert_eq!(status, 0);
        assert_eq!(output.lines().collect::<Vec<_>>(), expected);
        assert_eq!(report, "LETTERS actions=0\n");
        for (name, bytes) in &unread {
            assert_eq!(&fs::read(f.new_file(name)).expect("still unread"), bytes);
        }
        writeln!(
            std::io::stderr().lock(),
            "ONCE-MEASURE sample={sample} unread=3 lines=3 wall_ns={}",
            elapsed.as_nanos()
        )
        .expect("snapshot measurement");
    }
    let (status, output, report) = entry_command(&f, &["follow", "--once", "--peer", "beta"]);
    assert_eq!(status, 0);
    assert!(
        output.is_empty(),
        "peer filtering is an admitted empty snapshot"
    );
    assert_eq!(report, "LETTERS actions=0\n");
}

/// # Panics
/// Panics only if fixture setup fails or a refused entry disappears silently.
/// ´claim:entry:letters-once-entry-names-invalid-unread-entries´
/// ´test:unit:letters-once-entry-names-invalid-unread-entries´
#[test]
fn letters_once_entry_names_invalid_unread_entries() {
    let f = Fixture::new();
    let shape = f.post();
    f.replace(&shape, b"invalid record");
    let permissions = f.post();
    fs::set_permissions(f.new_file(&permissions), fs::Permissions::from_mode(0o640))
        .expect("wrong mode");
    let retired = f.post();
    identity(&f.new_file(&retired), 2999, 3001);
    fs::write(f.new_file(".tmp-unpublished"), b"unfinished publication").expect("temporary entry");
    let (status, output, report) = entry_command(&f, &["follow", "--once"]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 3);
    assert_eq!(output.matches(" refused reason=").count(), 3);
    for name in [&shape, &permissions, &retired] {
        assert!(
            output
                .lines()
                .any(|line| line.starts_with(&format!("{name} refused reason=")))
        );
        assert!(f.new_file(name).exists());
    }
    assert!(output.contains("letters malformed letter"));
    assert!(output.contains("letters malformed file metadata"));
    assert!(output.contains("letters sender uid matches no registry row"));
    assert_eq!(report, "LETTERS actions=0\n");
}

/// ´claim:entry:letters-next-entry-drains-burst-and-excludes-without-taking´
/// ´test:unit:letters-next-entry-drains-burst-and-excludes-without-taking´
#[test]
fn letters_next_entry_drains_burst_and_excludes_without_taking() {
    let f = Fixture::new();
    let first = f.post();
    let second = f.post();
    let (status, output, report) = entry_next(&f, &[]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 1);
    assert!(output.starts_with(&format!("{first} ")));
    assert_eq!(report, "LETTERS actions=0\n");
    let (status, output, _) = entry_next(&f, &["--exclude", &first]);
    assert_eq!(status, 0);
    assert!(output.starts_with(&format!("{second} ")));
    assert!(f.new_file(&first).exists());
    assert!(f.new_file(&second).exists());
    hook("follow-wait", stop);
    let (status, output, _) = entry_next(&f, &["--exclude", &first, "--exclude", &second]);
    assert_ne!(status, 0);
    assert_eq!(output, "");
}

/// ´claim:entry:letters-next-entry-waits-past-held-oldest-for-arrival´
/// ´test:unit:letters-next-entry-waits-past-held-oldest-for-arrival´
#[test]
fn letters_next_entry_waits_past_held_oldest_for_arrival() {
    let f = Fixture::new();
    let held = f.post();
    let sender = f.context(41001);
    hook("follow-wait", move || {
        command(
            &sender,
            &["post", "beta", "--subject", "重要 \\\"release\\\" \\\\"].map(String::from),
            &mut &b"private body"[..],
            &mut Vec::new(),
        )
        .expect("post after arming");
    });
    let (status, output, _) = entry_next(&f, &["--exclude", &held, "--interval", "86400"]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 1);
    let metadata = crate::parse_letter_metadata(output.trim_end()).expect("strict metadata");
    assert_eq!(metadata.subject, "重要 \\\"release\\\" \\\\");
    assert_ne!(metadata.name, held);
    assert!(!output.contains("private body"));
    assert!(f.new_file(&held).exists());
    assert!(f.new_file(&metadata.name).exists());
}

/// ´claim:entry:letters-next-entry-first-arrival-and-detachment´
/// ´test:unit:letters-next-entry-first-arrival-and-detachment´
#[test]
fn letters_next_entry_first_arrival_and_detachment() {
    let f = Fixture::new();
    let sender = f.context(41001);
    hook("follow-armed", move || {
        command(
            &sender,
            &["post", "beta", "--subject", "first"].map(String::from),
            &mut &b"body"[..],
            &mut Vec::new(),
        )
        .expect("first arrival");
    });
    assert_eq!(entry_next(&f, &[]).0, 0);
    let held = f.directory.path.join(".var/loops/beta/inbox/new");
    hook("follow-armed", move || {
        fs::rename(&held, held.with_file_name("parked")).expect("detach");
    });
    let (status, output, report) = entry_next(&f, &[]);
    assert_ne!(status, 0);
    assert_eq!(output, "");
    assert!(report.contains("detached before notification"));
}

/// ´claim:entry:letters-next-entry-empty-wait-expires-at-outer-deadline´
/// ´test:unit:letters-next-entry-empty-wait-expires-at-outer-deadline´
#[test]
fn letters_next_entry_empty_wait_expires_at_outer_deadline() {
    const FILTER: &str =
        "letters::tests::follow::letters_next_entry_empty_wait_expires_at_outer_deadline";
    if std::env::var_os("LETTERS_DEADLINE_CHILD").is_some() {
        let f = Fixture::new();
        let (status, output, _) = entry_next(&f, &[]);
        assert_ne!(status, 0);
        assert_eq!(output, "");
        return;
    }
    let start = std::time::Instant::now();
    let result = std::process::Command::new("timeout")
        .arg("2")
        .arg(std::env::current_exe().expect("test executable"))
        .args([FILTER, "--exact", "--nocapture"])
        .env("LETTERS_DEADLINE_CHILD", "1")
        .output()
        .expect("bounded entry");
    assert_eq!(result.status.code(), Some(124));
    assert!(start.elapsed() >= std::time::Duration::from_secs(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("sender="));
}

/// ´claim:entry:letters-metadata-readers-require-the-current-subject-field´
/// ´test:unit:letters-metadata-readers-require-the-current-subject-field´
#[test]
fn letters_metadata_readers_require_the_current_subject_field() {
    let f = Fixture::new();
    f.run(
        41001,
        &[
            "post",
            "beta",
            "--subject",
            "重要 \"quoted\" \\ refused reason=",
        ],
        b"secret body",
    )
    .expect("post subject");
    let listed = String::from_utf8(f.run(41002, &["list"], b"").expect("list")).expect("UTF-8");
    let once = String::from_utf8(f.run(41002, &["follow", "--once"], b"").expect("snapshot"))
        .expect("UTF-8");
    let (status, next, _) = entry_next(&f, &[]);
    assert_eq!(status, 0);
    assert_eq!(listed.trim_start_matches("new/"), once);
    assert_eq!(once, next);
    let line = listed.trim_end();
    let metadata = crate::parse_letter_metadata(line).expect("current shape");
    assert_eq!(metadata.subject, "重要 \"quoted\" \\ refused reason=");
    assert!(!listed.contains("secret body"));
    assert!(
        crate::parse_letter_metadata(line.split_once(" subject=").expect("fifth field").0).is_err()
    );
    assert!(crate::parse_letter_metadata(&format!("{line} extra=1")).is_err());
}

/// ´claim:entry:letters-next-skips-retired-sender-and-reports-once´
/// ´test:unit:letters-next-skips-retired-sender-and-reports-once´
#[test]
fn letters_next_skips_retired_sender_and_reports_once() {
    let f = Fixture::new();
    let retired = f.post();
    identity(&f.new_file(&retired), 2999, 3001);
    let valid = f.post();
    for excludes in [&[][..], &["--exclude", retired.as_str()][..]] {
        let (status, output, report) = entry_next(&f, excludes);
        assert_eq!(status, 0);
        assert_eq!(output.lines().count(), 1);
        assert!(output.starts_with(&format!("{valid} ")));
        assert_eq!(report.matches("refused reason=").count(), 1);
        assert!(report.contains("letters sender uid matches no registry row"));
    }
    let sender = f.context(41001);
    hook("follow-wait", move || {
        hook("follow-wait", move || {
            command(
                &sender,
                &["post", "beta", "--subject", "arrival"].map(String::from),
                &mut &b"body"[..],
                &mut Vec::new(),
            )
            .expect("arrival");
        });
    });
    let (status, output, report) = entry_next(&f, &["--exclude", &valid, "--interval", "1"]);
    assert_eq!(status, 0);
    assert_eq!(output.lines().count(), 1);
    assert_eq!(report.matches("refused reason=").count(), 1);
    assert!(f.new_file(&retired).exists());
}

/// ´claim:entry:letters-list-measures-thirty-read-and-one-unread´
/// ´test:unit:letters-list-measures-thirty-read-and-one-unread´
#[test]
fn letters_list_measures_thirty_read_and_one_unread() {
    for size in [6, 65536] {
        let f = Fixture::new();
        let body = vec![b'x'; size];
        for index in 0..31 {
            let posted = String::from_utf8(
                f.run(41001, &["post", "beta", "--subject", "measurement"], &body)
                    .expect("post"),
            )
            .expect("post line");
            let name = posted
                .split_whitespace()
                .find_map(|word| word.strip_prefix("name="))
                .expect("name");
            if index < 30 {
                f.run(41002, &["read", name, "--body"], b"").expect("take");
            }
        }
        for sample in 0..5 {
            let start = std::time::Instant::now();
            let (status, output, _) = entry_command(&f, &["list"]);
            let elapsed = start.elapsed();
            assert_eq!(status, 0);
            assert_eq!(output.lines().count(), 31);
            assert_eq!(
                output
                    .lines()
                    .filter(|line| line.starts_with("new/"))
                    .count(),
                1
            );
            if std::env::var("LETTERS_LIST_MEASURE").as_deref() == Ok("1") {
                writeln!(
                std::io::stderr(),
                "LIST-MEASURE body_bytes={size} read=30 unread=1 sample={sample} wall_ns={} output_bytes={}",
                elapsed.as_nanos(),
                output.len()
                ).expect("measurement report");
            }
        }
    }
}
