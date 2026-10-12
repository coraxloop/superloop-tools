//! Injected namespace identities exercise the actual letters dispatcher, not kernel DAC.

mod follow;

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use super::record::{LetterRecord, MAX_BODY, parse_name};
use super::store::{Context, IDENTITIES, command};
use crate::{LoopError, LoopRecord};

struct Fixture {
    _namespace: super::NamespaceFixture,
    directory: crate::tests::TestDir,
    rows: Vec<LoopRecord>,
    signals: nix::sys::signal::SigSet,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A production helper retains TERM blocked until exit. The fixture is a
        // reusable test thread, so restore its caller's mask after that boundary.
        nix::sys::signal::pthread_sigmask(
            nix::sys::signal::SigmaskHow::SIG_SETMASK,
            Some(&self.signals),
            None,
        )
        .expect("restore fixture signal mask");
    }
}

fn identity(path: &Path, uid: u32, gid: u32) {
    let meta = fs::symlink_metadata(path).expect("identity metadata");
    IDENTITIES.with(|identities| {
        identities
            .borrow_mut()
            .insert((meta.dev(), meta.ino()), (uid, gid));
    });
}

impl Fixture {
    fn new() -> Self {
        let signals = nix::sys::signal::SigSet::thread_get_mask().expect("fixture signal mask");
        super::wake::SUPPRESS_NOTICE.set(false);
        assert!(
            std::env::var_os("TMPDIR").is_some(),
            "fixtures require TMPDIR"
        );
        IDENTITIES.with(|identities| identities.borrow_mut().clear());
        super::store::RACE.with(|race| {
            race.borrow_mut().take();
        });
        let directory = crate::tests::TestDir::new("letters-namespace");
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).expect("home mode");
        for (suffix, mode) in [
            (".config", 0o700),
            (".config/loops", 0o700),
            (".var", 0o711),
            (".var/loops", 0o711),
        ] {
            let path = directory.path.join(suffix);
            fs::create_dir(&path).expect("fixture owner root");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("owner root mode");
        }
        let registry = directory.path.join(".config/loops/registry.toml");
        fs::write(&registry, "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1,0,0]\nloops = [{ name = 'alpha', uid = 41001, launch = 'dev/alpha' }, { name = 'beta', uid = 41002, launch = 'dev/beta' }]\n").expect("registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
        let ledger = directory.path.join(".config/loops/allocations.toml");
        fs::write(&ledger, "letters_gid = 3001\n").expect("grant");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("ledger mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        for (name, uid) in [("alpha", 41001), ("beta", 41002)] {
            let home = directory.path.join(".var/loops").join(name);
            for (suffix, uid, gid, mode) in [
                ("", owner, owner, 0o711),
                ("shared", uid, uid, 0o750),
                ("inbox", uid, 3001, 0o710),
                ("inbox/new", uid, 3001, 0o1730),
                ("inbox/cur", uid, uid, 0o700),
            ] {
                let path = home.join(suffix);
                fs::create_dir(&path).expect("fixture directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("fixture mode");
                identity(&path, uid, gid);
            }
        }
        let inherited = open(
            &directory.path,
            OFlag::O_PATH | OFlag::O_DIRECTORY,
            Mode::empty(),
        )
        .expect("inherited owner home");
        let namespace =
            super::activate_fixture(&directory.path, &inherited).expect("namespace fixture");
        let context = super::build_context("alpha", &directory.path).expect("real context builder");
        Self {
            _namespace: namespace,
            directory,
            rows: context.rows,
            signals,
        }
    }

    fn context(&self, uid: u32) -> Context {
        let name = self
            .rows
            .iter()
            .find(|row| row.uid == uid)
            .map_or("alpha", |row| row.name.as_str());
        let mut context =
            super::build_context(name, &self.directory.path).expect("real context builder");
        // The negative owner test injects an identity absent from the actual registry.
        context.uid = uid;
        context
    }

    fn owner_identity(&self, uid: u32) {
        for suffix in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/registry.toml",
            ".config/loops/allocations.toml",
            ".var",
            ".var/loops",
            ".var/loops/alpha",
            ".var/loops/beta",
        ] {
            identity(&self.directory.path.join(suffix), uid, uid);
        }
    }

    fn run(&self, uid: u32, args: &[&str], body: &[u8]) -> Result<Vec<u8>, LoopError> {
        let args = args
            .iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        command(&self.context(uid), &args, &mut &body[..], &mut output)?;
        Ok(output)
    }

    fn post(&self) -> String {
        let output = self
            .run(
                41001,
                &["post", "beta", "--subject", "operations"],
                b"report\n",
            )
            .expect("post");
        String::from_utf8(output)
            .expect("output")
            .split_whitespace()
            .find_map(|word| word.strip_prefix("name="))
            .expect("name")
            .to_owned()
    }

    fn new_file(&self, name: &str) -> std::path::PathBuf {
        self.directory
            .path
            .join(".var/loops/beta/inbox/new")
            .join(name)
    }

    fn replace(&self, name: &str, bytes: &[u8]) {
        let path = self.new_file(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("writable fixture");
        fs::write(&path, bytes).expect("replace fixture bytes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).expect("fixture mode");
    }

    fn refused(&self, uid: u32, args: &[&str], body: &[u8], message: &str) {
        let error = self.run(uid, args, body).expect_err("refusal");
        assert_eq!(error.status(), 2);
        assert!(error.message().contains(message), "{}", error.message());
    }
}

/// ´claim:entry:letters-two-uid-post-take-list-and-remove´
/// ´test:unit:letters-two-uid-post-take-list-and-remove´
#[test]
fn letters_two_uid_post_take_list_and_remove() {
    let f = Fixture::new();
    let name = f.post();
    let path = f.new_file(&name);
    let fd = open(&path, OFlag::O_RDONLY, Mode::empty()).expect("posted file");
    let metadata = super::store::stat(&fd).expect("injected identity");
    assert_eq!(
        (metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o7777),
        (41001, 3001, 0o440)
    );
    let listed = f.run(41002, &["list"], b"").expect("list");
    assert!(
        String::from_utf8(listed)
            .expect("line")
            .starts_with(&format!("new/{name} "))
    );
    assert_eq!(
        f.run(41002, &["list", "--peer", "beta"], b"")
            .expect("filtered"),
        b""
    );
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"").expect("read"),
        b"report\n"
    );
    assert!(!path.exists());
    let listed = f
        .run(41002, &["list", "--peer", "alpha"], b"")
        .expect("list cur");
    assert!(
        String::from_utf8(listed)
            .expect("line")
            .starts_with(&format!("cur/{name} "))
    );
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"")
            .expect("reread"),
        b"report\n"
    );
    fs::remove_file(
        f.directory
            .path
            .join(".var/loops/beta/inbox/cur")
            .join(name),
    )
    .expect("receiver fixture removes");
    assert_eq!(f.run(41002, &["list"], b"").expect("empty"), b"");
}

/// ´claim:entry:letters-read-accepts-listed-box-name-and-refuses-other-paths´
/// ´test:unit:letters-read-accepts-listed-box-name-and-refuses-other-paths´
#[test]
fn letters_read_accepts_listed_box_name_and_refuses_other_paths() {
    let f = Fixture::new();
    let name = f.post();
    let listed =
        String::from_utf8(f.run(41002, &["list"], b"").expect("new list")).expect("listing");
    let listed_new = listed.split_whitespace().next().expect("new name");
    assert!(
        crate::parse_letter_metadata(listed.trim_end())
            .expect("new metadata")
            .unread
    );
    assert_eq!(listed_new, format!("new/{name}"));
    for (invalid, defect) in [
        (format!("other/{name}"), "invalid box prefix"),
        (format!("a/b/{name}"), "unexpected path separator"),
        (format!("new/a/{name}"), "unexpected path separator"),
    ] {
        let error = f
            .run(41002, &["read", &invalid], b"")
            .expect_err("invalid read name is refused");
        assert_eq!(error.status(), 2);
        assert_eq!(
            error.message(),
            format!("letters malformed letter name={invalid} ({defect})")
        );
    }
    assert_eq!(
        f.run(41002, &["read", listed_new, "--body"], b"")
            .expect("read listed new name"),
        b"report\n"
    );
    let listed =
        String::from_utf8(f.run(41002, &["list"], b"").expect("cur list")).expect("listing");
    let listed_cur = listed.split_whitespace().next().expect("cur name");
    assert!(
        !crate::parse_letter_metadata(listed.trim_end())
            .expect("cur metadata")
            .unread
    );
    assert_eq!(listed_cur, format!("cur/{name}"));
    assert_eq!(
        f.run(41002, &["read", listed_cur, "--body"], b"")
            .expect("read listed cur name"),
        b"report\n"
    );
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"")
            .expect("bare name still searches both"),
        b"report\n"
    );
}

/// ´claim:entry:letters-read-malformed-names-escape-fields-and-controls´
/// ´test:unit:letters-read-malformed-names-escape-fields-and-controls´
#[test]
fn letters_read_malformed_names_escape_fields_and_controls() {
    let f = Fixture::new();
    for uid in [41001, 41002] {
        for (name, escaped) in [
            ("new/bad name", "new/bad\\x20name"),
            ("new/bad=name", "new/bad\\x3dname"),
            ("new/bad\nname", "new/bad\\nname"),
        ] {
            let error = f
                .run(uid, &["read", name], b"")
                .expect_err("malformed read name is refused");
            assert_eq!(error.status(), 2);
            assert_eq!(
                error.message(),
                format!("letters malformed letter name={escaped} (invalid letter name grammar)")
            );
        }
    }
}

/// ´claim:entry:letters-dry-runs-print-full-record-and-match-actions´
/// ´test:unit:letters-dry-runs-print-full-record-and-match-actions´
#[test]
fn letters_dry_runs_print_full_record_and_match_actions() {
    let f = Fixture::new();
    let dry = f
        .run(
            41001,
            &["post", "beta", "--subject", "preview", "--dry-run"],
            b"full\0body",
        )
        .expect("dry post");
    let newline = dry.iter().position(|byte| *byte == b'\n').expect("report");
    assert!(String::from_utf8_lossy(&dry[..newline]).contains("actions=1 dry_run=true"));
    assert_eq!(
        LetterRecord::decode(&dry[newline + 1..])
            .expect("full record")
            .body,
        b"full\0body"
    );
    assert_eq!(f.run(41002, &["list"], b"").expect("no change"), b"");
    let name = f.post();
    let dry = f
        .run(41002, &["read", &name, "--dry-run"], b"")
        .expect("dry read");
    assert!(String::from_utf8_lossy(&dry).contains("actions=1 dry_run=true"));
    assert!(f.new_file(&name).exists());
    f.run(41002, &["read", &name], b"").expect("take");
    let dry = f
        .run(41002, &["read", &name, "--dry-run"], b"")
        .expect("already taken");
    assert!(String::from_utf8_lossy(&dry).contains("actions=0 dry_run=true"));
}

/// ´claim:entry:letters-refuse-self-unknown-oversized-subject-and-arguments´
/// ´test:unit:letters-refuse-self-unknown-oversized-subject-and-arguments´
#[test]
fn letters_refuse_self_unknown_oversized_subject_and_arguments() {
    let f = Fixture::new();
    f.refused(
        41001,
        &["post", "alpha", "--subject", "x"],
        b"",
        "self-post",
    );
    f.refused(
        41001,
        &["post", "unknown", "--subject", "x"],
        b"",
        "unknown loop",
    );
    f.refused(
        41001,
        &["post", "beta", "--subject", "x"],
        &vec![0; MAX_BODY + 1],
        "oversized",
    );
    f.refused(
        41001,
        &["post", "beta", "--subject", "bad\nsubject"],
        b"",
        "malformed",
    );
    f.refused(
        41001,
        &["post", "beta", "--subject", &"x".repeat(1025)],
        b"",
        "malformed",
    );
    f.refused(
        41003,
        &["post", "beta", "--subject", "x"],
        b"",
        "sender uid matches no",
    );
    for args in [
        vec![],
        vec!["unknown"],
        vec!["post"],
        vec!["post", "beta", "bad", "x"],
        vec!["post", "beta", "--subject", "x", "bad"],
        vec!["list", "bad"],
        vec!["read"],
        vec!["read", "x", "bad"],
        vec!["read", "x", "--body", "--body"],
    ] {
        f.refused(41001, &args, b"", "usage:");
    }
    f.refused(41002, &["list", "--peer", "unknown"], b"", "unknown loop");
}

/// ´claim:entry:letters-refuse-claimed-sender-and-unregistered-owner´
/// ´test:unit:letters-refuse-claimed-sender-and-unregistered-owner´
#[test]
fn letters_refuse_claimed_sender_and_unregistered_owner() {
    let f = Fixture::new();
    let name = f.post();
    identity(&f.new_file(&name), 41002, 3001);
    f.refused(41002, &["read", &name], b"", "claimed sender differs");
    assert!(f.new_file(&name).exists());
    identity(&f.new_file(&name), 41003, 3001);
    f.refused(41002, &["read", &name], b"", "sender uid matches no");
}

/// ´claim:entry:letters-refuse-malformed-bounded-records-and-metadata´
/// ´test:unit:letters-refuse-malformed-bounded-records-and-metadata´
#[test]
fn letters_refuse_malformed_bounded_records_and_metadata() {
    let f = Fixture::new();
    let name = f.post();
    let original = fs::read(f.new_file(&name)).expect("record");
    for bytes in [
        b"bad".to_vec(),
        original[..original.len() - 1].to_vec(),
        vec![0; MAX_BODY + 4097],
        [b"LOOP-LETTER 2".as_slice(), &original[13..]].concat(),
    ] {
        f.replace(&name, &bytes);
        let error = f
            .run(41002, &["read", &name], b"")
            .expect_err("malformed or oversized");
        assert_eq!(error.status(), 2);
    }
    f.replace(&name, &original);
    fs::set_permissions(f.new_file(&name), fs::Permissions::from_mode(0o640)).expect("bad mode");
    f.refused(41002, &["read", &name], b"", "malformed file metadata");
    fs::set_permissions(f.new_file(&name), fs::Permissions::from_mode(0o440)).expect("mode");
    fs::hard_link(f.new_file(&name), f.directory.path.join("alias")).expect("hard link");
    f.refused(41002, &["read", &name], b"", "malformed file metadata");
}

/// ´claim:entry:letters-refuse-unsafe-paths-and-inbox-identity-mode´
/// ´test:unit:letters-refuse-unsafe-paths-and-inbox-identity-mode´
#[test]
fn letters_refuse_unsafe_paths_and_inbox_identity_mode() {
    let f = Fixture::new();
    let new = f.directory.path.join(".var/loops/beta/inbox/new");
    fs::set_permissions(&new, fs::Permissions::from_mode(0o730)).expect("bad mode");
    f.refused(
        41001,
        &["post", "beta", "--subject", "x"],
        b"",
        "inbox owner, group or mode",
    );
    fs::set_permissions(&new, fs::Permissions::from_mode(0o1730)).expect("mode");
    identity(&new, 41001, 3001);
    f.refused(
        41001,
        &["post", "beta", "--subject", "x"],
        b"",
        "inbox owner, group or mode",
    );
    identity(&new, 41002, 3001);
    fs::rename(&new, new.with_file_name("parked")).expect("park");
    symlink("parked", &new).expect("linked inbox");
    f.refused(
        41001,
        &["post", "beta", "--subject", "x"],
        b"",
        "unsafe path",
    );
    f.refused(41002, &["read", "../elsewhere"], b"", "malformed");
}

/// ´claim:entry:letters-order-posting-instants-hide-temporary-and-allow-retraction´
/// ´test:unit:letters-order-posting-instants-hide-temporary-and-allow-retraction´
#[test]
fn letters_order_posting_instants_hide_temporary_and_allow_retraction() {
    let f = Fixture::new();
    let first = f.post();
    let second = f.post();
    assert!(parse_name(&first).expect("name").1 <= parse_name(&second).expect("name").1);
    fs::write(f.new_file(".tmp-unpublished"), b"half written").expect("temporary");
    let list = String::from_utf8(f.run(41002, &["list"], b"").expect("list")).expect("lines");
    assert_eq!(list.lines().count(), 2);
    assert!(list.lines().next().expect("first").contains(&first));
    fs::remove_file(f.new_file(&first)).expect("sender retraction fixture");
    let list = String::from_utf8(f.run(41002, &["list"], b"").expect("list")).expect("lines");
    assert_eq!(list.lines().count(), 1);
    assert!(list.contains(&second));
}

/// ´claim:entry:letters-group-ledger-roundtrip-and-collisions´
/// ´test:unit:letters-group-ledger-roundtrip-and-collisions´
#[test]
fn letters_group_ledger_roundtrip_and_collisions() {
    let mut ledger =
        crate::allocations::Allocations::parse("[alpha]\nuids = { base = 65000, count = 536 }\n")
            .expect("ledger");
    assert_eq!(
        ledger
            .ensure_letters_gid(&[41001, 41002, 64999])
            .expect("free group"),
        64998
    );
    let mut copy = crate::allocations::Allocations::parse(&ledger.to_toml()).expect("round trip");
    assert_eq!(copy.letters_gid(), Some(64998));
    assert!(copy.ensure_letters_gid(&[64998]).is_err());
    assert!(!copy.next_block().expect("worker block").contains(64998));
    for value in ["0", "65534", "65536", "'x'", "[]"] {
        assert!(
            crate::allocations::Allocations::parse(&format!("letters_gid = {value}\n")).is_err()
        );
    }
    let conflict = crate::allocations::Allocations::parse(
        "letters_gid = 40000\n[alpha]\nuids = { base = 40000, count = 64 }\n",
    )
    .expect_err("worker group collision");
    assert_eq!(conflict.status(), 2);
    assert!(conflict.message().contains("conflicts with a worker group"));
    let mut exhausted =
        crate::allocations::Allocations::parse("[alpha]\nuids = { base = 1000, count = 64536 }\n")
            .expect("full subordinate range");
    let error = exhausted
        .ensure_letters_gid(&[41001, 41002])
        .expect_err("no group remains");
    assert_eq!(error.status(), 2);
    assert_eq!(error.message(), "letters group range exhausted");
    let mut overflow = crate::allocations::Allocations::default();
    assert_eq!(
        overflow
            .ensure_letters_gid(&[41001, 41002, 65535])
            .expect("skip overflow gid"),
        65533
    );
    let mut blocked_top =
        crate::allocations::Allocations::parse("[alpha]\nuids = { base = 65535, count = 1 }\n")
            .expect("worker occupies top gid");
    assert_eq!(
        blocked_top
            .ensure_letters_gid(&[41001, 41002])
            .expect("skip unmapped gid"),
        65533
    );
}

/// ´claim:entry:letters-private-entry-refuses-invalid-boundary´
/// ´test:unit:letters-private-entry-refuses-invalid-boundary´
#[test]
fn letters_private_entry_refuses_invalid_boundary() {
    let mut output = Vec::new();
    let mut report = Vec::new();
    let error = super::private_entry(&[], &mut output, &mut report)
        .expect_err("missing private entry arguments");
    assert_eq!(error.status(), 2);
    assert_eq!(
        error.message(),
        "letters private entry needs loop and owner home"
    );
    assert_ne!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "fixture runs as a worker identity"
    );
    let arguments = ["alpha", "/unused", "list"].map(String::from);
    let error = super::private_entry(&arguments, &mut output, &mut report)
        .expect_err("private entry requires namespace root before any path access");
    assert_eq!(error.status(), 2);
    assert_eq!(
        error.message(),
        "letters private entry requires namespace root"
    );
    assert_eq!(output, b"");
    assert_eq!(report, b"");
    assert!(super::pin_home(Path::new("relative")).is_err());
    assert!(super::pin_home(Path::new("/..")).is_err());
}

/// ´claim:entry:letters-actions-match-for-dry-and-changing-commands´
/// ´test:unit:letters-actions-match-for-dry-and-changing-commands´
#[test]
fn letters_actions_match_for_dry_and_changing_commands() {
    let f = Fixture::new();
    for dry in [true, false] {
        let mut args = vec!["post", "beta", "--subject", "counts"];
        if dry {
            args.push("--dry-run");
        }
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            command(&f.context(41001), &args, &mut &b"body"[..], &mut Vec::new())
                .expect("post count"),
            1
        );
    }
    let name = f.post();
    for dry in [true, false] {
        let mut args = vec!["read".to_owned(), name.clone()];
        if dry {
            args.push("--dry-run".to_owned());
        }
        assert_eq!(
            command(&f.context(41002), &args, &mut &b""[..], &mut Vec::new()).expect("take count"),
            1
        );
    }
}

/// ´claim:entry:letters-refuse-file-links-directories-wrong-group-and-missing-names´
/// ´test:unit:letters-refuse-file-links-directories-wrong-group-and-missing-names´
#[test]
fn letters_refuse_file_links_directories_wrong_group_and_missing_names() {
    let f = Fixture::new();
    let name = f.post();
    identity(&f.new_file(&name), 41001, 3002);
    f.refused(41002, &["read", &name], b"", "malformed file metadata");
    identity(&f.new_file(&name), 41001, 3001);
    let parked = f.directory.path.join("parked-letter");
    fs::rename(f.new_file(&name), &parked).expect("park letter");
    symlink(&parked, f.new_file(&name)).expect("letter link");
    f.refused(41002, &["read", &name], b"", "unsafe path");
    fs::remove_file(f.new_file(&name)).expect("unlink fixture");
    fs::create_dir(f.new_file(&name)).expect("directory letter");
    identity(&f.new_file(&name), 41001, 3001);
    f.refused(41002, &["read", &name], b"", "malformed file metadata");
    fs::remove_dir(f.new_file(&name)).expect("remove directory");
    assert_eq!(
        f.run(41002, &["read", &name], b"").expect("absent"),
        format!("LETTERS read name={name} absent\n").as_bytes()
    );
    let cur = f
        .directory
        .path
        .join(".var/loops/beta/inbox/cur")
        .join(&name);
    symlink(&parked, &cur).expect("cur link");
    f.refused(41002, &["read", &name], b"", "unsafe path");
}

/// ´claim:entry:letters-codec-refuses-noncanonical-headers-names-and-wrong-receiver´
/// ´test:unit:letters-codec-refuses-noncanonical-headers-names-and-wrong-receiver´
#[test]
fn letters_codec_refuses_noncanonical_headers_names_and_wrong_receiver() {
    let f = Fixture::new();
    let name = f.post();
    let original = fs::read(f.new_file(&name)).expect("record");
    let source = String::from_utf8(original.clone()).expect("text fixture");
    for bytes in [
        source.replace("sender=alpha", "sender=Bad"),
        source.replace("body_bytes=7", "body_bytes=07"),
        source.replace("subject_hex=", "extra=x\nsubject_hex="),
        source.replace("subject_hex=", "subject_hex=z"),
        source.replace("receiver=beta", "receiver=gamma"),
        source.replace("posted_ns=", "posted_ns=0"),
        format!("{source}extra"),
        "x".repeat(4097),
    ] {
        f.replace(&name, bytes.as_bytes());
        assert_eq!(
            f.run(41002, &["read", &name], b"")
                .expect_err("malformed")
                .status(),
            2
        );
    }
    f.replace(&name, &original);
    for bad in [
        "alpha",
        "alpha.0.00",
        ".1.x",
        "alpha.00000000000000000000.00000000000000000000000000000000",
    ] {
        f.refused(41002, &["read", bad], b"", "malformed");
    }
}

/// ´claim:entry:letters-roots-are-standard-and-private-is-unchanged´
/// ´test:unit:letters-roots-are-standard-and-private-is-unchanged´
#[test]
fn letters_roots_are_standard_and_private_is_unchanged() {
    let mut rows = crate::ensure::standard_roots(Path::new("/fixture"), "alpha");
    super::add_roots(&mut rows, Path::new("/fixture"), "alpha", 3001);
    let row = |suffix| {
        rows.iter()
            .find(|row| row.path.ends_with(suffix))
            .expect("standard root")
    };
    assert_eq!(row("alpha/private").mode, 0o700);
    assert_eq!(row("alpha/shared").owner, crate::ensure::RootOwner::Loop);
    assert_eq!(row("inbox/new").mode, 0o1730);
    assert_eq!(row("inbox/cur").owner, crate::ensure::RootOwner::Loop);
    assert_eq!(row("inbox/cur").mode, 0o700);
}

/// ´claim:entry:letters-group-publication-preserves-worker-blocks-and-refuses-unsafe-ledgers´
/// ´test:unit:letters-group-publication-preserves-worker-blocks-and-refuses-unsafe-ledgers´
#[test]
fn letters_group_publication_preserves_worker_blocks_and_refuses_unsafe_ledgers() {
    let home = crate::tests::TestDir::new("letters-ledger");
    fs::set_permissions(&home.path, fs::Permissions::from_mode(0o700)).expect("fixture home mode");
    let inherited = open(
        &home.path,
        OFlag::O_PATH | OFlag::O_DIRECTORY,
        Mode::empty(),
    )
    .expect("inherited owner home");
    let _namespace =
        super::activate_fixture(&home.path, &inherited).expect("activate namespace fixture");
    assert_eq!(
        super::group(&home.path, false).expect("missing configuration"),
        None
    );
    assert!(
        super::group(&home.path, true)
            .expect_err("missing configuration refuses mutation")
            .message()
            .contains("missing owner configuration")
    );
    let config = home.path.join(".config/loops");
    fs::create_dir_all(&config).expect("configuration");
    fs::set_permissions(home.path.join(".config"), fs::Permissions::from_mode(0o700))
        .expect("configuration ancestor mode");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("private config");
    let registry = config.join("registry.toml");
    fs::write(&registry, "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1,0,0]\nloops = [{ name = 'alpha', uid = 41001, launch = 'dev/alpha' }, { name = 'beta', uid = 41002, launch = 'dev/beta' }]\n").expect("registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    let ledger = config.join("allocations.toml");
    fs::write(&ledger, "[alpha]\nuids = { base = 40000, count = 64 }\n").expect("worker ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("ledger mode");
    assert_eq!(
        super::group(&home.path, false).expect("inspect absent grant"),
        None
    );
    let candidate = super::planned_group(&home.path).expect("read-only candidate");
    let gid = super::group(&home.path, true)
        .expect("allocate")
        .expect("group");
    assert_eq!(candidate, Some(gid));
    let bytes = fs::read(&ledger).expect("ledger");
    assert_eq!(super::group(&home.path, true).expect("repeat"), Some(gid));
    assert_eq!(fs::read(&ledger).expect("unchanged"), bytes);
    let parsed = crate::allocations::Allocations::parse(std::str::from_utf8(&bytes).expect("TOML"))
        .expect("preserved ledger");
    assert_eq!(parsed.require("alpha").expect("block").base, 40000);
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert!(
        super::group(&home.path, false)
            .expect_err("mode refusal")
            .message()
            .contains("unsafe allocations")
    );
    fs::remove_file(&ledger).expect("remove fixture ledger");
    symlink(&registry, &ledger).expect("linked ledger");
    assert!(super::group(&home.path, false).is_err());
    fs::remove_file(&ledger).expect("unlink fixture");
    fs::write(&ledger, "letters_gid = 41001\n").expect("colliding grant");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(
        super::group(&home.path, false)
            .expect_err("private group collision")
            .message()
            .contains("conflicts")
    );
    fs::write(&ledger, vec![b'x'; 65537]).expect("oversized ledger");
    assert!(
        super::group(&home.path, false)
            .expect_err("bound")
            .message()
            .contains("oversized")
    );
    fs::write(&ledger, [0xff]).expect("non-UTF-8 ledger");
    let error = super::group(&home.path, false).expect_err("malformed ledger bytes");
    assert_eq!(error.status(), 2);
    assert_eq!(error.message(), "letters malformed allocations.toml");
}

/// ´claim:entry:letters-entry-plan-selects-the-private-dispatch-and-preserves-command-words´
/// ´test:unit:letters-entry-plan-selects-the-private-dispatch-and-preserves-command-words´
#[test]
fn letters_entry_plan_selects_the_private_dispatch_and_preserves_command_words() {
    let f = Fixture::new();
    let plan = |command: &[String]| {
        crate::entry_plan(
            &f.rows[0],
            Path::new("/fixture/entry"),
            Path::new("/fixture"),
            Path::new("/fixture/report"),
            None,
            &["podman".to_owned()],
            command,
            "xterm",
            "C",
            crate::IoMode::Inherit,
        )
    };
    let letters = plan(&["letters", "post", "beta", "--subject", "two words"].map(str::to_owned));
    assert!(letters.inner_script.contains(
        "exec /fixture/entry letters-private alpha /fixture post beta --subject 'two words'"
    ));
    let ordinary = plan(&["printf", "exec setpriv --clear-groups"].map(str::to_owned));
    assert!(
        ordinary
            .inner_script
            .ends_with("printf 'exec setpriv --clear-groups'")
    );
    assert!(ordinary.inner_script.contains("--clear-groups"));
    assert!(!ordinary.inner_script.contains("letters-group"));
}

/// ´claim:entry:letters-publication-refuses-tampered-and-replaced-temporaries´
/// ´test:unit:letters-publication-refuses-tampered-and-replaced-temporaries´
#[test]
fn letters_publication_refuses_tampered_and_replaced_temporaries() {
    for (phase, expected) in [
        ("written", "failed verification"),
        ("verified", "was replaced"),
    ] {
        let f = Fixture::new();
        let directory = f.directory.path.join(".var/loops/beta/inbox/new");
        super::store::RACE.with(|race| {
            *race.borrow_mut() = Some((
                phase,
                Box::new(move || {
                    let temporary = fs::read_dir(&directory)
                        .expect("temporary directory")
                        .next()
                        .expect("temporary")
                        .expect("entry")
                        .path();
                    if phase == "written" {
                        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
                            .expect("writable");
                        fs::write(&temporary, b"tampered").expect("tamper");
                        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o440))
                            .expect("mode");
                    } else {
                        fs::rename(
                            &temporary,
                            directory.parent().expect("inbox").join("parked"),
                        )
                        .expect("substitution");
                        fs::write(&temporary, b"replacement").expect("replace");
                    }
                }),
            ));
        });
        f.refused(
            41001,
            &["post", "beta", "--subject", "race"],
            b"body",
            expected,
        );
        assert_eq!(
            fs::read_dir(f.directory.path.join(".var/loops/beta/inbox/new"))
                .expect("cleaned new")
                .count(),
            0
        );
    }
}

/// ´claim:entry:letters-reader-refuses-mutation-and-inode-substitution-before-output´
/// ´test:unit:letters-reader-refuses-mutation-and-inode-substitution-before-output´
#[test]
fn letters_reader_refuses_mutation_and_inode_substitution_before_output() {
    for (phase, expected) in [
        ("read", "changed while reading"),
        ("taking", "replaced during take"),
    ] {
        let f = Fixture::new();
        let name = f.post();
        let path = f.new_file(&name);
        super::store::RACE.with(|race| {
            *race.borrow_mut() = Some((
                phase,
                Box::new(move || {
                    if phase == "read" {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                            .expect("writable");
                        fs::write(&path, b"changed").expect("mutation");
                    } else {
                        fs::rename(&path, path.with_file_name("parked")).expect("substitution");
                        fs::write(&path, b"replacement").expect("replacement");
                    }
                }),
            ));
        });
        let mut output = Vec::new();
        let error = command(
            &f.context(41002),
            &["read".to_owned(), name],
            &mut &b""[..],
            &mut output,
        )
        .expect_err("race refused");
        assert!(error.message().contains(expected), "{}", error.message());
        assert_eq!(output, b"");
    }
}

/// ´claim:entry:letters-inherited-root-survives-path-substitution´
/// ´test:unit:letters-inherited-root-survives-path-substitution´
#[test]
fn letters_inherited_root_survives_path_substitution() {
    let f = Fixture::new();
    let context = f.context(41001);
    let old = f.directory.path.join(".var/loops/beta");
    let parked = f.directory.path.join("parked-beta");
    // The loop root itself must still carry the expected receiver identity at use.
    fs::rename(&old, &parked).expect("park receiver");
    symlink(&parked, &old).expect("substitute receiver");
    let error = command(
        &context,
        &["post", "beta", "--subject", "race"].map(str::to_owned),
        &mut &b"body"[..],
        &mut Vec::new(),
    )
    .expect_err("link refusal");
    assert!(error.message().contains("unsafe path"));
}

/// ´claim:entry:letters-context-builder-refuses-missing-grants-and-unsafe-roots´
/// ´test:unit:letters-context-builder-refuses-missing-grants-and-unsafe-roots´
#[test]
fn letters_context_builder_refuses_missing_grants_and_unsafe_roots() {
    struct NoCommands;
    impl crate::runner::Runner for NoCommands {
        fn run(
            &mut self,
            _: &crate::planner::CommandSpec,
        ) -> Result<crate::runner::CommandOutput, crate::runner::RunError> {
            panic!("private helper must not launch an external command");
        }
    }
    let f = Fixture::new();
    let ledger = f.directory.path.join(".config/loops/allocations.toml");
    fs::write(&ledger, "").expect("older ledger");
    let failure = super::build_context("alpha", &f.directory.path)
        .err()
        .expect("missing grant");
    assert_eq!(failure.status(), 2);
    assert_eq!(failure.message(), "letters missing letters group");
    let mut output = Vec::new();
    let mut error = Vec::new();
    assert_eq!(
        crate::enter_loop_entry(
            std::ffi::OsStr::new("superloop"),
            [
                std::ffi::OsString::from("letters-group"),
                f.directory.path.as_os_str().to_owned()
            ],
            &mut NoCommands,
            &mut output,
            &mut error,
        ),
        2
    );
    assert_eq!(output, b"");
    assert_eq!(error, b"letters group is not provisioned\n");
    fs::write(&ledger, "letters_gid = 3001\n").expect("restore grant");
    for suffix in [".var", ".var/loops"] {
        let path = f.directory.path.join(suffix);
        let wrong_mode = if suffix == ".var" { 0o700 } else { 0o755 };
        fs::set_permissions(&path, fs::Permissions::from_mode(wrong_mode))
            .expect("wrong root mode");
        let failure = super::build_context("beta", &f.directory.path)
            .err()
            .expect("root refusal");
        assert_eq!(failure.status(), 2);
        assert!(failure.message().starts_with("letters directory mismatch:"));
        assert!(
            failure
                .message()
                .contains(&format!("\"{}\"", path.to_string_lossy().escape_debug()))
        );
        assert!(
            failure
                .message()
                .contains(&format!("mode={wrong_mode:04o}"))
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).expect("restore mode");
    }
    assert!(super::build_context("alpha", &f.directory.path).is_ok());
    let durable = f.directory.path.join(".var");
    let owner = nix::unistd::Uid::effective().as_raw();
    identity(&durable, owner + 1, owner);
    let failure = super::build_context("alpha", &f.directory.path)
        .err()
        .expect("wrong owner refused through injected identity");
    assert_eq!(failure.status(), 2);
    assert!(
        failure
            .message()
            .contains(&format!("\"{}\"", durable.to_string_lossy().escape_debug()))
    );
    assert!(
        failure
            .message()
            .contains(&format!("observed uid={}", owner + 1))
    );
    assert!(
        failure
            .message()
            .contains(&format!("expected directory uid={owner}"))
    );
}

/// ´claim:entry:letters-owner-roots-differ-from-effective-and-loop-identities´
/// ´test:unit:letters-owner-roots-differ-from-effective-and-loop-identities´
#[test]
fn letters_owner_roots_differ_from_effective_and_loop_identities() {
    let f = Fixture::new();
    let effective = nix::unistd::Uid::effective().as_raw();
    let owner = if effective == 0 { 9100 } else { 0 };
    f.owner_identity(owner);
    assert_ne!(owner, effective);
    for uid in [41001, 41002] {
        let context = f.context(uid);
        assert_eq!(context.root_uid, owner);
        assert_ne!(context.root_uid, context.uid);
    }
    assert_eq!(
        super::group(&f.directory.path, false).expect("owner grant"),
        Some(3001)
    );
    let dry = f
        .run(
            41001,
            &["post", "beta", "--subject", "owner proof", "--dry-run"],
            b"report\n",
        )
        .expect("dry post with distinct owner");
    assert!(
        String::from_utf8(dry)
            .expect("dry record")
            .contains("actions=1 dry_run=true")
    );
    let name = f.post();
    let listing = f
        .run(41002, &["list", "--peer", "alpha"], b"")
        .expect("receiver list");
    assert!(String::from_utf8(listing).expect("listing").contains(&name));
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"")
            .expect("receiver take"),
        b"report\n"
    );
    let reply = f
        .run(41002, &["post", "alpha", "--subject", "reply"], b"reply\n")
        .expect("reply post");
    let reply = String::from_utf8(reply).expect("post line");
    let name = reply
        .split_whitespace()
        .find_map(|word| word.strip_prefix("name="))
        .expect("reply name");
    assert_eq!(
        f.run(41001, &["read", name, "--body"], b"")
            .expect("reply take"),
        b"reply\n"
    );
}

/// ´claim:entry:letters-accept-checked-roots-that-inspect-roots-passes´
/// ´test:unit:letters-accept-checked-roots-that-inspect-roots-passes´
#[test]
fn letters_accept_checked_roots_that_inspect_roots_passes() {
    let f = Fixture::new();
    let home = &f.directory.path;
    let owner = fs::metadata(home).expect("owner home");
    let owner = (owner.uid(), owner.gid());
    fs::set_permissions(home.join(".var"), fs::Permissions::from_mode(0o755))
        .expect("host-shaped durable class root");
    fs::create_dir(home.join(".cache")).expect("cache class root");
    fs::set_permissions(home.join(".cache"), fs::Permissions::from_mode(0o711))
        .expect("cache mode");
    for name in ["alpha", "beta"] {
        let private = home.join(".var/loops").join(name).join("private");
        fs::create_dir(&private).expect("existing private tier");
        fs::set_permissions(private, fs::Permissions::from_mode(0o700)).expect("private mode");
        let mut roots = crate::ensure::standard_roots(home, name);
        super::add_roots(&mut roots, home, name, owner.1);
        crate::ensure::ensure_roots(&roots, owner, owner, &mut Vec::new())
            .expect("ensure the actual standard roots");
        assert_eq!(
            crate::ensure::inspect_roots(&roots, owner, owner).status(),
            0
        );
    }
    assert_eq!(
        fs::metadata(home.join(".var"))
            .expect("checked root")
            .mode()
            & 0o7777,
        0o755
    );
    for uid in [41001, 41002] {
        let _context = f.context(uid);
    }
    let name = f.post();
    let listing = String::from_utf8(
        f.run(41002, &["list", "--peer", "alpha"], b"")
            .expect("receiver list"),
    )
    .expect("listing");
    assert!(listing.contains(&format!("new/{name}")));
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"")
            .expect("receiver read"),
        b"report\n"
    );
    let listing =
        String::from_utf8(f.run(41002, &["list"], b"").expect("current list")).expect("listing");
    assert!(listing.contains(&format!("cur/{name}")));
}

/// ´claim:entry:verify-and-letters-name-writable-durable-root-with-distinct-loop-identities´
/// ´test:unit:verify-and-letters-name-writable-durable-root-with-distinct-loop-identities´
#[test]
fn verify_and_letters_name_writable_durable_root_with_distinct_loop_identities() {
    let f = Fixture::new();
    let home = &f.directory.path;
    fs::create_dir(home.join(".cache")).expect("cache class root");
    fs::set_permissions(home.join(".cache"), fs::Permissions::from_mode(0o711))
        .expect("cache mode");
    let metadata = fs::metadata(home).expect("owner home");
    let owner = (metadata.uid(), metadata.gid());
    let path = home.join(".var");
    for row in &f.rows {
        assert_ne!(owner.0, row.uid, "owner and loop must be distinct");
        let roots = crate::ensure::standard_roots(home, &row.name);
        // Inspect the owner-owned class root independently of the injected loop
        // ownership: this fixture models identities, not kernel DAC.
        let class = &roots[..1];
        let loop_id = (row.uid, row.uid);
        assert_eq!(
            crate::ensure::inspect_roots(class, owner, loop_id).status(),
            0
        );
        for mode in [0o775, 0o757, 0o1777] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("writable root");
            let inspection = crate::ensure::inspect_roots(class, owner, loop_id);
            assert_eq!(inspection.status(), 4);
            let reason = format!("mode {mode:04o}, group or other write permission");
            assert!(inspection.observations.iter().any(|observed| {
                observed.path == path
                    && observed.action == crate::ensure::RootAction::Refuse(reason.clone())
            }));
            let report = format!("inspection 4 0 0\n{}\n", inspection.to_json());
            let audit = crate::verify::RootAudit::parse(report.as_bytes()).expect("verify report");
            let json = audit.skipped_json("the ensure step would refuse a home entry", None, None);
            assert!(json.contains(&path.to_string_lossy().to_string()));
            assert!(json.contains(&reason));
            let failure = crate::ensure::ensure_roots(&roots, owner, loop_id, &mut Vec::new())
                .expect_err("entry also refuses the checked root");
            assert_eq!(failure.path, path);
            assert_eq!(failure.reason, reason);
            let failure = super::build_context(&row.name, home)
                .err()
                .expect("letters refusal");
            assert_eq!(failure.status(), 2);
            assert!(
                failure
                    .message()
                    .contains(&path.to_string_lossy().escape_debug().to_string())
            );
            assert!(failure.message().contains("no group or other write"));
            assert_eq!(
                fs::metadata(&path).expect("unchanged root").mode() & 0o7777,
                mode
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("restore root");
        }
    }
}

/// ´claim:entry:letters-directory-refusals-name-observed-and-expected-roots´
/// ´test:unit:letters-directory-refusals-name-observed-and-expected-roots´
#[test]
fn letters_directory_refusals_name_observed_and_expected_roots() {
    let f = Fixture::new();
    let home = &f.directory.path;
    let owner = fs::metadata(home).expect("owner home");
    let (uid, gid) = (owner.uid(), owner.gid());
    for (suffix, observed, expected) in [
        (".var", 0o700, "search for others; no group or other write"),
        (".var", 0o775, "search for others; no group or other write"),
        (".var/loops", 0o755, "0711"),
        (".config/loops", 0o755, "0700"),
    ] {
        let path = home.join(suffix);
        let original = fs::metadata(&path).expect("root").mode() & 0o7777;
        fs::set_permissions(&path, fs::Permissions::from_mode(observed)).expect("invalid mode");
        let error = super::build_context("alpha", home)
            .err()
            .expect("root refusal");
        assert_eq!(error.status(), 2);
        assert_eq!(
            error.message(),
            format!(
                "letters directory mismatch: \"{}\"; observed uid={uid} gid={gid} mode={observed:04o}; expected directory uid={uid} gid={gid} mode={expected}",
                path.to_string_lossy().escape_debug()
            )
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(original)).expect("restore root");
    }
    let path = home.join(".config");
    identity(&path, uid + 1, gid + 1);
    let error = super::build_context("alpha", home)
        .err()
        .expect("configuration ownership refusal");
    assert_eq!(error.status(), 2);
    assert_eq!(
        error.message(),
        format!(
            "letters directory mismatch: \"{}\"; observed uid={} gid={} mode=0700; expected directory uid={uid} gid={gid} mode=any (checked configuration root)",
            path.to_string_lossy().escape_debug(),
            uid + 1,
            gid + 1
        )
    );
    identity(&path, uid, gid + 1);
    let error = super::build_context("alpha", home)
        .err()
        .expect("configuration group refusal");
    assert_eq!(error.status(), 2);
    assert!(
        error
            .message()
            .contains(&format!("observed uid={uid} gid={}", gid + 1))
    );
}

/// ´claim:entry:letters-owner-walks-refuse-caller-owned-substitutions´
/// ´test:unit:letters-owner-walks-refuse-caller-owned-substitutions´
#[test]
fn letters_owner_walks_refuse_caller_owned_substitutions() {
    let f = Fixture::new();
    let effective = nix::unistd::Uid::effective().as_raw();
    let owner = if effective == 0 { 9100 } else { 0 };
    f.owner_identity(owner);
    for suffix in [
        ".config",
        ".config/loops",
        ".config/loops/registry.toml",
        ".config/loops/allocations.toml",
        ".var",
        ".var/loops",
    ] {
        let path = f.directory.path.join(suffix);
        identity(&path, effective, effective);
        let error = super::build_context("alpha", &f.directory.path)
            .err()
            .expect("caller is not owner");
        assert_eq!(error.status(), 2, "{suffix}: {error}");
        assert!(
            error
                .message()
                .contains(if suffix.ends_with("registry.toml") {
                    "unsafe registry"
                } else if suffix.ends_with("allocations.toml") {
                    "unsafe allocations.toml"
                } else {
                    "letters directory mismatch"
                }),
            "{suffix}: {error}"
        );
        identity(&path, owner, owner);
    }
    let receiver_root = f.directory.path.join(".var/loops/beta");
    identity(&receiver_root, effective, effective);
    f.refused(
        41001,
        &["post", "beta", "--subject", "wrong owner"],
        b"body",
        "unsafe loop root",
    );
}

/// ´claim:entry:letters-home-ancestors-use-the-pinned-owner-not-the-caller´
/// ´test:unit:letters-home-ancestors-use-the-pinned-owner-not-the-caller´
#[test]
fn letters_home_ancestors_use_the_pinned_owner_not_the_caller() {
    let f = Fixture::new();
    let effective = nix::unistd::Uid::effective().as_raw();
    let owner = if effective == 0 { 9100 } else { 0 };
    let system = if effective == 9200 { 9201 } else { 9200 };
    let root = f.directory.path.join("ancestor-proof");
    fs::create_dir(&root).expect("fixture root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    identity(&root, system, system);
    for suffix in ["owner", "owner/home"] {
        let path = root.join(suffix);
        fs::create_dir(&path).expect("owned ancestor");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("ancestor mode");
        identity(&path, owner, owner);
    }
    let anchor = open(&root, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).expect("anchor");
    for expected in [None, Some(owner)] {
        let held = super::walk_owner_path(
            nix::unistd::dup(&anchor).expect("duplicate"),
            Path::new("owner/home"),
            expected,
        )
        .expect("recorded owner accepted");
        assert_eq!(super::store::stat(&held).expect("held home").st_uid, owner);
    }
    identity(&root.join("owner"), effective, effective);
    let error = super::walk_owner_path(
        nix::unistd::dup(&anchor).expect("duplicate"),
        Path::new("owner/home"),
        None,
    )
    .expect_err("unrelated ancestor refused");
    assert_eq!(error.status(), 2);
    assert!(
        error
            .message()
            .contains("unsafe owner-home ancestor: owner")
    );
    identity(&root.join("owner"), owner, owner);
    fs::set_permissions(root.join("owner"), fs::Permissions::from_mode(0o777))
        .expect("unsafe mode");
    let error = super::walk_owner_path(anchor, Path::new("owner/home"), Some(owner))
        .expect_err("replaceable ancestor refused");
    assert_eq!(error.status(), 2);
    assert!(
        error
            .message()
            .contains("unsafe owner-home ancestor: owner")
    );
}

/// # Panics
/// Panics only if the isolated fixture or its asserted lock and grant contracts fail.
///
/// ´claim:entry:letters-grants-read-without-locks-and-allocation-rereads-under-both-locks´
/// ´test:unit:letters-grants-read-without-locks-and-allocation-rereads-under-both-locks´
#[test]
fn letters_grants_read_without_locks_and_allocation_rereads_under_both_locks() {
    use nix::fcntl::{Flock, FlockArg};

    // The configuration root is unique, but another test can fork while group()
    // holds its flock. That child shares the open file description until exec,
    // extending the lock past group() returning even with O_CLOEXEC. Keep the
    // free-lock assertions in a process with no concurrent spawning fixtures.
    const FILTER: &str =
        "letters::tests::letters_grants_read_without_locks_and_allocation_rereads_under_both_locks";
    if std::env::var_os("LETTERS_GRANT_LOCK_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([FILTER, "--exact", "--nocapture"])
            .env("LETTERS_GRANT_LOCK_CHILD", "1")
            .output()
            .expect("isolated grant lock fixture");
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "isolated child must execute the exact grant test: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        return;
    }

    let f = Fixture::new();
    let config = f.directory.path.join(".config/loops");
    let ledger = config.join("allocations.toml");
    let directory_lock = Flock::lock(
        fs::File::open(&config).expect("config"),
        FlockArg::LockSharedNonblock,
    )
    .expect("assembly lock");
    let file_lock = Flock::lock(
        fs::File::open(&ledger).expect("ledger"),
        FlockArg::LockExclusiveNonblock,
    )
    .expect("allocator lock");
    let before = fs::read(&ledger).expect("grant bytes");
    assert_eq!(
        super::group(&f.directory.path, true).expect("existing grant ignores locks"),
        Some(3001)
    );
    let name = f.post();
    assert_eq!(
        f.run(41002, &["read", &name, "--body"], b"")
            .expect("entry during assembly"),
        b"report\n"
    );
    assert_eq!(fs::read(&ledger).expect("unchanged"), before);
    fs::write(&ledger, "[alpha]\nuids = { base = 40000, count = 64 }\n").expect("grant absent");
    assert_eq!(
        super::group(&f.directory.path, true)
            .expect_err("configuration lock busy")
            .status(),
        1
    );
    drop(directory_lock);
    assert_eq!(
        super::group(&f.directory.path, true)
            .expect_err("ledger lock busy")
            .status(),
        1
    );
    drop(file_lock);
    let changed = ledger.clone();
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some(("grant-absent", Box::new(move || {
            fs::write(changed, "[alpha]\nuids = { base = 40000, count = 64 }\n[beta]\nuids = { base = 50000, count = 64 }\n").expect("allocator wins before locks");
        })));
    });
    let gid = super::group(&f.directory.path, true)
        .expect("allocate under locks")
        .expect("gid");
    assert_ne!(gid, 65534);
    let parsed =
        crate::allocations::Allocations::parse(&fs::read_to_string(&ledger).expect("ledger"))
            .expect("ledger parse");
    assert_eq!(parsed.require("alpha").expect("first block").base, 40000);
    assert_eq!(parsed.require("beta").expect("racing block").base, 50000);
    fs::write(&ledger, "").expect("grant absent again");
    let changed = ledger.clone();
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some((
            "grant-absent",
            Box::new(move || {
                fs::write(changed, "letters_gid = 3001\n").expect("another entry wins");
            }),
        ));
    });
    assert_eq!(
        super::group(&f.directory.path, true).expect("reread winning grant"),
        Some(3001)
    );
    assert_eq!(
        fs::read(&ledger).expect("winner preserved"),
        b"letters_gid = 3001\n"
    );
}

/// ´claim:entry:letters-read-and-list-handle-retraction-races´
/// ´test:unit:letters-read-and-list-handle-retraction-races´
#[test]
fn letters_read_and_list_handle_retraction_races() {
    for phase in ["before-open", "taking"] {
        let f = Fixture::new();
        let name = f.post();
        let path = f.new_file(&name);
        if phase == "before-open" {
            fs::remove_file(path).expect("retract before open");
        } else {
            super::store::RACE.with(|race| {
                *race.borrow_mut() = Some((
                    "taking",
                    Box::new(move || {
                        fs::remove_file(path).expect("retract before rename");
                    }),
                ));
            });
        }
        let mut output = Vec::new();
        let actions = command(
            &f.context(41002),
            &["read".to_owned(), name.clone()],
            &mut &b""[..],
            &mut output,
        )
        .expect("successful absence outcome");
        assert_eq!(actions, 0);
        assert_eq!(
            output,
            format!("LETTERS read name={name} absent\n").as_bytes()
        );
    }
    let f = Fixture::new();
    let removed = f.post();
    let retained = f.post();
    let path = f.new_file(&removed);
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some((
            "listing",
            Box::new(move || {
                fs::remove_file(path).expect("retract after readdir");
            }),
        ));
    });
    let output = String::from_utf8(
        f.run(41002, &["list"], b"")
            .expect("list skips retracted entry"),
    )
    .expect("listing");
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains(&retained));
    assert!(!output.contains(&removed));
}

/// ´claim:entry:letters-concurrent-takes-at-open-and-rename-return-the-record-with-zero-actions´
/// ´test:unit:letters-concurrent-takes-at-open-and-rename-return-the-record-with-zero-actions´
#[test]
fn letters_concurrent_takes_at_open_and_rename_return_the_record_with_zero_actions() {
    for (phase, prefix) in [
        ("opening", ""),
        ("opening", "new/"),
        ("taking", ""),
        ("taking", "new/"),
    ] {
        let f = Fixture::new();
        let name = f.post();
        let new = f.new_file(&name);
        let cur = new.parent().expect("new").with_file_name("cur").join(&name);
        let source = new.clone();
        let destination = cur.clone();
        super::store::RACE.with(|race| {
            *race.borrow_mut() = Some((
                phase,
                Box::new(move || {
                    fs::rename(source, destination).expect("concurrent receiver take");
                }),
            ));
        });
        let mut output = Vec::new();
        let actions = command(
            &f.context(41002),
            &[
                "read".to_owned(),
                format!("{prefix}{name}"),
                "--body".to_owned(),
            ],
            &mut &b""[..],
            &mut output,
        )
        .expect("read concurrent take");
        assert_eq!(output, b"report\n");
        assert_eq!(actions, 0);
        assert!(!new.exists());
        assert!(cur.exists());
    }
}

/// ´claim:entry:letters-current-letter-disappearance-is-a-runtime-failure´
/// ´test:unit:letters-current-letter-disappearance-is-a-runtime-failure´
#[test]
fn letters_current_letter_disappearance_is_a_runtime_failure() {
    let f = Fixture::new();
    let name = f.post();
    f.run(41002, &["read", &name], b"").expect("take");
    let cur = f
        .new_file(&name)
        .parent()
        .expect("new")
        .with_file_name("cur")
        .join(&name);
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some((
            "opening",
            Box::new(move || {
                fs::remove_file(cur).expect("receiver removes current letter");
            }),
        ));
    });
    let error = f
        .run(41002, &["read", &name], b"")
        .expect_err("current letter disappeared");
    assert_eq!(error.status(), 1);
    assert_eq!(
        error.message(),
        format!("letters IO failure: current letter disappeared: {name}")
    );
}

/// ´claim:entry:letters-concurrent-take-rejects-a-different-inode´
/// ´test:unit:letters-concurrent-take-rejects-a-different-inode´
#[test]
fn letters_concurrent_take_rejects_a_different_inode() {
    let f = Fixture::new();
    let name = f.post();
    let new = f.new_file(&name);
    let cur = new.parent().expect("new").with_file_name("cur").join(&name);
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some((
            "taking",
            Box::new(move || {
                fs::remove_file(new).expect("remove original");
                fs::write(cur, b"replacement").expect("plant another inode");
            }),
        ));
    });
    f.refused(41002, &["read", &name], b"", "letter replaced during take");
}

/// ´claim:entry:letters-never-posted-and-retracted-names-are-both-absent´
/// ´test:unit:letters-never-posted-and-retracted-names-are-both-absent´
#[test]
fn letters_never_posted_and_retracted_names_are_both_absent() {
    let f = Fixture::new();
    let never_posted = "alpha.00000000000000000001.00000000000000000000000000000000";
    assert_eq!(
        f.run(41002, &["read", never_posted], b"")
            .expect("absent unposted name"),
        format!("LETTERS read name={never_posted} absent\n").as_bytes()
    );
    let name = f.post();
    fs::remove_file(f.new_file(&name)).expect("sender unlinks before take");
    assert_eq!(
        f.run(41002, &["read", &name], b"")
            .expect("absent unlinked name"),
        format!("LETTERS read name={name} absent\n").as_bytes()
    );
}

/// ´claim:entry:letters-list-stays-on-the-held-directory-after-replacement´
/// ´test:unit:letters-list-stays-on-the-held-directory-after-replacement´
#[test]
fn letters_list_stays_on_the_held_directory_after_replacement() {
    let f = Fixture::new();
    let name = f.post();
    let new = f.directory.path.join(".var/loops/beta/inbox/new");
    super::store::RACE.with(|race| {
        *race.borrow_mut() = Some((
            "listing",
            Box::new(move || {
                fs::rename(&new, new.with_file_name("parked")).expect("move held directory");
                fs::create_dir(&new).expect("replacement directory");
                fs::write(new.join("malformed"), b"untrusted replacement")
                    .expect("replacement contents");
            }),
        ));
    });
    let output = String::from_utf8(
        f.run(41002, &["list"], b"")
            .expect("held directory listing"),
    )
    .expect("listing");
    assert!(output.starts_with(&format!("new/{name} ")));
}

/// ´claim:entry:letters-stream-failures-are-runtime-errors´
/// ´test:unit:letters-stream-failures-are-runtime-errors´
#[test]
fn letters_stream_failures_are_runtime_errors() {
    struct FailedOutput;
    impl std::io::Write for FailedOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new();
    let error = command(
        &f.context(41001),
        &["post", "beta", "--subject", "x", "--dry-run"].map(String::from),
        &mut &b"body"[..],
        &mut FailedOutput,
    )
    .expect_err("output failure");
    assert_eq!(error.status(), 1);
    assert!(error.message().contains("letters IO failure"));
}

/// ´claim:entry:letters-allocation-refuses-a-replaced-or-disappeared-locked-ledger´
/// ´test:unit:letters-allocation-refuses-a-replaced-or-disappeared-locked-ledger´
#[test]
fn letters_allocation_refuses_a_replaced_or_disappeared_locked_ledger() {
    for replaced in [false, true] {
        let f = Fixture::new();
        let ledger = f.directory.path.join(".config/loops/allocations.toml");
        fs::write(&ledger, "").expect("grant absent");
        super::store::RACE.with(|race| {
            *race.borrow_mut() = Some((
                "grant-locked",
                Box::new(move || {
                    fs::rename(&ledger, ledger.with_file_name("parked-ledger"))
                        .expect("move locked ledger");
                    if replaced {
                        fs::write(&ledger, "letters_gid = 3001\n").expect("replacement ledger");
                        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600))
                            .expect("replacement mode");
                    }
                }),
            ));
        });
        let error = super::group(&f.directory.path, true).expect_err("locked inode lost its name");
        assert_eq!(error.status(), if replaced { 2 } else { 1 });
        assert!(error.message().contains(if replaced {
            "replaced before allocation"
        } else {
            "disappeared under lock"
        }));
    }
}
