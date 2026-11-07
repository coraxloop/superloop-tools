use super::*;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "anchor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("fixture directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        Self(path)
    }
    fn file(&self, name: &str, bytes: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).expect("fixture file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("file mode");
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}
fn policy(kind: Kind) -> Policy {
    Policy {
        kind,
        owner: Owner::Host,
        mode: ModePolicy::Exact(if kind == Kind::Directory {
            0o700
        } else {
            0o600
        }),
    }
}
fn bundle(
    path: &Path,
    purpose: &str,
    selected: Policy,
) -> (Manifest, Vec<OwnedFd>, Vec<Requirement>) {
    let pin = HostVerifier::current()
        .expect("host verifier")
        .pin(path, purpose, 0, selected)
        .expect("host pin");
    (
        Manifest {
            version: 1,
            transport: Transport::Rights,
            operation: "fixture".into(),
            loop_name: "alpha".into(),
            records: vec![pin.record()],
        },
        vec![pin.into_fd()],
        vec![Requirement {
            purpose: purpose.into(),
            policy: selected,
            alias_group: None,
        }],
    )
}
fn validate(
    manifest: &Manifest,
    fds: Vec<OwnedFd>,
    required: &[Requirement],
) -> Result<Vec<Anchor>> {
    Receiver::current()?.validate(
        manifest,
        fds,
        "fixture",
        "alpha",
        manifest.transport,
        required,
    )
}

/// # Panics
/// Panics if the manifest admits an undeclared authority or malformed shape.
/// ´claim:loophome:anchor-manifest-is-bounded-and-operation-bound´
/// ´test:unit:anchor-manifest-is-bounded-and-operation-bound´
#[test]
fn anchor_manifest_is_bounded_and_operation_bound() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    let (m, fds, required) = bundle(&path, "input", policy(Kind::File));
    let source = serde_json::to_string(&m).expect("manifest");
    Manifest::parse(&source).expect("valid");
    for text in [
        source.replacen('{', "{\"extra\":1,", 1),
        source.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        " ".repeat(MAX_MANIFEST + 1),
    ] {
        assert_eq!(
            Manifest::parse(&text).expect_err("malformed").kind,
            "anchor-declaration"
        );
    }
    let mut changed = m.clone();
    changed.operation = "other".into();
    assert_eq!(
        validate(&changed, fds, &required)
            .expect_err("operation")
            .kind,
        "anchor-declaration"
    );
    for mutate in [0, 1, 2, 3] {
        let mut changed = m.clone();
        match mutate {
            0 => changed.records.push(changed.records[0].clone()),
            1 => changed.records[0].slot = 64,
            2 => changed.version = 2,
            _ => changed.records = vec![changed.records[0].clone(); MAX_ANCHORS + 1],
        }
        assert_eq!(
            changed.check().expect_err("bad shape").kind,
            "anchor-declaration"
        );
    }
}

/// # Panics
/// Panics if a named custody refusal is lost.
/// ´claim:loophome:anchor-bundle-refuses-missing-substituted-kind-owner-and-mode´
/// ´test:unit:anchor-bundle-refuses-missing-substituted-kind-owner-and-mode´
#[test]
fn anchor_bundle_refuses_missing_substituted_kind_owner_and_mode() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    let other = fixture.file("other", "other");
    let (m, fds, required) = bundle(&path, "input", policy(Kind::File));
    drop(fds);
    assert_eq!(
        validate(&m, vec![], &required).expect_err("missing").kind,
        "anchor-missing"
    );
    assert_eq!(
        validate(
            &m,
            vec![File::open(&other).expect("other").into()],
            &required
        )
        .expect_err("substitution")
        .kind,
        "anchor-identity"
    );
    let dir = open(&fixture.0, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty()).expect("directory");
    assert_eq!(
        validate(&m, vec![dir], &required).expect_err("kind").kind,
        "anchor-kind"
    );
    let mut wrong = m.clone();
    wrong.records[0].owner_uid += 1;
    assert_eq!(
        validate(
            &wrong,
            vec![File::open(&path).expect("file").into()],
            &required
        )
        .expect_err("owner")
        .kind,
        "anchor-owner"
    );
    let mut wrong = m.clone();
    wrong.records[0].inode += 1;
    assert_eq!(
        validate(
            &wrong,
            vec![File::open(&path).expect("file").into()],
            &required
        )
        .expect_err("declaration identity")
        .kind,
        "anchor-identity"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("unsafe mode");
    assert_eq!(
        validate(&m, vec![File::open(&path).expect("file").into()], &required)
            .expect_err("mode")
            .kind,
        "anchor-mode"
    );
}

/// # Panics
/// Panics if inherited numbers or aliases grant undeclared authority.
/// ´claim:loophome:anchor-inheritance-validates-identities-and-aliases´
/// ´test:unit:anchor-inheritance-validates-identities-and-aliases´
#[test]
fn anchor_inheritance_validates_identities_and_aliases() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    let (mut m, mut fds, mut required) = bundle(&path, "input", policy(Kind::File));
    let second = fds[0].try_clone().expect("second");
    let mut record = m.records[0].clone();
    record.purpose = "alias".into();
    record.slot = 1;
    m.records.push(record);
    required.push(Requirement {
        purpose: "alias".into(),
        policy: policy(Kind::File),
        alias_group: None,
    });
    fds.push(second);
    assert_eq!(
        validate(&m, fds, &required)
            .expect_err("unapproved alias")
            .kind,
        "anchor-declaration"
    );
    for r in &mut required {
        r.alias_group = Some("same-input".into());
    }
    let first: OwnedFd = File::open(&path).expect("first").into();
    let second = first.try_clone().expect("second");
    m.transport = Transport::Inherit;
    m.records[0].slot = u32::try_from(first.as_raw_fd()).expect("fd");
    m.records[1].slot = u32::try_from(second.as_raw_fd()).expect("fd");
    let anchors = validate(&m, vec![first, second], &required).expect("authorized aliases");
    for anchor in anchors {
        let flags =
            nix::fcntl::fcntl(&anchor, nix::fcntl::FcntlArg::F_GETFD).expect("descriptor flags");
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}

/// # Panics
/// Panics if a path escape or ACL widening is admitted.
/// ´claim:loophome:anchor-confined-opens-preserve-acl-custody´
/// ´test:unit:anchor-confined-opens-preserve-acl-custody´
#[test]
fn anchor_confined_opens_preserve_acl_custody() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    crate::mail::acl::install(&File::open(&fixture.0).expect("directory"), 31000, true)
        .expect("directory ACL");
    crate::mail::acl::install(&File::open(&path).expect("file"), 31000, false).expect("file ACL");
    let (m, fds, required) = bundle(&fixture.0, "configuration", policy(Kind::Directory));
    let anchor = validate(&m, fds, &required).expect("directory").remove(0);
    anchor
        .open_beneath(Path::new("file"), policy(Kind::File), 0o700)
        .expect("read ACL");
    symlink(&path, fixture.0.join("link")).expect("link");
    for path in ["../file", "/file", "a/../file", "./file", "link", "a//file"] {
        assert_eq!(
            anchor
                .open_beneath(Path::new(path), policy(Kind::File), 0o700)
                .expect_err("escape")
                .kind,
            "anchor-escape"
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("widen mask");
    assert_eq!(
        anchor
            .open_beneath(Path::new("file"), policy(Kind::File), 0o700)
            .expect_err("mask")
            .kind,
        "anchor-mode"
    );
}

/// # Panics
/// Panics if the anchored reader reopens the old path or omits registry validation.
/// ´claim:loophome:anchor-ledger-and-registry-share-one-capability´
/// ´test:unit:anchor-ledger-and-registry-share-one-capability´
#[test]
fn anchor_ledger_and_registry_share_one_capability() {
    let mut fixture = Fixture::new();
    fixture.file("registry.toml", "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n");
    fixture.file(
        "allocations.toml",
        "[alpha]\nuids = { base = 42000, count = 8 }\n",
    );
    let (m, fds, required) = bundle(&fixture.0, "configuration", policy(Kind::Directory));
    let anchor = validate(&m, fds, &required)
        .expect("configuration")
        .remove(0);
    let old = fixture.0.clone();
    let renamed = old.with_extension("moved");
    fs::rename(&old, &renamed).expect("rename protected directory");
    fixture.0 = renamed;
    anchor
        .read_configuration(&old, false)
        .expect("both reads use capabilities");
    fixture.file(
        "allocations.toml",
        "[alpha]\nuids = { base = 41001, count = 8 }\n",
    );
    let error = anchor
        .read_configuration(&old, false)
        .expect_err("registry UID collision");
    assert_eq!(error.kind, "anchor-declaration");
    assert!(
        error.to_string().contains(
            "check=registry-ledger-binding: worker uids for loop alpha contain registered uid 41001"
        ),
        "{error}"
    );
    fs::remove_file(fixture.0.join("allocations.toml")).expect("remove ledger");
    anchor
        .read_configuration(&old, true)
        .expect("optional ledger after registry check");
    fs::remove_file(fixture.0.join("registry.toml")).expect("remove registry");
    assert_eq!(
        anchor
            .read_configuration(&old, true)
            .expect_err("registry is mandatory")
            .kind,
        "anchor-missing"
    );
}

/// # Panics
/// Panics if an overflow representation alone authorizes a child or directory.
/// ´claim:loophome:anchor-root-file-proof-does-not-authorize-overflow-walks´
/// ´test:unit:anchor-root-file-proof-does-not-authorize-overflow-walks´
#[test]
fn anchor_root_file_proof_does_not_authorize_overflow_walks() {
    let fixture = Fixture::new();
    let fd = File::open(fixture.file("file", "fixture")).expect("file");
    let mut stat = fstat(&fd).expect("stat");
    stat.st_uid = 65534;
    let view = View {
        owners: Owners::parse("0 1000 1\n1 100000 65536\n", 0, 65534).expect("partial map"),
        host_uid: 1000,
    };
    let p = Policy {
        kind: Kind::File,
        owner: Owner::RootFile,
        mode: ModePolicy::Exact(0o600),
    };
    check_owner(&view, &stat, p, 0, true, "fixture", "system").expect("held root file proof");
    assert_eq!(
        check_owner(&view, &stat, p, 0, false, "fixture", "child")
            .expect_err("no proof")
            .kind,
        "anchor-owner"
    );
    assert_eq!(
        check_owner(
            &view,
            &stat,
            Policy {
                kind: Kind::Directory,
                ..p
            },
            0,
            true,
            "fixture",
            "directory"
        )
        .expect_err("no root directory exemption")
        .kind,
        "anchor-owner"
    );
    let ordinary = Policy {
        kind: Kind::File,
        owner: Owner::Mapped(65534),
        mode: ModePolicy::Exact(0o600),
    };
    assert_eq!(
        check_owner(&view, &stat, ordinary, 165_533, true, "fixture", "ordinary")
            .expect_err("ambiguous grant")
            .kind,
        "anchor-owner"
    );
}

/// # Panics
/// Panics if the rights control buffer truncates a valid 64-descriptor bundle.
/// ´claim:loophome:anchor-rights-count-sizes-the-control-buffer´
/// ´test:unit:anchor-rights-count-sizes-the-control-buffer´
#[test]
fn anchor_rights_count_sizes_the_control_buffer() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    let fds: Vec<OwnedFd> = (0..MAX_ANCHORS)
        .map(|_| File::open(&path).expect("file").into())
        .collect();
    let (sender, receiver) = UnixStream::pair().expect("pair");
    transport::send(&sender, &fds).expect("send");
    let handles =
        transport::receive(&receiver, MAX_ANCHORS, Duration::from_secs(2)).expect("all rights");
    assert_eq!(handles.len(), MAX_ANCHORS);
    for fd in handles {
        assert_eq!(
            fstat(&fd).expect("received").st_ino,
            fs::metadata(&path).expect("path").ino()
        );
        assert_ne!(
            nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFD).expect("flags")
                & libc::FD_CLOEXEC,
            0
        );
    }
}

/// # Panics
/// Panics if truncation, count mismatch, extra data or an absent EOF is accepted.
/// ´claim:loophome:anchor-rights-refuse-malformed-or-incomplete-frames´
/// ´test:unit:anchor-rights-refuse-malformed-or-incomplete-frames´
#[test]
fn anchor_rights_refuse_malformed_or_incomplete_frames() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    for count in [0, 1, 2] {
        let (mut sender, receiver) = UnixStream::pair().expect("pair");
        let fds: Vec<OwnedFd> = (0..64)
            .map(|_| File::open(&path).expect("file").into())
            .collect();
        if count == 0 {
            sender.write_all(&[2]).expect("extra byte");
        }
        transport::send(&sender, &fds).expect("send");
        assert_eq!(
            transport::receive(&receiver, count, Duration::from_secs(1))
                .expect_err("malformed")
                .kind,
            "anchor-transport"
        );
    }
    let (sender, receiver) = UnixStream::pair().expect("pair");
    drop(sender);
    assert_eq!(
        transport::receive(&receiver, 1, Duration::from_secs(1))
            .expect_err("missing")
            .kind,
        "anchor-transport"
    );
}

/// # Panics
/// Panics if a partial map can become a host verifier.
/// ´claim:loophome:anchor-host-verifier-requires-one-identity-range´
/// ´test:unit:anchor-host-verifier-requires-one-identity-range´
#[test]
fn anchor_host_verifier_requires_one_identity_range() {
    for source in ["0 1000 1", "0 0 1\n1 1 4294967294"] {
        let view = View {
            owners: Owners::parse(source, 0, 65534).expect("valid map"),
            host_uid: 0,
        };
        assert_eq!(
            HostVerifier::from_view(view)
                .expect_err("not initial map")
                .kind,
            "anchor-uid-map"
        );
    }
    HostVerifier::current().expect("live host map");
}

/// # Panics
/// Panics if trailing messages or an unclosed sender escape the receive deadline, or a refused frame leaves a descriptor open.
/// ´claim:loophome:anchor-rights-require-bounded-eof´
/// ´test:unit:anchor-rights-require-bounded-eof´
#[test]
fn anchor_rights_require_bounded_eof() {
    let fixture = Fixture::new();
    let file: OwnedFd = File::open(fixture.file("file", "fixture"))
        .expect("file")
        .into();
    let (mut sender, receiver) = UnixStream::pair().expect("pair");
    transport::send_frame(&sender, &[file.try_clone().expect("clone")]).expect("frame");
    sender.write_all(&[2]).expect("second message");
    sender.shutdown(std::net::Shutdown::Write).expect("EOF");
    assert_eq!(
        transport::receive(&receiver, 1, Duration::from_secs(1))
            .expect_err("extra message")
            .kind,
        "anchor-transport"
    );
    let (sender, receiver) = UnixStream::pair().expect("pair");
    transport::send_frame(&sender, &[file]).expect("frame");
    assert_eq!(
        transport::receive(&receiver, 1, Duration::from_millis(10))
            .expect_err("no EOF")
            .kind,
        "anchor-transport"
    );
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    nix::fcntl::fcntl(&reader, nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
        .expect("nonblocking reader");
    let copy = || -> OwnedFd { writer.try_clone().expect("writer copy").into() };
    let (sender, receiver) = UnixStream::pair().expect("pair");
    transport::send_frame(&sender, &[copy()]).expect("first frame");
    transport::send(&sender, &[copy()]).expect("second frame");
    assert_eq!(
        transport::receive(&receiver, 1, Duration::from_secs(1))
            .expect_err("second frame")
            .kind,
        "anchor-transport"
    );
    let (sender, receiver) = UnixStream::pair().expect("pair");
    transport::send(&sender, &[copy(), copy(), copy()]).expect("excess frame");
    assert_eq!(
        transport::receive(&receiver, 1, Duration::from_secs(1))
            .expect_err("excess descriptors")
            .kind,
        "anchor-transport"
    );
    drop(writer);
    let mut byte = [0_u8];
    // A concurrent test's fork may hold a copy until its exec; a leak never clears.
    let began = std::time::Instant::now();
    while reader.read(&mut byte).is_err() && began.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(reader.read(&mut byte).expect("refused copies closed"), 0);
}

/// # Panics
/// Panics if declaration-supplied owner claims can replace the configuration grant.
/// ´claim:loophome:anchor-configuration-precedes-loop-owner-authorization´
/// ´test:unit:anchor-configuration-precedes-loop-owner-authorization´
#[test]
fn anchor_configuration_precedes_loop_owner_authorization() {
    let fixture = Fixture::new();
    fixture.file("registry.toml", "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n");
    let input = fixture.file("input", "fixture");
    let (mut manifest, mut fds, mut required) =
        bundle(&fixture.0, "configuration", policy(Kind::Directory));
    let pin = HostVerifier::current()
        .expect("host")
        .pin(
            &input,
            "loop-input",
            1,
            Policy {
                owner: Owner::Mapped(41001),
                ..policy(Kind::File)
            },
        )
        .expect("record deferred leaf owner");
    manifest.records.push(pin.record());
    fds.push(pin.into_fd());
    let receiver = Receiver::current().expect("receiver");
    let configuration = receiver
        .configuration(
            &manifest,
            &fds,
            Entry {
                operation: "fixture",
                loop_name: "alpha",
                transport: Transport::Rights,
            },
            &fixture.0,
            true,
        )
        .expect("bootstrap registry");
    let uid = configuration.registry.rows(&fixture.0)[0].uid;
    assert_eq!(uid, 41001);
    required.push(Requirement {
        purpose: "loop-input".into(),
        policy: Policy {
            owner: Owner::Mapped(uid),
            ..policy(Kind::File)
        },
        alias_group: None,
    });
    let held: Vec<OwnedFd> = fds
        .iter()
        .map(|fd| fd.try_clone().expect("held copy"))
        .collect();
    assert_eq!(
        validate(&manifest, fds, &required)
            .expect_err("leaf belongs to host, not granted loop")
            .kind,
        "anchor-owner"
    );
    manifest.records[1].owner_uid = uid;
    assert_eq!(
        validate(&manifest, held, &required)
            .expect_err("declared owner is not the live owner")
            .kind,
        "anchor-owner"
    );
}

/// # Panics
/// Panics if a link or writable host ancestor is pinned.
/// ´claim:loophome:anchor-host-walk-refuses-links-and-writable-parents´
/// ´test:unit:anchor-host-walk-refuses-links-and-writable-parents´
#[test]
fn anchor_host_walk_refuses_links_and_writable_parents() {
    let fixture = Fixture::new();
    let path = fixture.file("file", "fixture");
    let directory = fixture.0.join("directory");
    fs::create_dir(&directory).expect("directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("mode");
    symlink(&directory, fixture.0.join("link")).expect("link");
    let verifier = HostVerifier::current().expect("host");
    assert_eq!(
        verifier
            .pin(&fixture.0.join("link/file"), "input", 0, policy(Kind::File))
            .expect_err("link")
            .kind,
        "anchor-escape"
    );
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o722)).expect("unsafe parent");
    assert_eq!(
        verifier
            .pin(&path, "input", 0, policy(Kind::File))
            .expect_err("parent")
            .kind,
        "anchor-mode"
    );
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).expect("restore parent");
}

/// # Panics
/// Panics if an executable is not pinned `O_PATH` or defers its ownership proof.
/// ´claim:loophome:anchor-executable-pins-require-host-owner-proof´
/// ´test:unit:anchor-executable-pins-require-host-owner-proof´
#[test]
fn anchor_executable_pins_require_host_owner_proof() {
    let fixture = Fixture::new();
    let path = fixture.file("program", "fixture bytes are not executed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable mode");
    let executable = Policy {
        kind: Kind::File,
        owner: Owner::Host,
        mode: ModePolicy::Executable,
    };
    let (manifest, fds, required) = bundle(&path, "program", executable);
    let anchor = validate(&manifest, fds, &required)
        .expect("executable pin")
        .remove(0);
    assert_ne!(
        nix::fcntl::fcntl(&anchor, nix::fcntl::FcntlArg::F_GETFL).expect("flags") & libc::O_PATH,
        0
    );
    assert_eq!(
        HostVerifier::current()
            .expect("host")
            .pin(
                &path,
                "program",
                0,
                Policy {
                    owner: Owner::Mapped(41001),
                    ..executable
                }
            )
            .expect_err("deferred executable owner")
            .kind,
        "anchor-owner"
    );
}

/// # Panics
/// Panics if ownership, mode, syscall or transport failures lose their distinct cause.
/// ´claim:loophome:anchor-refusals-retain-the-failed-check´
/// ´test:unit:anchor-refusals-retain-the-failed-check´
#[test]
fn anchor_refusals_retain_the_failed_check() {
    let fixture = Fixture::new();
    let child = fixture.file("child", "payload");
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o770)).expect("writable ancestor");
    let host = HostVerifier::current()
        .expect("host")
        .for_operation("mail-serve");
    let error = host
        .pin(&child, "configuration", 0, policy(Kind::File))
        .expect_err("ancestor mode");
    assert_eq!(error.kind, "anchor-mode");
    assert!(
        error
            .to_string()
            .contains("operation=mail-serve purpose=configuration check=ancestor-mode"),
        "{error}"
    );
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).expect("restore");
    let fd = host
        .pin(&fixture.0, "configuration", 0, policy(Kind::Directory))
        .expect("directory")
        .into_fd();
    let error = open_component(
        &fd,
        Path::new(&"x".repeat(4096)),
        policy(Kind::File),
        "mail-serve",
        "configuration",
    )
    .expect_err("name limit");
    assert_eq!(error.kind, "anchor-io");
    assert!(
        error.to_string().contains("check=openat2: ENAMETOOLONG"),
        "{error}"
    );
    let (sender, receiver) = UnixStream::pair().expect("socket");
    transport::send(&sender, &[]).expect("empty frame");
    let error = transport::receive(&receiver, 1, Duration::from_secs(1))
        .expect_err("missing rights")
        .context("mail-serve", "rights");
    assert_eq!(error.kind, "anchor-transport");
    assert!(
        error.to_string().contains(
            "operation=mail-serve purpose=rights check=rights-frame: expected=1 received=0"
        ),
        "{error}"
    );
}

/// # Panics
/// Panics if registry and ledger schema failures lose their parser-specific cause.
/// ´claim:loophome:anchor-configuration-refusals-retain-parser-causes´
/// ´test:unit:anchor-configuration-refusals-retain-parser-causes´
#[test]
fn anchor_configuration_refusals_retain_parser_causes() {
    let fixture = Fixture::new();
    let (manifest, fds, required) = bundle(&fixture.0, "configuration", policy(Kind::Directory));
    let anchor = validate(&manifest, fds, &required)
        .expect("configuration")
        .remove(0);
    fixture.file("registry.toml", "invalid TOML");
    let error = anchor
        .read_configuration(&fixture.0, false)
        .expect_err("registry schema");
    assert!(
        error.to_string().contains("check=registry-parse:"),
        "{error}"
    );
    fixture.file(
        "registry.toml",
        "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[]\n",
    );
    fixture.file("allocations.toml", "invalid TOML");
    let error = anchor
        .read_configuration(&fixture.0, false)
        .expect_err("ledger schema");
    assert!(
        error
            .to_string()
            .contains("check=ledger-parse: malformed allocations.toml"),
        "{error}"
    );
}

/// # Panics
/// Panics if execution reopens a removed pathname or falls back for an unsupported script.
/// ´claim:loophome:anchor-exec-retains-the-held-file´
/// ´test:unit:anchor-exec-retains-the-held-file´
#[test]
fn anchor_exec_retains_the_held_file() {
    let fixture = Fixture::new();
    let path = fixture.0.join("image");
    fs::copy("/usr/bin/true", &path).expect("native fixture image");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable mode");
    let selected = Policy {
        kind: Kind::File,
        owner: Owner::Host,
        mode: ModePolicy::Executable,
    };
    let (manifest, fds, required) = bundle(&path, "executable", selected);
    let anchor = validate(&manifest, fds, &required)
        .expect("anchor")
        .remove(0);
    fs::remove_file(&path).expect("remove pathname");
    let mut command = std::process::Command::new(&path);
    assert_eq!(
        anchor
            .configure_exec(&mut command, &[], &[])
            .expect_err("empty argv")
            .kind,
        "anchor-exec"
    );
    anchor
        .configure_exec(&mut command, &["held-image".into()], &[])
        .expect("descriptor exec");
    assert!(command.status().expect("held execution").success());

    let path = fixture.file("script", "#!/bin/sh\nexit 0\n");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("script mode");
    let (manifest, fds, required) = bundle(&path, "executable", selected);
    let anchor = validate(&manifest, fds, &required)
        .expect("anchor")
        .remove(0);
    let mut command = std::process::Command::new(&path);
    anchor
        .configure_exec(&mut command, &["unsupported-script".into()], &[])
        .expect("prepared refusal");
    assert!(
        command.status().is_err(),
        "an unpinned interpreter must not execute by fallback"
    );
}

/// # Panics
/// Panics if consumed transport stdin is absent, is not the null device or supplies input.
fn null_input_reference() -> File {
    transport::replace_stdin("fixture").expect("replace consumed stdin");
    let actual = fstat(std::io::stdin().as_fd()).expect("stdin identity before any new open");
    let null = File::open("/dev/null").expect("null identity");
    assert!(
        null.as_raw_fd() > 2,
        "reference open must not fill vacant stdio"
    );
    let expected = fstat(&null).expect("null identity");
    assert_eq!(
        (actual.st_dev, actual.st_ino),
        (expected.st_dev, expected.st_ino)
    );
    assert_eq!(
        std::io::stdin().read(&mut [0_u8; 1]).expect("null input"),
        0
    );
    null
}

/// # Panics
/// Panics if descriptor exhaustion loses its named cause or consumed stdin can become a capability slot.
/// ´claim:loophome:anchor-descriptor-system-failures-retain-their-cause´
/// ´test:unit:anchor-descriptor-system-failures-retain-their-cause´
#[test]
#[allow(unsafe_code)]
fn anchor_descriptor_system_failures_retain_their_cause() {
    const CHILD: &str = "SUPERLOOP_ANCHOR_DESCRIPTOR_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "anchor::tests::anchor_descriptor_system_failures_retain_their_cause",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated descriptor fixture");
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let null = null_input_reference();
    let ceiling = u64::try_from(null.as_raw_fd()).expect("null descriptor") + 1;
    let fixture = Fixture::new();
    let file = File::open(fixture.file("child", "held")).expect("later descriptor");
    assert!(file.as_raw_fd() > 2);
    let (manifest, descriptors, required) =
        bundle(&fixture.0, "configuration", policy(Kind::Directory));
    let dir = validate(
        &manifest,
        descriptors
            .iter()
            .map(|fd| fd.try_clone().expect("copy"))
            .collect(),
        &required,
    )
    .expect("directory anchor")
    .remove(0);
    let image = fixture.0.join("image");
    fs::copy("/usr/bin/true", &image).expect("native image");
    fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).expect("executable mode");
    let (executable, fds, required) = bundle(
        &image,
        "executable",
        Policy {
            kind: Kind::File,
            owner: Owner::Host,
            mode: ModePolicy::Executable,
        },
    );
    let executable = validate(&executable, fds, &required)
        .expect("executable anchor")
        .remove(0);
    let receiver = Receiver::current().expect("receiver map");
    let mut command = std::process::Command::new(&image);
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: this test runs in its own subprocess, the pointers are live, and
    // only the soft limit changes; restore it before assertions or reporting.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut old), 0);
        let limited = libc::rlimit {
            rlim_cur: ceiling,
            rlim_max: old.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limited), 0);
    }
    let relay = dir.relay();
    let child = dir.open_beneath(Path::new("child"), policy(Kind::File), 0o700);
    let exec = executable.configure_exec(&mut command, &["held-image".into()], &[]);
    let configuration = receiver.configuration(
        &manifest,
        &descriptors,
        Entry {
            operation: "fixture",
            loop_name: "alpha",
            transport: Transport::Rights,
        },
        &fixture.0,
        false,
    );
    // SAFETY: the saved limit belongs to this isolated process and remains valid.
    unsafe {
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &raw const old), 0);
    }
    for (error, check) in [
        (relay.expect_err("relay exhaustion"), "relay-duplicate"),
        (child.expect_err("child exhaustion"), "child-duplicate"),
        (exec.expect_err("exec exhaustion"), "exec-duplicate"),
        (
            configuration.expect_err("configuration exhaustion"),
            "configuration-duplicate",
        ),
    ] {
        assert_eq!(error.kind, "anchor-io", "{error}");
        assert!(error.to_string().contains(check), "{error}");
        assert!(
            error
                .to_string()
                .contains(&format!("os error {}", libc::EMFILE)),
            "{error}"
        );
    }
}
