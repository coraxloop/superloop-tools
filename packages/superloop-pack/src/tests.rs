//! # `superloop-pack` library test matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Archive construction | 3 | Object-database exclusions, dirty checkout, and moved tag |
//! | Verification | 15 | Register binding, activation prerequisites, precise refusal families, and real-linter pack round trips, growth, debt, and kept private values |

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Mutex, PoisonError};

use serde_json::json;

use super::{
    BuildRefusal, BuildRequest, BuildStage, CheckEvidence, CheckOutcome, MANIFEST_PATH,
    VerifyCheck, VerifyRefusal, VerifyRequest, audit_archive, build, build_with_hook,
    extract_archive, path_option, read_manifest, run_git, run_git_archive, sha256_bytes,
    sha256_file, verify,
};

const TAG: &str = "release-1";

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// For output callers with unconfigured streams, library/std/src/process.rs documents inherited stdio for spawn and noninherited stdin for output (lines 1063, 1095-1096, 1103, 1138-1139), library/std/src/sys/process/mod.rs selects `MakePipe` (lines 54-57), and library/std/src/sys/process/unix/common.rs selects null stdin (lines 358-365).
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn write_executable(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[allow(dead_code)]
fn spawn_serialized(command: &mut Command) -> std::io::Result<Child> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

/// Production spawn boundaries cannot take this test lock, so it stays held through each production call and its wait.
fn with_process_lock<T>(action: impl FnOnce() -> T) -> T {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    action()
}
const REGISTER: &str = concat!(
    "values = [\n",
    "  { value = \"sagofink\", match = \"identifier\" },\n",
    "  { value = \"example-loop\", match = \"substring\" },\n",
    "]\n",
);

struct Fixture {
    temporary: tempfile::TempDir,
    repository: PathBuf,
    burn_register: PathBuf,
    pack: PathBuf,
    commit: String,
    tree: String,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("fixture temporary root");
        let repository = temporary.path().join("fictional-repository");
        fs::create_dir(&repository).expect("fixture repository");
        git_ok(&repository, &["init", "-q"]);
        git_ok(
            &repository,
            &["config", "user.name", "Fictional Pack Builder"],
        );
        git_ok(
            &repository,
            &["config", "user.email", "builder@example.invalid"],
        );
        fs::create_dir(repository.join("docs")).expect("fixture docs");
        fs::create_dir(repository.join("local")).expect("fixture local");
        fs::write(repository.join(".gitignore"), "ignored.txt\n").expect("ignore fixture");
        fs::write(repository.join("tracked.txt"), "tagged bytes\n").expect("tracked fixture");
        fs::write(repository.join("docs/guide.md"), "# Fictional guide\n").expect("guide fixture");
        let burn_register = repository.join("local/burn-register.toml");
        fs::write(&burn_register, REGISTER).expect("burn fixture");
        fs::write(repository.join("ignored.txt"), "ignored bytes\n").expect("ignored fixture");
        git_ok(&repository, &["add", "-A"]);
        git_ok(&repository, &["commit", "-qm", "fictional source"]);
        git_ok(&repository, &["tag", TAG]);
        let commit = git_line_test(&repository, &["rev-parse", "HEAD"]);
        let tree = git_line_test(&repository, &["show", "-s", "--format=%T", "HEAD"]);
        let pack = temporary.path().join("fictional-public-pack.zip");
        Self {
            temporary,
            repository,
            burn_register,
            pack,
            commit,
            tree,
        }
    }

    fn request(&self) -> BuildRequest<'_> {
        BuildRequest {
            tag: TAG,
            out: &self.pack,
            burn_register: &self.burn_register,
            linter_version: Some("fixture-linter-1"),
            repository_root: &self.repository,
        }
    }

    fn build(&self) -> super::BuildReport {
        with_process_lock(|| build(self.request())).expect("fixture pack build")
    }
}

///
/// # Panics
/// Panics only if fixture operations fail or a packed manifest inherits its metadata.
/// ´test:unit:packed-library-manifests-retain-explicit-license-and-authors´
#[test]
fn packed_library_manifests_retain_explicit_license_and_authors() {
    let fixture = Fixture::new();
    for (name, source) in [
        (
            "superloop-cli-common",
            include_str!("../../superloop-cli-common/Cargo.toml"),
        ),
        (
            "superloop-execwrap",
            include_str!("../../superloop-execwrap/Cargo.toml"),
        ),
        (
            "superloop-lint",
            include_str!("../../superloop-lint/Cargo.toml"),
        ),
    ] {
        let directory = fixture.repository.join("packages").join(name);
        fs::create_dir_all(&directory).expect("package directory");
        fs::write(directory.join("Cargo.toml"), source).expect("vendored manifest");
    }
    git_ok(&fixture.repository, &["add", "packages"]);
    git_ok(&fixture.repository, &["commit", "-qm", "library manifests"]);
    git_ok(&fixture.repository, &["tag", "-f", TAG]);
    fixture.build();
    let audit = audit_archive(&fixture.pack).expect("archive audit");
    let extracted = tempfile::tempdir().expect("extraction");
    with_process_lock(|| extract_archive(&fixture.pack, extracted.path(), &audit))
        .expect("extract built pack");
    for name in [
        "superloop-cli-common",
        "superloop-execwrap",
        "superloop-lint",
    ] {
        let source =
            fs::read_to_string(extracted.path().join(format!("packages/{name}/Cargo.toml")))
                .expect("manifest bytes");
        let manifest: toml::Value = toml::from_str(&source).expect("manifest TOML");
        assert_eq!(
            manifest["package"]["license"].as_str(),
            Some("GPL-3.0-or-later")
        );
        if name == "superloop-lint" {
            continue;
        }
        assert_eq!(
            manifest["package"]["authors"]
                .as_array()
                .expect("explicit authors")
                .len(),
            1
        );
        assert_eq!(
            manifest["package"]["authors"][0].as_str(),
            Some("Orchestration helpers authors")
        );
    }
}

fn git_ok(root: &Path, arguments: &[&str]) {
    with_process_lock(|| git_ok_unlocked(root, arguments));
}

fn git_ok_unlocked(root: &Path, arguments: &[&str]) {
    let arguments: Vec<std::ffi::OsString> =
        arguments.iter().map(std::ffi::OsString::from).collect();
    let output = run_git(root, &arguments).expect("fixture git process");
    assert!(output.status.success(), "fixture git command failed");
}

fn git_line_test(root: &Path, arguments: &[&str]) -> String {
    let arguments: Vec<std::ffi::OsString> =
        arguments.iter().map(std::ffi::OsString::from).collect();
    let output = with_process_lock(|| run_git(root, &arguments)).expect("fixture git process");
    assert!(output.status.success(), "fixture git command failed");
    String::from_utf8(output.stdout)
        .expect("fixture git UTF-8")
        .trim()
        .to_owned()
}

#[derive(Clone, Copy)]
struct StubReport {
    clean: bool,
    failures: usize,
    public_pack: bool,
    owed: usize,
}

impl StubReport {
    const fn green() -> Self {
        Self {
            clean: true,
            failures: 0,
            public_pack: true,
            owed: 0,
        }
    }
}

fn stub_linter(directory: &Path, burn_register: &Path, report: StubReport) -> PathBuf {
    let source = fs::canonicalize(burn_register).expect("canonical fixture register");
    let document = json!({
        "clean": report.clean,
        "failures": report.failures,
        "public_pack": report.public_pack,
        "burn": {
            "declared": 2,
            "occurrences": report.owed,
            "owed": report.owed,
            "families": [{
                "family": "public-pack values",
                "declared": 2,
                "source": source.to_string_lossy(),
                "source_kind": "external",
                "occurrences": report.owed,
                "registered": report.owed,
                "owed": report.owed,
            }],
        },
    })
    .to_string();
    assert!(
        !document.contains('\''),
        "fixture JSON must be shell-quotable"
    );
    let script = directory.join("fixture-linter");
    write_executable(
        &script,
        format!("#!/bin/sh\nprintf '%s\\n' '{document}'\n").as_bytes(),
        0o755,
    )
    .expect("stub linter");
    script
}

fn verify_with_stub(
    fixture: &Fixture,
    staging: &Path,
    linter: &Path,
) -> Result<super::VerifyReport, super::VerifyError> {
    with_process_lock(|| {
        verify(VerifyRequest {
            pack: &fixture.pack,
            burn_register: &fixture.burn_register,
            linter,
            staging,
        })
    })
}

/// ´test:unit:archive-uses-tagged-bytes-excludes-private-and-worktree-content-and-round-trips-provenance´
#[test]
fn archive_uses_tagged_bytes_excludes_private_and_worktree_content_and_round_trips_provenance() {
    let fixture = Fixture::new();
    let report = with_process_lock(|| {
        build_with_hook(fixture.request(), |stage| {
            if stage == BuildStage::CheckoutValidated {
                fs::write(fixture.repository.join("tracked.txt"), "modified bytes\n")
                    .expect("modify tracked fixture");
                fs::write(
                    fixture.repository.join("untracked.txt"),
                    "untracked bytes\n",
                )
                .expect("untracked fixture");
            }
            Ok(())
        })
    })
    .expect("object database build");

    let audit = audit_archive(&fixture.pack).expect("archive audit");
    let names: Vec<&Path> = audit
        .members
        .iter()
        .map(|member| member.path.as_path())
        .collect();
    assert!(names.contains(&Path::new(MANIFEST_PATH)));
    assert!(!names.iter().any(|path| path.starts_with("local")));
    assert!(!names.contains(&Path::new("ignored.txt")));
    assert!(!names.contains(&Path::new("untracked.txt")));

    let extracted = tempfile::tempdir().expect("extraction fixture");
    with_process_lock(|| extract_archive(&fixture.pack, extracted.path(), &audit))
        .expect("fixture extraction");
    assert_eq!(
        fs::read(extracted.path().join("tracked.txt")).expect("extracted tracked bytes"),
        b"tagged bytes\n"
    );
    let manifest = read_manifest(extracted.path()).expect("extracted manifest");
    assert_eq!(manifest, report.manifest);
    assert_eq!(manifest.tag, TAG);
    assert_eq!(manifest.commit, fixture.commit);
    assert_eq!(manifest.tree, fixture.tree);
    assert_eq!(
        manifest.burn_register_sha256,
        sha256_bytes(REGISTER.as_bytes())
    );
    assert_eq!(manifest.burn_register_count, 2);
    assert_eq!(
        report.final_zip_sha256,
        sha256_file(&fixture.pack).expect("pack digest")
    );

    let identity = with_process_lock(|| super::resolve_tag(&fixture.repository, TAG))
        .expect("fixture tag identity");
    let plain = fixture.temporary.path().join("reconstructed-plain.zip");
    with_process_lock(|| run_git_archive(&fixture.repository, &identity, &plain, None))
        .expect("reconstructed plain archive");
    assert_eq!(
        manifest.archive_sha256,
        sha256_file(&plain).expect("plain digest")
    );
}

/// ´test:unit:dirty-checkout-refuses-before-archive-publication´
#[test]
fn dirty_checkout_refuses_before_archive_publication() {
    let fixture = Fixture::new();
    fs::write(fixture.repository.join("untracked.txt"), "untracked\n").expect("dirty fixture");

    let error =
        with_process_lock(|| build(fixture.request())).expect_err("dirty checkout must refuse");

    assert_eq!(error.reason(), BuildRefusal::Checkout);
    assert!(!fixture.pack.exists());
}

/// ´test:unit:moved-tag-refuses-before-archive-publication´
#[test]
fn moved_tag_refuses_before_archive_publication() {
    let fixture = Fixture::new();
    fs::write(fixture.repository.join("future.txt"), "future bytes\n").expect("future fixture");
    git_ok(&fixture.repository, &["add", "future.txt"]);
    git_ok(&fixture.repository, &["commit", "-qm", "future source"]);
    let moved_commit = git_line_test(&fixture.repository, &["rev-parse", "HEAD"]);
    git_ok(&fixture.repository, &["checkout", "-q", "--detach", TAG]);

    let error = with_process_lock(|| {
        build_with_hook(fixture.request(), |stage| {
            if stage == BuildStage::BeforeTagRecheck {
                git_ok_unlocked(&fixture.repository, &["tag", "-f", TAG, &moved_commit]);
            }
            Ok(())
        })
    })
    .expect_err("moved tag must refuse");

    assert_eq!(error.reason(), BuildRefusal::TagMoved);
    assert!(!fixture.pack.exists());
}

/// ´test:unit:verify-accepts-green-public-pack-report-and-prints-complete-evidence´
#[test]
fn verify_accepts_green_public_pack_report_and_prints_complete_evidence() {
    let fixture = Fixture::new();
    let built = fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let program_root = tempfile::tempdir().expect("program fixture");
    let linter = stub_linter(
        program_root.path(),
        &fixture.burn_register,
        StubReport::green(),
    );

    let report = verify_with_stub(&fixture, staging.path(), &linter).expect("green verification");

    assert_eq!(report.manifest, built.manifest);
    assert_eq!(report.checks.len(), 8);
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.outcome == CheckOutcome::Passed)
    );
    assert!(matches!(
        report.checks[0].evidence,
        CheckEvidence::Mount {
            staging_device,
            temporary_root_device,
        } if staging_device == temporary_root_device
    ));
    assert!(matches!(
        report.checks[7].evidence,
        CheckEvidence::Linter {
            declared: 2,
            occurrences: 0,
            ref source_kind,
        } if source_kind == "external"
    ));
    assert!(staging.path().join(".git/index").is_file());
}

/// ´test:unit:verify-refuses-an-archive-member-under-local´
#[test]
fn verify_refuses_an_archive_member_under_local() {
    let fixture = Fixture::new();
    let raw_pack = fixture.temporary.path().join("unsafe.zip");
    let output = with_process_lock(|| {
        run_git(
            &fixture.repository,
            &[
                std::ffi::OsString::from("archive"),
                std::ffi::OsString::from("--format=zip"),
                path_option("--output=", &raw_pack),
                std::ffi::OsString::from(TAG),
            ],
        )
    })
    .expect("raw archive process");
    assert!(output.status.success());
    let staging = tempfile::tempdir().expect("staging fixture");
    let request = VerifyRequest {
        pack: &raw_pack,
        burn_register: &fixture.burn_register,
        linter: Path::new("unused-linter"),
        staging: staging.path(),
    };

    let error = with_process_lock(|| verify(request)).expect_err("local member must refuse");

    assert_eq!(error.reason(), VerifyRefusal::ForbiddenMember);
    assert_eq!(error.exit_status(), 5);
    assert_eq!(error.checks()[1].check, VerifyCheck::ArchiveMembers);
    assert_eq!(error.checks()[1].outcome, CheckOutcome::Refused);
}

/// ´test:unit:verify-refuses-a-register-digest-mismatch´
#[test]
fn verify_refuses_a_register_digest_mismatch() {
    let fixture = Fixture::new();
    fixture.build();
    let alternate = fixture.temporary.path().join("alternate-register.toml");
    fs::write(
        &alternate,
        "values = [{ value = \"different\", match = \"substring\" }]\n",
    )
    .expect("alternate register");
    let staging = tempfile::tempdir().expect("staging fixture");

    let error = with_process_lock(|| {
        verify(VerifyRequest {
            pack: &fixture.pack,
            burn_register: &alternate,
            linter: Path::new("unused-linter"),
            staging: staging.path(),
        })
    })
    .expect_err("register mismatch must refuse");

    assert_eq!(error.reason(), VerifyRefusal::BurnRegisterMismatch);
    assert_eq!(error.exit_status(), 7);
}

/// ´test:unit:verify-refuses-a-non-empty-staging-directory´
#[test]
fn verify_refuses_a_non_empty_staging_directory() {
    let fixture = Fixture::new();
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    fs::write(staging.path().join("occupied"), "occupied\n").expect("occupied staging");

    let error = with_process_lock(|| {
        verify(VerifyRequest {
            pack: &fixture.pack,
            burn_register: &fixture.burn_register,
            linter: Path::new("unused-linter"),
            staging: staging.path(),
        })
    })
    .expect_err("non-empty staging must refuse");

    assert_eq!(error.reason(), VerifyRefusal::StagingNotEmpty);
    assert_eq!(error.exit_status(), 4);
    assert!(
        error
            .checks()
            .iter()
            .skip(1)
            .all(|check| check.outcome == CheckOutcome::Skipped)
    );
}

/// ´test:unit:verify-refuses-owed-burn-debt´
#[test]
fn verify_refuses_owed_burn_debt() {
    let fixture = Fixture::new();
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let program_root = tempfile::tempdir().expect("program fixture");
    let linter = stub_linter(
        program_root.path(),
        &fixture.burn_register,
        StubReport {
            owed: 1,
            ..StubReport::green()
        },
    );

    let error = verify_with_stub(&fixture, staging.path(), &linter)
        .expect_err("burn occurrences must refuse");

    assert_eq!(error.reason(), VerifyRefusal::BurnEvidence);
    assert_eq!(error.exit_status(), 10);
}

/// ´test:unit:verify-refuses-a-false-public-pack-report´
#[test]
fn verify_refuses_a_false_public_pack_report() {
    let fixture = Fixture::new();
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let program_root = tempfile::tempdir().expect("program fixture");
    let linter = stub_linter(
        program_root.path(),
        &fixture.burn_register,
        StubReport {
            public_pack: false,
            ..StubReport::green()
        },
    );

    let error = verify_with_stub(&fixture, staging.path(), &linter)
        .expect_err("false superloop-pack report must refuse");

    assert_eq!(error.reason(), VerifyRefusal::LinterNotPublicPack);
    assert_eq!(error.exit_status(), 10);
}

fn deployed_linter() -> PathBuf {
    PathBuf::from(
        std::env::var_os("PUBLIC_PACK_TEST_LINTER")
            .expect("PUBLIC_PACK_TEST_LINTER must name the registered linter executable"),
    )
}

fn declared_fixture(external: bool, guide: &str, rows: &str) -> Fixture {
    let mut fixture = Fixture::new();
    let declaration = fixture.repository.join(".linter");
    fs::create_dir(&declaration).expect("fixture declaration");
    let policies = if external {
        "policies = [{ owner = \"PROJECTA\", policy = \"public-pack.values-absent\" }, { owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n"
    } else {
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n"
    };
    let mut lists = if external {
        format!("[PROJECTA.\"public-pack.values-absent\"]\npath_counts = [{rows}]\n")
    } else {
        String::new()
    };
    lists.push_str("[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n");
    for (name, body) in [
        (
            "owners",
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        ),
        ("environments", "environments = []\n"),
        ("policies", policies),
        ("lists", lists.as_str()),
        ("shape", "universe = \"git-tracked\"\nignore = []\n"),
    ] {
        fs::write(
            declaration.join(format!("{name}.toml")),
            format!(
                "namespace = \"{}.{name}\"\nversion = [1, 0, 0]\n\n{body}",
                if name == "lists" || name.starts_with("policy.") {
                    "class.linter"
                } else {
                    "org.example.linter"
                }
            ),
        )
        .expect("fixture declaration document");
    }
    if external {
        fs::write(
            declaration.join("policy-public-pack-values.toml"),
            concat!(
                "namespace = \"class.linter.policy.public-pack.values-absent\"\n",
                "version = [1, 0, 0]\n[owners.PROJECTA]\nsurface = \"*VCHAR\"\n",
                "values = \"local/burn-register.toml\"\n",
                "exclude = '%s\"local\" [ \"/\" *VCHAR ]'\n",
            ),
        )
        .expect("fixture superloop-pack policy");
    }
    fs::write(fixture.repository.join("docs/guide.md"), guide).expect("fixture guide");
    git_ok(&fixture.repository, &["add", "-A"]);
    git_ok(&fixture.repository, &["commit", "-qm", "declare fixture"]);
    git_ok(&fixture.repository, &["tag", "-f", TAG]);
    fixture.commit = git_line_test(&fixture.repository, &["rev-parse", "HEAD"]);
    fixture.tree = git_line_test(&fixture.repository, &["show", "-s", "--format=%T", "HEAD"]);
    fixture
}

fn pack_only_fixture(manifest_owned: bool) -> Fixture {
    let mut fixture = declared_fixture(true, "Fictional public guide.\n", "");
    git_ok(
        &fixture.repository,
        &["rm", "-q", "local/burn-register.toml"],
    );
    fs::remove_file(fixture.repository.join("ignored.txt")).expect("remove incidental fixture");
    fs::write(fixture.repository.join(".gitignore"), "local/\n").expect("private register ignore");
    let declaration = fixture.repository.join(".linter");
    let docs = if manifest_owned {
        "( %s\"docs/guide.md\" / %s\"docs/public-pack-provenance.toml\" )"
    } else {
        "%s\"docs/guide.md\""
    };
    fs::write(declaration.join("owners.toml"), format!(
        "namespace = \"org.example.linter.owners\"\nversion = [1, 0, 0]\n\
        root_owner = \"TOOLS\"\nowners = [\"TOOLS\", \"DOCS\"]\npartitions = [\n\
        {{ name = \"root\", owner = \"TOOLS\", pattern = '( %s\".gitignore\" / %s\"tracked.txt\" / %s\".linter/\" *VCHAR )' }},\n\
        {{ name = \"documents\", owner = \"DOCS\", pattern = '{docs}' }}\n]\nmay_cite = []\n"
    )).expect("narrow provenance ownership");
    fs::write(
        declaration.join("shape.toml"),
        concat!(
            "namespace = \"org.example.linter.shape\"\nversion = [1, 0, 0]\n",
            "universe = \"tracked-exclusive\"\n",
            "ignore = [{ name = \"private-register\", pattern = '%s\"local\" [ \"/\" *VCHAR ]' }]\n"
        ),
    )
    .expect("ignored private register corpus");
    for name in [
        "policies.toml",
        "lists.toml",
        "policy-public-pack-values.toml",
    ] {
        let path = declaration.join(name);
        let mut text = fs::read_to_string(&path)
            .expect("declaration")
            .replace("PROJECTA", "TOOLS")
            .replace(
                "owner = \"TOOLS\", policy = \"labels.mints-well-formed\"",
                "owner = \"DOCS\", policy = \"labels.mints-well-formed\"",
            )
            .replace(
                "[TOOLS.\"labels.mints-well-formed\"]",
                "[DOCS.\"labels.mints-well-formed\"]",
            );
        if name == "policy-public-pack-values.toml" {
            text = text
                .replace(
                    "[owners.TOOLS]\n",
                    "[owners.TOOLS]\nactivation = \"public-pack\"\n",
                )
                .replace(
                    "local/burn-register.toml",
                    "local/linter/public-pack-burn.toml",
                );
        }
        fs::write(path, text).expect("pack-only declaration");
    }
    git_ok(&fixture.repository, &["add", "-A"]);
    git_ok(
        &fixture.repository,
        &["commit", "-qm", "declare pack-only fixture"],
    );
    git_ok(&fixture.repository, &["tag", "-f", TAG]);
    fixture.commit = git_line_test(&fixture.repository, &["rev-parse", "HEAD"]);
    fixture.tree = git_line_test(&fixture.repository, &["show", "-s", "--format=%T", "HEAD"]);
    fixture.burn_register = fixture
        .repository
        .join("local/linter/public-pack-burn.toml");
    fixture
}

fn supply_private_register(fixture: &Fixture) {
    fs::create_dir_all(fixture.repository.join("local/linter")).expect("private register home");
    fs::write(&fixture.burn_register, REGISTER).expect("private register");
    assert_eq!(
        git_line_test(
            &fixture.repository,
            &["status", "--porcelain=v1", "--untracked-files=all"]
        ),
        ""
    );
    assert_eq!(
        git_line_test(&fixture.repository, &["ls-files", "local"]),
        ""
    );
}

/// Plain check needs no private inventory; pack verification needs both its external binding and provenance ownership.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or the declared ownership verdict differs.
///
/// ´test:unit:pack-only-activation-builds-and-verifies-with-narrow-provenance-ownership´
#[test]
fn pack_only_activation_builds_and_verifies_with_narrow_provenance_ownership() {
    let linter = deployed_linter();
    for manifest_owned in [false, true] {
        let fixture = pack_only_fixture(manifest_owned);
        assert!(!fixture.burn_register.exists());
        for supplied in [false, true] {
            if supplied {
                supply_private_register(&fixture);
            }
            let plain = with_process_lock(|| {
                Command::new(&linter)
                    .arg("check")
                    .arg("--root")
                    .arg(&fixture.repository)
                    .output()
            })
            .expect("plain check with or without a private document");
            assert!(
                plain.status.success(),
                "{}",
                String::from_utf8_lossy(&plain.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&plain.stdout).expect("plain report");
            assert_eq!(report["clean"], true);
            assert_eq!(report["sources_scanned"], 1, "the guide is activated prose");
            assert_eq!(report["public_pack"], false);
            assert!(
                !report["burn"]["families"]
                    .as_array()
                    .expect("burn families")
                    .iter()
                    .any(|family| family["family"] == "public-pack values")
            );
        }
        let built = fixture.build();
        assert_eq!(built.manifest.burn_register_count, 2);
        let staging = tempfile::tempdir().expect("pack staging");
        let inputs = tempfile::tempdir().expect("external verifier directory");
        let external = inputs.path().join("public-pack-burn.toml");
        fs::copy(&fixture.burn_register, &external).expect("verifier register copy");
        let result = with_process_lock(|| {
            verify(VerifyRequest {
                pack: &fixture.pack,
                burn_register: &external,
                linter: &linter,
                staging: staging.path(),
            })
        });
        assert!(!staging.path().join("local").exists());
        assert!(staging.path().join(MANIFEST_PATH).is_file());
        if manifest_owned {
            let verified = result.expect("owned provenance verifies with the external register");
            assert_eq!(verified.manifest, built.manifest);
            assert!(
                verified
                    .checks
                    .iter()
                    .all(|check| check.outcome == CheckOutcome::Passed)
            );
            assert!(matches!(&verified.checks[7].evidence,
                CheckEvidence::Linter { declared: 2, occurrences: 0, source_kind }
                    if source_kind == "external"));
        } else {
            assert_eq!(
                result.expect_err("unowned provenance must refuse").reason(),
                VerifyRefusal::LinterStatus
            );
        }
    }
}

/// A clean pack proves that the real linter read the supplied register.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or verification disagrees.
///
/// ´test:unit:verify-round-trips-clean-packs-through-the-real-linter´
#[test]
fn verify_round_trips_clean_packs_through_the_real_linter() {
    let linter = deployed_linter();
    let fixture = declared_fixture(true, "Fictional public guide.\n", "");
    let built = fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let result = verify_with_stub(&fixture, staging.path(), &linter);
    let report = result.as_ref().expect("real linter accepts clean pack");
    assert_eq!(report.manifest, built.manifest);
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.outcome == CheckOutcome::Passed)
    );
    assert!(matches!(
        &report.checks[7].evidence,
        CheckEvidence::Linter { declared: 2, occurrences: 0, source_kind }
            if source_kind == "external"
    ));
    let mut output = Vec::new();
    super::write_verify_report(&result, std::time::Duration::ZERO, &mut output)
        .expect("verification report");
    assert!(
        String::from_utf8(output)
            .expect("report text")
            .contains("clean=yes")
    );
}

/// Built-in zero counts cannot prove that the supplied private-value register was read.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or a vacuous census is accepted.
///
/// ´test:unit:verify-refuses-a-real-linter-verdict-without-register-binding´
#[test]
fn verify_refuses_a_real_linter_verdict_without_register_binding() {
    let fixture = declared_fixture(false, "sagofink-loop is still present.\n", "");
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let error = verify_with_stub(&fixture, staging.path(), &deployed_linter())
        .expect_err("unread register must refuse despite clean linter verdict");
    assert_eq!(error.reason(), VerifyRefusal::BurnEvidence);
    assert!(!error.to_string().contains("family="));
}

/// Plain checks require the local values document; a pack excludes it and reads the external register.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or document selection disagrees.
///
/// ´test:unit:activation-requires-local-values-for-plain-checks-and-external-values-for-packs´
#[test]
fn activation_requires_local_values_for_plain_checks_and_external_values_for_packs() {
    let fixture = declared_fixture(true, "Fictional public guide.\n", "");
    let linter = deployed_linter();
    let plain_check = || {
        with_process_lock(|| {
            Command::new(&linter)
                .arg("check")
                .arg("--root")
                .arg(&fixture.repository)
                .output()
        })
        .expect("plain linter check")
    };
    fs::remove_file(&fixture.burn_register).expect("remove local values");
    let missing = plain_check();
    assert!(!missing.status.success());
    assert_eq!(missing.stdout, [] as [u8; 0]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("burn-value document is absent"));
    fs::write(&fixture.burn_register, REGISTER).expect("restore local values");
    let local = plain_check();
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&local.stdout).expect("plain report");
    assert_eq!(report["clean"], true);
    assert_eq!(report["sources_scanned"], 1, "the guide is activated prose");
    let family = report["burn"]["families"]
        .as_array()
        .expect("burn families")
        .iter()
        .find(|family| family["family"] == "public-pack values")
        .expect("activated family");
    assert_eq!(family["source_kind"], "repository");
    assert_eq!(family["source"], "local/burn-register.toml");
    assert_eq!(family["declared"], 2);
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let verified = verify_with_stub(&fixture, staging.path(), &linter)
        .expect("pack reads the external register after excluding local");
    assert!(!staging.path().join("local").exists());
    assert!(matches!(
        &verified.checks[7].evidence,
        CheckEvidence::Linter { declared: 2, occurrences: 0, source_kind }
            if source_kind == "external"
    ));
}

/// A real burn growth finding survives verification with its family named.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or the refusal loses its family.
///
/// ´test:unit:verify-names-the-real-linters-burn-occurrence-family´
#[test]
fn verify_names_the_real_linters_burn_occurrence_family() {
    let fixture = declared_fixture(true, "sagofink-loop is a derived name.\n", "");
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let result = verify_with_stub(&fixture, staging.path(), &deployed_linter());
    let error = result.as_ref().expect_err("burn growth must refuse");
    assert_eq!(error.reason(), VerifyRefusal::BurnEvidence);
    assert_eq!(error.exit_status(), 10);
    assert!(error.to_string().contains("public-pack values"));
    let mut output = Vec::new();
    super::write_verify_report(&result, std::time::Duration::ZERO, &mut output)
        .expect("refusal report");
    assert!(
        String::from_utf8(output)
            .expect("report text")
            .contains("family=\"public-pack values\"")
    );
}

/// A clean ratchet verdict still refuses debt that the burn register owes.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or owed debt is accepted.
///
/// ´test:unit:verify-refuses-real-registered-burn-debt´
#[test]
fn verify_refuses_real_registered_burn_debt() {
    let fixture = declared_fixture(
        true,
        "sagofink-loop is a derived name.\n",
        "{ path = \"docs/guide.md\", maximum = 1 }",
    );
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let error = verify_with_stub(&fixture, staging.path(), &deployed_linter())
        .expect_err("registered but unkept burn debt must refuse");
    assert_eq!(error.reason(), VerifyRefusal::BurnEvidence);
    assert!(error.to_string().contains("public-pack values"));
}

/// A kept private value still cannot be carried by a public pack.
///
/// # Panics
///
/// Panics only if fixture operations fail, the registered linter is absent, or a kept private value is accepted.
///
/// ´test:unit:verify-refuses-real-kept-private-values´
#[test]
fn verify_refuses_real_kept_private_values() {
    let fixture = declared_fixture(
        true,
        "sagofink-loop is a derived name.\n",
        "{ path = \"docs/guide.md\", maximum = 1, kept = \"published example\" }",
    );
    fixture.build();
    let staging = tempfile::tempdir().expect("staging fixture");
    let error = verify_with_stub(&fixture, staging.path(), &deployed_linter())
        .expect_err("a kept private value still refuses");
    assert_eq!(error.reason(), VerifyRefusal::BurnEvidence);
    assert!(error.to_string().contains("family=\"public-pack values\""));
}

fn verdict_fixture() -> super::LinterObservation {
    super::LinterObservation {
        status_success: true,
        report: super::LinterReport {
            clean: true,
            failures: 0,
            public_pack: true,
            burn: super::LinterBurn {
                owed: 0,
                families: vec![super::LinterFamily {
                    family: "private values".to_owned(),
                    declared: Some(2),
                    source: Some("/fixture/register.toml".to_owned()),
                    source_kind: Some("external".to_owned()),
                    occurrences: 0,
                    registered: 0,
                    owed: 0,
                }],
            },
        },
    }
}

/// # Panics
///
/// Panics only if an incomplete register binding is accepted.
///
/// ´test:unit:register-binding-requires-source-kind-path-and-positive-value-count´
#[test]
fn register_binding_requires_source_kind_path_and_positive_value_count() {
    for (kind, source, declared) in [
        (None, Some("/fixture/register.toml"), Some(2)),
        (Some("repository"), Some("/fixture/register.toml"), Some(2)),
        (Some("external"), None, Some(2)),
        (Some("external"), Some("/other/register.toml"), Some(2)),
        (Some("external"), Some("/fixture/register.toml"), None),
        (Some("external"), Some("/fixture/register.toml"), Some(0)),
    ] {
        let mut observation = verdict_fixture();
        let family = &mut observation.report.burn.families[0];
        family.source_kind = kind.map(str::to_owned);
        family.source = source.map(str::to_owned);
        family.declared = declared;
        let (reason, _) =
            super::validate_linter_verdict(&observation, Path::new("/fixture/register.toml"))
                .expect_err("incomplete binding must refuse");
        assert_eq!(reason, VerifyRefusal::BurnEvidence);
    }
}

/// ´test:unit:burn-details-name-only-families-causing-the-refusal´
#[test]
fn burn_details_name_only_families_causing_the_refusal() {
    let mut observation = verdict_fixture();
    observation.report.burn.families.push(super::LinterFamily {
        family: "kept built-in family".to_owned(),
        declared: None,
        source: None,
        source_kind: None,
        occurrences: 1,
        registered: 1,
        owed: 0,
    });
    let register = Path::new("/fixture/register.toml");
    assert!(super::validate_linter_verdict(&observation, register).is_ok());
    observation.status_success = false;
    observation.report.clean = false;
    observation.report.failures = 1;
    assert_eq!(
        super::validate_linter_verdict(&observation, register),
        Err((VerifyRefusal::LinterStatus, Vec::new()))
    );
    observation.report.burn.families[0].occurrences = 1;
    assert_eq!(
        super::validate_linter_verdict(&observation, register),
        Err((
            VerifyRefusal::BurnEvidence,
            vec!["private values".to_owned()]
        ))
    );
    observation.report.burn.families[0].occurrences = 0;
    observation.report.burn.families[1].occurrences = 2;
    assert_eq!(
        super::validate_linter_verdict(&observation, register),
        Err((
            VerifyRefusal::BurnEvidence,
            vec!["kept built-in family".to_owned()]
        ))
    );
}
