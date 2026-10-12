//! # `superloop-install` library test matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Copy transaction | 7 | New, unchanged, changed, idempotent, wrong mode, source alias, and fixture map |
//! | Preflight boundaries | 12 | Escape, duplicate, missing input, destination symlinks, backup identity, mode, schema exclusivity and root normalization |
//! | Rendering | 10 | Determinism, order, section bijection, uniqueness, base conflict, leftovers, overlay shape, and cap |
//! | Dry-run and reporting | 4 | Zero mutation, stable statuses, terminal framing, and refusal summaries |
//! | Build, provenance and registry | 9 | Build records and refusals, staged and live domains, commit-sensitive provenance, release identity, registry roots and collisions |

use std::fs::{self, File, FileTimes};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use super::{
    BackupDisposition, InstallRequest, RefusalClass, RefusalReason, RegistryRoot, TargetOutcome,
    install, render, write_report,
};

const MAP_ROOT: &str = "/srv/example/example-user/harness";
const COPY_FIXTURE: &str = include_str!("../tests/fixtures/maps/copy.toml");
const RENDER_FIXTURE: &str = include_str!("../tests/fixtures/maps/render.toml");

/// ´test:unit:root-check-rejects-nonabsolute-and-unnormalized-inputs´
#[test]
fn root_check_rejects_nonabsolute_and_unnormalized_inputs() {
    for allow_missing in [false, true] {
        for root in ["relative", "/../root"] {
            assert_eq!(
                super::check_root(Path::new(root), allow_missing),
                Err(RefusalReason::InvalidRoot)
            );
        }
    }
    let fixture = Fixture::new();
    let normalized = fixture.root.join("../destination-root");
    let mut request = fixture.request(true);
    request.root_override = Some(&normalized);
    fixture.source("source.md", COPY_BYTES);
    fs::write(&fixture.map, copy_map("source.md", "target.md", "0644")).expect("map");
    assert!(
        install(request).is_ok(),
        "production entry normalizes before checking"
    );
}
const COPY_BYTES: &[u8] = include_bytes!("../tests/fixtures/repository/copy.md");
const BASE_BYTES: &[u8] = include_bytes!("../tests/fixtures/repository/base.md");
const OVERLAY_BYTES: &[u8] = include_bytes!("../tests/fixtures/repository/overlay.md");

struct Fixture {
    temporary: tempfile::TempDir,
    repository: PathBuf,
    root: PathBuf,
    map: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary fixture root");
        let repository = temporary.path().join("repository");
        let root = temporary.path().join("destination-root");
        fs::create_dir(&repository).expect("repository fixture directory");
        fs::create_dir(&root).expect("destination fixture directory");
        let map = temporary.path().join("install-map.toml");
        Self {
            temporary,
            repository,
            root,
            map,
        }
    }

    fn source(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.repository.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("source fixture parents");
        }
        fs::write(&path, bytes).expect("source fixture bytes");
        path
    }

    fn target(&self, relative: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("target fixture parents");
        }
        fs::write(&path, bytes).expect("target fixture bytes");
        set_mode(&path, mode);
        path
    }

    fn run(&self, map: &str, dry_run: bool) -> Result<super::InstallReport, super::InstallError> {
        fs::write(&self.map, map).expect("fixture map");
        install(self.request(dry_run))
    }

    fn request(&self, dry_run: bool) -> InstallRequest<'_> {
        InstallRequest {
            map_path: &self.map,
            repository_root: &self.repository,
            root_override: Some(&self.root),
            build_root: None,
            shape_root: None,
            registry_override: None,
            destdir: None,
            release_tag: None,
            release_commit: None,
            dry_run,
        }
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(args)
            .output()
            .expect("git fixture command");
        assert!(
            output.status.success(),
            "git fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git fixture output")
            .trim()
            .to_owned()
    }

    fn commit(&self) -> String {
        if !self.repository.join(".git").exists() {
            self.git(&["init", "-q"]);
            self.git(&["config", "user.email", "fixture@example.invalid"]);
            self.git(&["config", "user.name", "Fixture"]);
        }
        self.git(&["add", "."]);
        self.git(&["commit", "-q", "--allow-empty", "-m", "fixture"]);
        self.git(&["rev-parse", "HEAD"])
    }
}

fn copy_map(source: &str, destination: &str, mode: &str) -> String {
    format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"{source}\"\ndestination = \"{destination}\"\nmode = \"{mode}\"\n"
    )
}

fn render_map(base: &str, overlay: &str, destination: &str, max_bytes: u64) -> String {
    format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"render\"\nbase = \"{base}\"\noverlay = \"{overlay}\"\ndestination = \"{destination}\"\nmode = \"0644\"\nmax_bytes = {max_bytes}\n"
    )
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).expect("fixture metadata");
    (metadata.dev(), metadata.ino())
}

fn stamp(path: &Path) -> (u64, u64, u32, i64, i64, Vec<u8>) {
    let metadata = fs::symlink_metadata(path).expect("fixture metadata");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode() & 0o7777,
        metadata.mtime(),
        metadata.mtime_nsec(),
        fs::read(path).expect("fixture bytes"),
    )
}

fn pin_mtime(path: &Path, seconds: u64, nanoseconds: u32) {
    let modified = UNIX_EPOCH + Duration::new(seconds, nanoseconds);
    File::options()
        .write(true)
        .open(path)
        .expect("open timestamp fixture")
        .set_times(FileTimes::new().set_modified(modified))
        .expect("set exact fixture mtime");
}

/// ´test:unit:absent-target-becomes-independent-copy-with-declared-mode´
#[test]
fn absent_target_becomes_independent_copy_with_declared_mode() {
    let fixture = Fixture::new();
    let source = fixture.source("source.md", b"candidate\n");

    let report = fixture
        .run(&copy_map("source.md", "nested/target.md", "0640"), false)
        .expect("new target install");
    let target = fixture.root.join("nested/target.md");

    assert_eq!(report.targets[0].outcome, TargetOutcome::New);
    assert_eq!(report.targets[0].replacements, 1);
    assert_eq!(fs::read(&target).expect("installed bytes"), b"candidate\n");
    assert_eq!(stamp(&target).2, 0o640);
    assert_ne!(identity(&source), identity(&target));
}

/// ´test:unit:committed-copy-fixture-installs´
#[test]
fn committed_copy_fixture_installs() {
    let fixture = Fixture::new();
    fixture.source("copy.md", COPY_BYTES);

    let report = fixture.run(COPY_FIXTURE, false).expect("fixture install");

    assert_eq!(report.targets[0].outcome, TargetOutcome::New);
    assert_eq!(
        fs::read(fixture.root.join("nested/copied.md")).expect("fixture target"),
        COPY_BYTES
    );
}

/// ´test:unit:equal-target-retains-identity-bytes-mode-and-nanosecond-mtime´
#[test]
fn equal_target_retains_identity_bytes_mode_and_nanosecond_mtime() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"same\n");
    let target = fixture.target("target.md", b"same\n", 0o644);
    pin_mtime(&target, 1_700_000_000, 123_456_789);
    let before = stamp(&target);

    let report = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect("unchanged install");

    assert_eq!(report.targets[0].outcome, TargetOutcome::Unchanged);
    assert_eq!(report.targets[0].replacements, 0);
    assert!(!report.targets[0].touched);
    assert_eq!(stamp(&target), before);
    assert!(!target.with_file_name("target.md.pre-deploy").exists());
}

/// ´test:unit:changed-target-backs-up-outgoing-bytes-and-renames-once´
#[test]
fn changed_target_backs_up_outgoing_bytes_and_renames_once() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let target = fixture.target("target.md", b"old\n", 0o600);
    pin_mtime(&target, 1_600_000_000, 987_654_321);
    let before = stamp(&target);

    let report = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect("changed install");
    let after = stamp(&target);
    let backup = target.with_file_name("target.md.pre-deploy");
    let evidence = report.targets[0].backup.as_ref().expect("backup evidence");

    assert_eq!(report.targets[0].outcome, TargetOutcome::Changed);
    assert_eq!(report.targets[0].replacements, 1);
    assert_eq!(evidence.disposition, BackupDisposition::Written);
    assert_eq!(evidence.outgoing_sha256, evidence.backup_sha256);
    assert_eq!(fs::read(backup).expect("backup bytes"), b"old\n");
    assert_eq!(after.5, b"new\n");
    assert_eq!(after.2, 0o644);
    assert_ne!((before.0, before.1), (after.0, after.1));
    assert_ne!((before.3, before.4), (after.3, after.4));
}

/// ´test:unit:second-identical-install-has-no-writes-or-backup-drift´
#[test]
fn second_identical_install_has_no_writes_or_backup_drift() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let target = fixture.target("target.md", b"old\n", 0o644);
    let map = copy_map("source.md", "target.md", "0644");
    fixture.run(&map, false).expect("first install");
    let backup = target.with_file_name("target.md.pre-deploy");
    let target_after_first = stamp(&target);
    let backup_after_first = stamp(&backup);

    let second = fixture.run(&map, false).expect("second install");

    assert_eq!(second.count(TargetOutcome::Unchanged), 1);
    assert_eq!(second.count(TargetOutcome::New), 0);
    assert_eq!(second.count(TargetOutcome::Changed), 0);
    assert_eq!(stamp(&target), target_after_first);
    assert_eq!(stamp(&backup), backup_after_first);
}

/// ´test:unit:equal-bytes-with-wrong-mode-refuse-without-mutation´
#[test]
fn equal_bytes_with_wrong_mode_refuse_without_mutation() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"same\n");
    let target = fixture.target("target.md", b"same\n", 0o600);
    pin_mtime(&target, 1_500_000_000, 222_333_444);
    let before = stamp(&target);

    let error = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect_err("wrong equal mode must refuse");

    assert_eq!(error.class(), RefusalClass::Destination);
    assert_eq!(error.reason(), RefusalReason::EqualModeMismatch);
    assert_eq!(stamp(&target), before);
    assert!(error.touched().is_empty());
}

/// ´test:unit:source-target-hard-link-refuses-the-copy-model´
#[test]
fn source_target_hard_link_refuses_the_copy_model() {
    let fixture = Fixture::new();
    let source = fixture.source("source.md", b"same\n");
    let target = fixture.root.join("target.md");
    fs::hard_link(&source, &target).expect("hard-linked fixture");
    set_mode(&target, 0o644);

    let error = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect_err("source alias must refuse");

    assert_eq!(error.reason(), RefusalReason::SourceTargetAlias);
    assert_eq!(identity(&source), identity(&target));
}

/// ´test:unit:escaping-destination-refuses-before-an-earlier-target-mutates´
#[test]
fn escaping_destination_refuses_before_an_earlier_target_mutates() {
    let fixture = Fixture::new();
    fixture.source("one.md", b"new\n");
    fixture.source("two.md", b"other\n");
    let first = fixture.target("first.md", b"old\n", 0o644);
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"one.md\"\ndestination = \"first.md\"\nmode = \"0644\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"two.md\"\ndestination = \"../escape.md\"\nmode = \"0644\"\n"
    );
    let before = stamp(&first);

    let error = fixture.run(&map, false).expect_err("escape must refuse");

    assert_eq!(error.class(), RefusalClass::Map);
    assert_eq!(error.reason(), RefusalReason::InvalidRelativePath);
    assert_eq!(stamp(&first), before);
}

/// ´test:unit:normalized-duplicate-destination-refuses-before-mutation´
#[test]
fn normalized_duplicate_destination_refuses_before_mutation() {
    let fixture = Fixture::new();
    let first = fixture.target("same.md", b"old\n", 0o644);
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"missing-one.md\"\ndestination = \"same.md\"\nmode = \"0644\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"missing-two.md\"\ndestination = \"sub/../same.md\"\nmode = \"0644\"\n"
    );
    let before = stamp(&first);

    let error = fixture.run(&map, false).expect_err("duplicate must refuse");

    assert_eq!(error.reason(), RefusalReason::DuplicateDestination);
    assert_eq!(stamp(&first), before);
}

/// ´test:unit:target-cannot-collide-with-another-target-backup´
#[test]
fn target_cannot_collide_with_another_target_backup() {
    let fixture = Fixture::new();
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"one.md\"\ndestination = \"same.md\"\nmode = \"0644\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"two.md\"\ndestination = \"same.md.pre-deploy\"\nmode = \"0644\"\n"
    );

    let error = fixture.run(&map, false).expect_err("backup collision");

    assert_eq!(error.reason(), RefusalReason::BackupDestinationCollision);
}

/// ´test:unit:missing-source-refuses-before-an-earlier-target-mutates´
#[test]
fn missing_source_refuses_before_an_earlier_target_mutates() {
    let fixture = Fixture::new();
    fixture.source("present.md", b"new\n");
    let first = fixture.target("first.md", b"old\n", 0o644);
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"present.md\"\ndestination = \"first.md\"\nmode = \"0644\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"missing.md\"\ndestination = \"second.md\"\nmode = \"0644\"\n"
    );
    let before = stamp(&first);

    let error = fixture.run(&map, false).expect_err("missing source");

    assert_eq!(error.class(), RefusalClass::Source);
    assert_eq!(error.reason(), RefusalReason::SourceMissing);
    assert_eq!(stamp(&first), before);
}

/// ´test:unit:symlinked-destination-component-refuses-before-mutation´
#[test]
fn symlinked_destination_component_refuses_before_mutation() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).expect("outside fixture directory");
    std::os::unix::fs::symlink(&outside, fixture.root.join("linked"))
        .expect("destination component symlink");

    let error = fixture
        .run(&copy_map("source.md", "linked/target.md", "0644"), false)
        .expect_err("symlink component");

    assert_eq!(error.class(), RefusalClass::Destination);
    assert_eq!(error.reason(), RefusalReason::DestinationSymlink);
    assert!(!outside.join("target.md").exists());
}

/// ´test:unit:symlinked-root-component-refuses-before-mutation´
#[test]
fn symlinked_root_component_refuses_before_mutation() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let fixture_parent = fixture.root.parent().expect("fixture root parent");
    let real_parent = fixture_parent.join("real-root-parent");
    let real_root = real_parent.join("destination-root");
    fs::create_dir(&real_parent).expect("real root parent");
    fs::create_dir(&real_root).expect("real destination root");
    let linked_parent = fixture_parent.join("linked-root-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("root component symlink");
    let linked_root = linked_parent.join("destination-root");
    fs::write(&fixture.map, copy_map("source.md", "target.md", "0644")).expect("fixture map");

    let error = install(InstallRequest {
        map_path: &fixture.map,
        repository_root: &fixture.repository,
        root_override: Some(&linked_root),
        build_root: None,
        shape_root: None,
        registry_override: None,
        destdir: None,
        release_tag: None,
        release_commit: None,
        dry_run: false,
    })
    .expect_err("symlinked root component");

    assert_eq!(error.class(), RefusalClass::Destination);
    assert_eq!(error.reason(), RefusalReason::RootSymlink);
    assert!(!real_root.join("target.md").exists());
}

/// ´test:unit:symlinked-destination-file-refuses-without-replacement´
#[test]
fn symlinked_destination_file_refuses_without_replacement() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let outside = fixture.target("outside.md", b"outside\n", 0o644);
    let destination = fixture.root.join("target.md");
    std::os::unix::fs::symlink(&outside, &destination).expect("destination symlink");

    let error = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect_err("symlink destination");

    assert_eq!(error.reason(), RefusalReason::DestinationSymlink);
    assert_eq!(fs::read(outside).expect("outside bytes"), b"outside\n");
    assert!(
        fs::symlink_metadata(destination)
            .expect("symlink metadata")
            .file_type()
            .is_symlink()
    );
}

/// ´test:unit:symlinked-backup-destination-refuses-before-target-mutation´
#[test]
fn symlinked_backup_destination_refuses_before_target_mutation() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"new\n");
    let target = fixture.target("target.md", b"old\n", 0o644);
    let outside = fixture.target("outside.md", b"outside\n", 0o644);
    std::os::unix::fs::symlink(&outside, target.with_file_name("target.md.pre-deploy"))
        .expect("backup symlink");
    let before = stamp(&target);

    let error = fixture
        .run(&copy_map("source.md", "target.md", "0644"), false)
        .expect_err("unsafe backup identity");

    assert_eq!(error.reason(), RefusalReason::BackupDestinationType);
    assert_eq!(stamp(&target), before);
    assert_eq!(fs::read(outside).expect("outside bytes"), b"outside\n");
}

/// ´test:unit:copy-target-with-both-source-and-base-is-map-refusal´
#[test]
fn copy_target_with_both_source_and_base_is_map_refusal() {
    let fixture = Fixture::new();
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\nbase = \"base.md\"\ndestination = \"target.md\"\nmode = \"0644\"\n"
    );

    let error = fixture.run(&map, false).expect_err("mixed target shape");

    assert_eq!(error.class(), RefusalClass::Map);
    assert_eq!(error.reason(), RefusalReason::TargetShape);
}

/// ´test:unit:target-with-neither-source-nor-base-is-map-refusal´
#[test]
fn target_with_neither_source_nor_base_is_map_refusal() {
    let fixture = Fixture::new();
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\ndestination = \"target.md\"\nmode = \"0644\"\n"
    );

    let error = fixture.run(&map, false).expect_err("empty target shape");

    assert_eq!(error.reason(), RefusalReason::TargetShape);
}

/// ´test:unit:mode-must-be-exact-four-digit-octal´
#[test]
fn mode_must_be_exact_four_digit_octal() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"content\n");

    for mode in ["644", "0o644", "0999", "00644"] {
        let error = fixture
            .run(&copy_map("source.md", "target.md", mode), false)
            .expect_err("invalid exact mode");
        assert_eq!(error.reason(), RefusalReason::InvalidMode, "mode {mode}");
    }
}

/// ´test:unit:rendering-is-deterministic-and-follows-base-slot-order´
#[test]
fn rendering_is_deterministic_and_follows_base_slot_order() {
    let base = b"# Base \xc2\xb7 `spec:example:base`\n\n{{overlay:sec:example:first}}\nBetween.\n{{overlay:sec:example:second}}\n";
    let overlay = b"## Second \xc2\xb7 `sec:example:second`\nsecond body\n\n## First \xc2\xb7 `sec:example:first`\nfirst body\n";

    let first = render(base, overlay, None).expect("valid render");
    let second = render(base, overlay, None).expect("repeat render");
    let first_position = first
        .windows(b"## First".len())
        .position(|window| window == b"## First")
        .expect("first section position");
    let second_position = first
        .windows(b"## Second".len())
        .position(|window| window == b"## Second")
        .expect("second section position");

    assert_eq!(first, second);
    assert!(first_position < second_position);
    assert!(!super::contains_bytes(&first, b"{{overlay:"));
}

/// ´test:unit:committed-render-fixture-installs-deterministic-bytes´
#[test]
fn committed_render_fixture_installs_deterministic_bytes() {
    let fixture = Fixture::new();
    fixture.source("base.md", BASE_BYTES);
    fixture.source("overlay.md", OVERLAY_BYTES);
    let expected = render(BASE_BYTES, OVERLAY_BYTES, Some(9_500)).expect("fixture render");

    let report = fixture
        .run(RENDER_FIXTURE, false)
        .expect("render fixture install");

    assert_eq!(report.targets[0].outcome, TargetOutcome::New);
    assert_eq!(
        fs::read(fixture.root.join("rendered.md")).expect("rendered target"),
        expected
    );

    let shape_a = fixture.temporary.path().join("shapes-a");
    let shape_b = fixture.temporary.path().join("shapes-b");
    for shape in [&shape_a, &shape_b] {
        fs::create_dir_all(shape.join("generic")).expect("shape directory");
        fs::write(shape.join("generic/base.md"), BASE_BYTES).expect("shape base");
    }
    let map = render_map("generic/base.md", "overlay.md", "shape-rendered.md", 9_500);
    let missing = fixture
        .run(&map, false)
        .expect_err("base absent from repository");
    assert_eq!(missing.class(), RefusalClass::Source);
    assert_eq!(missing.reason(), RefusalReason::SourceMissing);

    let first = install(InstallRequest {
        shape_root: Some(&shape_a),
        ..fixture.request(false)
    })
    .expect("base loaded from separate shape root");
    assert_eq!(first.targets[0].outcome, TargetOutcome::New);
    assert_eq!(
        fs::read(fixture.root.join("shape-rendered.md")).expect("shape render"),
        expected
    );
    let second = install(InstallRequest {
        shape_root: Some(&shape_b),
        ..fixture.request(false)
    })
    .expect("second shape root");
    assert_eq!(second.targets[0].outcome, TargetOutcome::Unchanged);
    assert_ne!(first.map_sha256, second.map_sha256);

    fs::write(
        &fixture.map,
        render_map("../outside.md", "overlay.md", "escape.md", 9_500),
    )
    .expect("escape map");
    let escape = install(InstallRequest {
        shape_root: Some(&shape_a),
        ..fixture.request(false)
    })
    .expect_err("base escapes shape root");
    assert_eq!(escape.class(), RefusalClass::Source);
    assert_eq!(escape.reason(), RefusalReason::InvalidRelativePath);
    assert!(!fixture.root.join("escape.md").exists());
}

/// ´test:unit:slot-without-overlay-section-refuses´
#[test]
fn slot_without_overlay_section_refuses() {
    let error = render(
        b"{{overlay:sec:example:missing}}\n",
        b"## Other \xc2\xb7 `sec:example:other`\nbody\n",
        None,
    )
    .expect_err("missing overlay section");

    assert_eq!(error.reason(), RefusalReason::MissingOverlaySection);
}

/// ´test:unit:overlay-section-without-slot-refuses´
#[test]
fn overlay_section_without_slot_refuses() {
    let error = render(
        b"{{overlay:sec:example:used}}\n",
        b"## Used \xc2\xb7 `sec:example:used`\nbody\n## Extra \xc2\xb7 `sec:example:extra`\nbody\n",
        None,
    )
    .expect_err("unused overlay section");

    assert_eq!(error.reason(), RefusalReason::UnusedOverlaySection);
}

/// ´test:unit:duplicate-overlay-section-label-refuses´
#[test]
fn duplicate_overlay_section_label_refuses() {
    let error = render(
        b"{{overlay:sec:example:used}}\n",
        b"## First \xc2\xb7 `sec:example:used`\nbody\n## Again \xc2\xb7 `sec:example:used`\nbody\n",
        None,
    )
    .expect_err("duplicate overlay label");

    assert_eq!(error.reason(), RefusalReason::DuplicateOverlaySection);
}

/// ´test:unit:duplicate-base-slot-refuses´
#[test]
fn duplicate_base_slot_refuses() {
    let error = render(
        b"{{overlay:sec:example:used}}\n{{overlay:sec:example:used}}\n",
        b"## Used \xc2\xb7 `sec:example:used`\nbody\n",
        None,
    )
    .expect_err("duplicate base slot");

    assert_eq!(error.reason(), RefusalReason::DuplicateSlot);
}

/// ´test:unit:slot-label-already-on-base-heading-refuses´
#[test]
fn slot_label_already_on_base_heading_refuses() {
    let error = render(
        b"## Generic \xc2\xb7 `sec:example:used`\n{{overlay:sec:example:used}}\n",
        b"## Instance \xc2\xb7 `sec:example:used`\nbody\n",
        None,
    )
    .expect_err("base heading conflict");

    assert_eq!(error.reason(), RefusalReason::BaseHeadingConflict);
}

/// ´test:unit:leftover-overlay-marker-refuses´
#[test]
fn leftover_overlay_marker_refuses() {
    let error = render(
        b"{{overlay:sec:example:used}}\nprefix {{overlay:sec:example:leftover}}\n",
        b"## Used \xc2\xb7 `sec:example:used`\nbody\n",
        None,
    )
    .expect_err("leftover marker");

    assert_eq!(error.reason(), RefusalReason::LeftoverSlot);
}

/// ´test:unit:overlay-must-start-with-a-complete-labeled-section´
#[test]
fn overlay_must_start_with_a_complete_labeled_section() {
    let error = render(
        b"{{overlay:sec:example:used}}\n",
        b"preamble\n## Used \xc2\xb7 `sec:example:used`\nbody\n",
        None,
    )
    .expect_err("overlay preamble");

    assert_eq!(error.reason(), RefusalReason::OverlayShape);
}

/// ´test:unit:rendered-size-cap-is-inclusive-and-refuses-before-target-touch´
#[test]
fn rendered_size_cap_is_inclusive_and_refuses_before_target_touch() {
    let base = b"{{overlay:sec:example:used}}\n";
    let overlay = b"## Used \xc2\xb7 `sec:example:used`\nbody\n";
    let exact = render(base, overlay, None).expect("uncapped render");
    assert_eq!(
        render(base, overlay, Some(exact.len() as u64)).expect("inclusive cap"),
        exact
    );

    let fixture = Fixture::new();
    fixture.source("base.md", base);
    fixture.source("overlay.md", overlay);
    let target = fixture.target("target.md", b"old\n", 0o644);
    let before = stamp(&target);
    let map = render_map("base.md", "overlay.md", "target.md", exact.len() as u64 - 1);

    let error = fixture.run(&map, false).expect_err("oversized render");

    assert_eq!(error.class(), RefusalClass::Render);
    assert_eq!(error.reason(), RefusalReason::RenderedSize);
    assert_eq!(stamp(&target), before);
    assert!(!target.with_file_name("target.md.pre-deploy").exists());
}

/// ´test:unit:dry-run-plans-new-and-changed-targets-with-zero-mutation´
#[test]
fn dry_run_plans_new_and_changed_targets_with_zero_mutation() {
    let fixture = Fixture::new();
    fixture.source("one.md", b"new-one\n");
    fixture.source("two.md", b"new-two\n");
    let changed = fixture.target("changed.md", b"old\n", 0o644);
    let before = stamp(&changed);
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"one.md\"\ndestination = \"changed.md\"\nmode = \"0644\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"two.md\"\ndestination = \"missing/target.md\"\nmode = \"0644\"\n"
    );

    let report = fixture.run(&map, true).expect("dry-run plan");

    assert_eq!(report.targets[0].outcome, TargetOutcome::Changed);
    assert_eq!(report.targets[1].outcome, TargetOutcome::New);
    assert!(report.targets[0].before.is_some());
    assert!(report.targets[0].after.is_none());
    assert!(report.targets[1].before.is_none());
    assert!(report.targets[1].after.is_none());
    assert!(report.targets.iter().all(|target| !target.touched));
    assert!(report.targets.iter().all(|target| target.replacements == 0));
    assert_eq!(
        report.targets[0]
            .backup
            .as_ref()
            .expect("planned backup")
            .disposition,
        BackupDisposition::Planned
    );
    assert_eq!(stamp(&changed), before);
    assert!(!changed.with_file_name("changed.md.pre-deploy").exists());
    assert!(!fixture.root.join("missing").exists());
}

/// ´test:unit:refusal-class-exit-statuses-are-distinct´
#[test]
fn refusal_class_exit_statuses_are_distinct() {
    let classes = [
        RefusalClass::Map,
        RefusalClass::Source,
        RefusalClass::Render,
        RefusalClass::Destination,
        RefusalClass::ConcurrentChange,
        RefusalClass::Backup,
        RefusalClass::Install,
        RefusalClass::Verification,
    ];
    let statuses = classes.map(RefusalClass::exit_status);
    let distinct = statuses
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(statuses, [3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(distinct.len(), classes.len());
}

/// ´test:unit:success-report-has-target-summary-and-one-terminal-run-report´
#[test]
fn success_report_has_target_summary_and_one_terminal_run_report() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"content\n");
    let result = fixture.run(&copy_map("source.md", "target.md", "0644"), true);
    let mut output = Vec::new();

    write_report(&result, Duration::from_millis(12), &mut output).expect("publish report");
    let text = std::str::from_utf8(&output).expect("UTF-8 report");

    assert!(text.starts_with("target=1 outcome=new"));
    assert!(text.contains("summary unchanged=0 new=1 changed=0 refused=0"));
    assert!(text.ends_with("RUN-REPORT exit=0 wall=0.012s verdict=ok\n"));
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
}

/// ´test:unit:refusal-report-carries-class-counts-and-matching-exit´
#[test]
fn refusal_report_carries_class_counts_and_matching_exit() {
    let fixture = Fixture::new();
    let result = fixture.run(&copy_map("missing.md", "target.md", "0644"), false);
    let mut output = Vec::new();

    write_report(&result, Duration::from_secs(2), &mut output).expect("publish refusal");
    let text = std::str::from_utf8(&output).expect("UTF-8 report");

    assert!(text.contains("target=1 outcome=refused class=source reason=source_missing"));
    assert!(text.contains("summary unchanged=0 new=0 changed=0 refused=1"));
    assert!(text.ends_with("RUN-REPORT exit=4 wall=2.000s verdict=refused\n"));
}

fn build_fixture(fixture: &Fixture, record_domain: &str) -> PathBuf {
    let root = fixture.temporary.path().join("build-root");
    fs::create_dir_all(root.join("bin")).expect("build fixture directory");
    fs::write(root.join("bin/tool"), b"fixture executable").expect("build output");
    let digest = super::hex_digest(b"fixture executable");
    fs::write(root.join("bin/tool.build.json"), serde_json::json!({"bin":"tool","build_wall_ms":1,"cargo_version":"cargo fixture","domain":record_domain,"installed_name":"tool","package":"fixture","profile":"release","release_group":"fixture","repository":"fixture","rustc_version":"rustc fixture","sha256":digest,"source_commit":"a".repeat(40),"version":"0.1.0","written":"2026-01-01T00:00:00Z"}).to_string()).expect("build record");
    root
}

fn build_map(root: &Path, domain: &str) -> String {
    format!(
        "root = \"{}\"\n\n[[targets]]\nkind = \"build\"\noutput = \"bin/tool\"\ndestination = \"tool\"\nmode = \"0755\"\ndomain = \"{domain}\"\n",
        root.display()
    )
}

/// ´test:unit:build-target-validates-record-and-installs-provenance´
#[test]
fn build_target_validates_record_and_installs_provenance() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"tracked\n");
    fixture.commit();
    let build_root = build_fixture(&fixture, "trusted-host");
    fs::write(&fixture.map, build_map(&fixture.root, "trusted-host")).expect("map");
    let mut request = fixture.request(false);
    request.build_root = Some(&build_root);
    let first = install(request).expect("first build install");
    assert_eq!(first.count(TargetOutcome::New), 2);
    let binary = fixture.root.join("tool");
    let provenance = fixture.root.join("tool.provenance");
    assert_eq!(fs::read(&binary).expect("output"), b"fixture executable");
    let bytes = fs::read_to_string(&provenance).expect("provenance");
    assert!(bytes.contains("built: 2026-01-01T00:00:00Z\n"));
    assert!(bytes.contains("sha256-prefix: "));
    assert_eq!(stamp(&provenance).2, 0o644);
    let binary_stamp = stamp(&binary);
    let provenance_stamp = stamp(&provenance);
    let second = install(request).expect("second build install");
    assert_eq!(second.count(TargetOutcome::Unchanged), 2);
    assert_eq!(stamp(&binary), binary_stamp);
    assert_eq!(stamp(&provenance), provenance_stamp);
    fixture.commit();
    let third = install(request).expect("new commit over equal binary");
    assert_eq!(third.count(TargetOutcome::Unchanged), 1);
    assert_eq!(third.count(TargetOutcome::Changed), 1);
    assert_eq!(stamp(&binary), binary_stamp);
    assert_ne!(stamp(&provenance), provenance_stamp);
}

/// ´test:unit:copy-provenance-changes-with-commit-over-equal-source´
#[test]
fn copy_provenance_changes_with_commit_over_equal_source() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"same\n");
    fixture.commit();
    let map = format!(
        "{}provenance = true\n",
        copy_map("source.md", "target.md", "0644")
    );
    fixture.run(&map, false).expect("first copy");
    let target = fixture.root.join("target.md");
    let target_stamp = stamp(&target);
    let provenance = fixture.root.join("target.md.provenance");
    let before = stamp(&provenance);
    let second = fixture.run(&map, false).expect("second copy");
    assert_eq!(second.count(TargetOutcome::Unchanged), 2);
    fixture.commit();
    let third = fixture.run(&map, false).expect("new commit");
    assert_eq!(third.count(TargetOutcome::Changed), 1);
    assert_eq!(stamp(&target), target_stamp);
    assert_ne!(stamp(&provenance), before);
}

/// ´test:unit:build-refusals-cover-boundary-record-and-digest´
#[test]
fn build_refusals_cover_boundary_record_and_digest() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"tracked\n");
    fixture.commit();
    let build_root = build_fixture(&fixture, "trusted-host");
    let mut map = build_map(&fixture.root, "trusted-host");
    fs::write(&fixture.map, &map).expect("map");
    let mut request = fixture.request(false);
    assert_eq!(
        install(request).expect_err("missing build root").reason(),
        RefusalReason::BuildRootMissing
    );
    request.build_root = Some(&build_root);
    map = map.replace("bin/tool", "../escape");
    fs::write(&fixture.map, &map).expect("escape map");
    assert_eq!(
        install(request).expect_err("escape output").reason(),
        RefusalReason::InvalidRelativePath
    );
    map = map.replace("../escape", "bin/missing");
    fs::write(&fixture.map, &map).expect("missing map");
    assert_eq!(
        install(request).expect_err("missing output").reason(),
        RefusalReason::SourceMissing
    );
    fs::write(&fixture.map, build_map(&fixture.root, "trusted-host")).expect("valid map");
    fs::remove_file(build_root.join("bin/tool.build.json")).expect("remove record");
    assert_eq!(
        install(request).expect_err("missing record").reason(),
        RefusalReason::BuildRecordMissing
    );
    build_fixture(&fixture, "trusted-host");
    fs::write(build_root.join("bin/tool"), b"tampered").expect("tamper output");
    assert_eq!(
        install(request).expect_err("digest mismatch").reason(),
        RefusalReason::BuildDigestMismatch
    );
}

/// ´test:unit:staged-domain-mismatch-is-installed-and-counted´
#[test]
fn staged_domain_mismatch_is_installed_and_counted() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"tracked\n");
    fixture.commit();
    let build_root = build_fixture(&fixture, "server");
    fs::write(&fixture.map, build_map(&fixture.root, "trusted-host")).expect("map");
    let mut request = fixture.request(false);
    request.build_root = Some(&build_root);
    let report = install(request).expect("staged install");
    assert_eq!(report.count(TargetOutcome::DomainMismatch), 1);
    assert_eq!(report.count(TargetOutcome::New), 2);
    assert!(fixture.root.join("tool.provenance").exists());
}

/// ´test:unit:release-pair-requires-tag-head-and-clean-tree´
#[test]
fn release_pair_requires_tag_head_and_clean_tree() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"tracked\n");
    let commit = fixture.commit();
    fixture.git(&["tag", "fixture-tag"]);
    fs::write(
        &fixture.map,
        copy_map("source.md", "target.md", "0644")
            .replace(MAP_ROOT, &fixture.root.to_string_lossy()),
    )
    .expect("map");
    let mut request = fixture.request(false);
    request.root_override = None;
    assert_eq!(
        install(request).expect_err("live needs pair").reason(),
        RefusalReason::ReleaseIdentity
    );
    request.release_tag = Some("fixture-tag");
    assert_eq!(
        install(request).expect_err("pair incomplete").reason(),
        RefusalReason::ReleaseIdentity
    );
    request.release_commit = Some("wrong");
    assert_eq!(
        install(request).expect_err("wrong commit").reason(),
        RefusalReason::ReleaseIdentity
    );
    request.release_commit = Some(&commit);
    let report = install(request).expect("matching release pair");
    assert_eq!(report.identity, commit);
    fixture.source("source.md", b"dirty\n");
    assert_eq!(
        install(request).expect_err("dirty release").reason(),
        RefusalReason::ReleaseIdentity
    );
    let next_commit = fixture.commit();
    request.release_commit = Some(&next_commit);
    assert_eq!(
        install(request).expect_err("tag on older commit").reason(),
        RefusalReason::ReleaseIdentity
    );
}

/// ´test:unit:live-build-domain-mismatch-refuses-before-install´
#[test]
fn live_build_domain_mismatch_refuses_before_install() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"tracked\n");
    let commit = fixture.commit();
    fixture.git(&["tag", "fixture-tag"]);
    let build_root = build_fixture(&fixture, "server");
    fs::write(&fixture.map, build_map(&fixture.root, "trusted-host")).expect("map");
    let mut request = fixture.request(false);
    request.root_override = None;
    request.build_root = Some(&build_root);
    request.release_tag = Some("fixture-tag");
    request.release_commit = Some(&commit);
    let error = install(request).expect_err("live domain mismatch");
    assert_eq!(error.reason(), RefusalReason::DomainMismatch);
    assert!(!fixture.root.join("tool").exists());
}

/// ´test:unit:registry-roots-install-in-file-order-and-name-missing-loop´
#[test]
fn registry_roots_install_in_file_order_and_name_missing_loop() {
    let fixture = Fixture::new();
    fixture.source("source.md", b"charter\n");
    let registry = fixture.temporary.path().join("registry.toml");
    fs::write(&registry, include_str!("../tests/fixtures/registry.toml"))
        .expect("registry fixture");
    let roots = fixture.temporary.path().join("registry-roots");
    fs::create_dir_all(roots.join("alpha")).expect("alpha root");
    fs::create_dir_all(roots.join("beta")).expect("beta root");
    fs::write(&fixture.map, "[registry]\npath = \"~/.config/loops/registry.toml\"\nroot = \"~/.claude-{name}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"CLAUDE.md\"\nmode = \"0644\"\n").expect("registry map");
    let mut request = fixture.request(false);
    request.root_override = Some(&roots);
    request.registry_override = Some(&registry);
    let first = install(request).expect("both registry roots");
    assert_eq!(first.count(TargetOutcome::New), 2);
    assert_eq!(
        fs::read(roots.join("alpha/CLAUDE.md")).expect("alpha copy"),
        b"charter\n"
    );
    assert_eq!(
        fs::read(roots.join("beta/CLAUDE.md")).expect("beta copy"),
        b"charter\n"
    );
    fs::remove_dir_all(roots.join("beta")).expect("remove beta root");
    let error = install(request).expect_err("missing beta root");
    assert_eq!(error.reason(), RefusalReason::RegistryRootMissing);
    assert_eq!(error.loop_name(), Some("beta"));
    let mut output = Vec::new();
    write_report(&Err(error), Duration::ZERO, &mut output).expect("refusal report");
    assert!(
        String::from_utf8(output)
            .expect("report")
            .contains(&format!(
                "reason=root-unavailable loop=beta root={}",
                roots.join("beta").display()
            ))
    );
    let map = fs::read_to_string(&fixture.map).expect("map");
    fs::write(
        &fixture.map,
        map.replace("[registry]", "[registry]\nmissing_root = \"skip\""),
    )
    .expect("skip map");
    let report = install(request).expect("skip beta");
    assert_eq!(
        report.skipped_roots,
        vec![RegistryRoot {
            loop_name: "beta".to_owned(),
            root: roots.join("beta"),
            reason: RefusalReason::RootUnavailable,
        }]
    );
    assert_eq!(report.count(TargetOutcome::Unchanged), 1);
    assert!(!roots.join("beta").exists());
}

/// ´test:unit:root-and-registry-are-exclusive´
#[test]
fn root_and_registry_are_exclusive() {
    let fixture = Fixture::new();
    let map = format!(
        "root = \"{MAP_ROOT}\"\n[registry]\npath = \"~/.config/loops/registry.toml\"\nroot = \"~/.claude-{{name}}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"CLAUDE.md\"\nmode = \"0644\"\n"
    );
    let error = fixture.run(&map, false).expect_err("exclusive roots");
    assert_eq!(error.reason(), RefusalReason::TargetShape);
}

/// ´test:unit:provenance-sibling-is-reserved-from-map-destinations´
#[test]
fn provenance_sibling_is_reserved_from_map_destinations() {
    let fixture = Fixture::new();
    let map = format!(
        "root = \"{MAP_ROOT}\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"target.md\"\nmode = \"0644\"\nprovenance = true\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"target.md.provenance\"\nmode = \"0644\"\n"
    );
    let error = fixture.run(&map, false).expect_err("provenance collision");
    assert_eq!(error.reason(), RefusalReason::ProvenanceCollision);
}
