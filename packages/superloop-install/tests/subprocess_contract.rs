//! # `superloop-install` subprocess contract matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Control paths | 2 | Help and usage end in one status-matching agent-text report |
//! | Install paths | 2 | Successful copy and source refusal publish target lines, summaries, and matching statuses |
//! | Staging | 1 | Home roots resolve through HOME and DESTDIR stages without live mutation |
//! | Registry | 9 | Missing, unsafe, inaccessible and invalid roots retain their causes; release identity precedes root checks; owner-owned 0700 roots admit ACLs |

use std::process::{Command, Output};

/// # Panics
/// Panics only if fixture setup or the owned charter-map contract fails.
/// ´test:integration:charter-map-installs-every-prepared-registered-claude-home´
#[test]
fn charter_map_installs_every_prepared_registered_claude_home() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = tempfile::tempdir().expect("charter fixture");
    let home = fixture.path().join("fixture-owner");
    for name in ["alpha", "beta"] {
        let path = home.join(".config/loops").join(name).join("claude");
        fs::create_dir_all(&path).expect("prepared home");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private home");
    }
    let registry = home.join(".config/loops/registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{name = \"alpha\", uid = 41001, launch = \"dev/alpha\"}, {name = \"beta\", uid = 41002, launch = \"dev/beta\"}]\n").expect("registry");
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let repository = fixtures.join("repository");
    for repeated in [false, true] {
        let output = command()
            .current_dir(&repository)
            .env("HOME", "/fixture-owner")
            .arg("--map")
            .arg(fixtures.join("maps/charter.toml"))
            .arg("--registry")
            .arg(&registry)
            .arg("--destdir")
            .arg(fixture.path())
            .output()
            .expect("charter install");
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("skipped=0"), "{text}");
        assert!(
            text.contains(if repeated { "unchanged=2" } else { "new=2" }),
            "{text}"
        );
    }
    for name in ["alpha", "beta"] {
        assert_eq!(
            fs::read(
                home.join(".config/loops")
                    .join(name)
                    .join("claude/CLAUDE.md")
            )
            .expect("charter"),
            fs::read(repository.join("copy.md")).expect("fixture publication")
        );
        assert!(!home.join(format!(".claude-{name}")).exists());
    }
}

struct RootFixture {
    temporary: tempfile::TempDir,
    root: std::path::PathBuf,
    registry: std::path::PathBuf,
    map: std::path::PathBuf,
}

impl RootFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("root fixture");
        let root = temporary.path().join("roots/alpha");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(temporary.path().join("source.md"), "charter\n").expect("source");
        let registry = temporary.path().join("registry.toml");
        std::fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"work/alpha\" }]\n").expect("registry");
        let map = temporary.path().join("map.toml");
        std::fs::write(&map, "[registry]\npath = \"~/.config/loops/registry.toml\"\nroot = \"~/roots/{name}\"\nmissing_root = \"skip\"\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"CLAUDE.md\"\nmode = \"0644\"\n").expect("map");
        Self {
            temporary,
            root,
            registry,
            map,
        }
    }

    fn command(&self) -> Command {
        let mut command = command();
        command
            .current_dir(self.temporary.path())
            .env("HOME", self.temporary.path())
            .args(["--map"])
            .arg(&self.map)
            .arg("--registry")
            .arg(&self.registry)
            .arg("--build-root")
            .arg(self.temporary.path())
            .arg("--dry-run");
        command
    }

    fn staged(&self) -> Command {
        let mut command = self.command();
        command
            .arg("--root")
            .arg(self.root.parent().expect("root parent"));
        command
    }

    fn assert_release_refusal(&self, output: &Output) {
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(text.matches("reason=release_identity").count(), 1, "{text}");
        assert!(
            text.contains(
                "target=map outcome=refused class=map reason=release_identity touched=no"
            ),
            "{text}"
        );
        assert!(text.contains(&format!("target=registry outcome=not_reached class=plan reason=plan_refused loop=alpha root={} touched=no", self.root.display())), "{text}");
        assert!(!text.contains("cause="), "{text}");
        assert_eq!(report_count(output), 1);
    }

    fn assert_refusal(&self, output: &Output, root: &std::path::Path, cause: &str) {
        assert_eq!(
            output.status.code(),
            Some(if cause == "invalid_root" { 3 } else { 6 })
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains(&format!("loop=alpha root={} cause={cause}", root.display())),
            "{text}"
        );
        assert!(text.contains("outcome=refused"), "{text}");
        assert!(!self.root.join("CLAUDE.md").exists());
        assert_eq!(report_count(output), 1);
    }
}

/// ´test:integration:registry-root-symlink-retains-cause´
#[test]
fn registry_root_symlink_retains_cause() {
    let fixture = RootFixture::new();
    std::fs::remove_dir(&fixture.root).expect("remove root");
    std::os::unix::fs::symlink(fixture.temporary.path(), &fixture.root).expect("symlink");
    fixture.assert_refusal(
        &fixture.staged().output().expect("install"),
        &fixture.root,
        "root_symlink",
    );
    let mut staged = fixture.command();
    staged.arg("--destdir").arg(&fixture.root);
    let destination = fixture
        .root
        .join(fixture.root.strip_prefix("/").expect("absolute root"));
    fixture.assert_refusal(
        &staged.output().expect("prefix install"),
        &destination,
        "root_symlink",
    );
}

/// ´test:integration:registry-root-nondirectory-retains-cause´
#[test]
fn registry_root_nondirectory_retains_cause() {
    let fixture = RootFixture::new();
    std::fs::remove_dir(&fixture.root).expect("remove root");
    std::fs::write(&fixture.root, "not a directory").expect("file root");
    fixture.assert_refusal(
        &fixture.staged().output().expect("install"),
        &fixture.root,
        "root_not_directory",
    );
}

/// ´test:integration:registry-root-inaccessible-retains-cause´
#[test]
fn registry_root_inaccessible_retains_cause() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = RootFixture::new();
    let parent = fixture.root.parent().expect("parent");
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o0)).expect("deny traversal");
    let output = fixture.staged().output().expect("install");
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .expect("restore traversal");
    fixture.assert_refusal(&output, &fixture.root, "root_inaccessible");
}

/// ´test:integration:registry-root-metadata-error-retains-cause´
#[test]
fn registry_root_metadata_error_retains_cause() {
    let fixture = RootFixture::new();
    let parent = fixture.temporary.path().join("x".repeat(256));
    let output = fixture
        .command()
        .arg("--root")
        .arg(&parent)
        .output()
        .expect("install");
    fixture.assert_refusal(&output, &parent.join("alpha"), "root_metadata");
}

/// ´test:integration:registry-root-relative-path-retains-cause´
#[test]
fn registry_root_relative_path_retains_cause() {
    let fixture = RootFixture::new();
    let output = fixture
        .command()
        .args(["--root", "relative"])
        .output()
        .expect("install");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("class=map reason=invalid_root loop=alpha")
    );
    fixture.assert_refusal(
        &output,
        std::path::Path::new("relative/alpha"),
        "invalid_root",
    );
}

/// ´test:integration:registry-hand-form-names-release-identity-before-roots´
#[test]
fn registry_hand_form_names_release_identity_before_roots() {
    let fixture = RootFixture::new();
    for root_present in [true, false] {
        if !root_present {
            std::fs::remove_dir(&fixture.root).expect("remove root");
        }
        let output = fixture.command().output().expect("hand install");
        fixture.assert_release_refusal(&output);
        let output = fixture
            .command()
            .arg("--destdir")
            .arg(fixture.temporary.path().join("stage"))
            .output()
            .expect("destdir install");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// ´test:integration:registry-resolution-failure-preserves-release-identity´
#[test]
fn registry_resolution_failure_preserves_release_identity() {
    for reason in ["registry_read", "invalid_root"] {
        let fixture = RootFixture::new();
        if reason == "registry_read" {
            std::fs::remove_file(&fixture.registry).expect("remove registry");
        } else {
            let map = std::fs::read_to_string(&fixture.map).expect("read map");
            std::fs::write(&fixture.map, map.replace("~/roots/{name}", "~/roots"))
                .expect("invalid root pattern");
        }
        let output = fixture.command().output().expect("hand install");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(text.matches("reason=release_identity").count(), 1, "{text}");
        assert!(
            text.contains(
                "target=map outcome=refused class=map reason=release_identity touched=no"
            ),
            "{text}"
        );
        assert!(text.contains(&format!("target=registry outcome=unresolved class=map reason={reason} stage=root_resolution touched=no")), "{text}");
        assert!(!text.contains("cause="), "{text}");
        assert_eq!(report_count(&output), 1);
    }
}

#[allow(unsafe_code)]
fn add_masked_acl(root: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(root.as_os_str().as_bytes()).expect("fixture path");
    let mut value = 2_u32.to_le_bytes().to_vec();
    for (tag, permission, id) in [
        (1_u16, 7_u16, u32::MAX),
        (2, 7, nix::unistd::geteuid().as_raw() + 1),
        (4, 0, u32::MAX),
        (16, 0, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        value.extend(tag.to_le_bytes());
        value.extend(permission.to_le_bytes());
        value.extend(id.to_le_bytes());
    }
    // SAFETY: both names are NUL-terminated, and value remains readable for its exact length throughout the call.
    let result = unsafe {
        nix::libc::setxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(
        result,
        0,
        "ACL fixture: {}",
        std::io::Error::last_os_error()
    );
}

/// ´test:integration:registry-owner-root-admits-masked-acl´
#[test]
fn registry_owner_root_admits_masked_acl() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let fixture = RootFixture::new();
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    for acl in [false, true] {
        if acl {
            add_masked_acl(&fixture.root);
        }
        let metadata = std::fs::metadata(&fixture.root).expect("root metadata");
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o700);
        let output = fixture.staged().output().expect("install");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!fixture.root.join("CLAUDE.md").exists());
        let output = fixture.command().output().expect("hand install");
        fixture.assert_release_refusal(&output);
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_superloop-install"))
}

/// ´test:integration:registry-missing-root-policy-reports-every-loop´
#[test]
fn registry_missing_root_policy_reports_every_loop() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("registry fixture");
    let repository = fixture.path().join("repository");
    let roots = fixture.path().join("roots");
    fs::create_dir(&repository).expect("repository");
    fs::create_dir_all(roots.join("alpha")).expect("alpha");
    fs::create_dir_all(roots.join("gamma")).expect("gamma");
    fs::write(repository.join("source.md"), "charter\n").expect("source");
    let registry = fixture.path().join("registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"work/alpha\" }, { name = \"beta\", uid = 41002, launch = \"work/beta\" }, { name = \"gamma\", uid = 41003, launch = \"work/gamma\" }]\n").expect("registry");
    let map = fixture.path().join("map.toml");
    let run = |policy: &str| {
        fs::write(&map, format!("[registry]\npath = \"~/.config/loops/registry.toml\"\nroot = \"~/.claude-{{name}}\"\n{policy}\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"CLAUDE.md\"\nmode = \"0644\"\n")).expect("map");
        command()
            .current_dir(&repository)
            .args(["--map"])
            .arg(&map)
            .arg("--root")
            .arg(&roots)
            .arg("--registry")
            .arg(&registry)
            .output()
            .expect("registry install")
    };
    let reason = format!(
        "reason=root-unavailable loop=beta root={}",
        roots.join("beta").display()
    );
    for policy in ["", "missing_root = \"refuse\""] {
        let output = run(policy);
        assert_eq!(output.status.code(), Some(6));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("{reason} cause=root_unavailable"))
        );
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert!(!roots.join("alpha/CLAUDE.md").exists());
        assert!(!roots.join("gamma/CLAUDE.md").exists());
    }
    let output = run("missing_root = \"skip\"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(&format!("outcome=skipped class=destination {reason}")));
    assert!(text.contains(&format!("{reason} cause=root_unavailable")));
    assert_eq!(text.matches("outcome=skipped").count(), 1);
    assert!(text.contains("new=2 changed=0 refused=0"));
    assert!(text.contains("skipped=1"));
    assert!(!roots.join("beta").exists());
    for name in ["alpha", "gamma"] {
        assert_eq!(
            fs::read_to_string(roots.join(name).join("CLAUDE.md")).expect("charter"),
            "charter\n"
        );
    }
    fs::remove_dir_all(roots.join("gamma")).expect("remove gamma");
    let output = run("");
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(text.matches("reason=root-unavailable").count(), 2);
    assert!(text.contains("loop=gamma root="));
    symlink(roots.join("alpha"), roots.join("beta")).expect("unsafe root");
    let output = run("missing_root = \"skip\"");
    assert_eq!(output.status.code(), Some(6));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(&format!("outcome=refused class=destination {reason}")));
    assert!(text.contains("outcome=skipped class=destination reason=root-unavailable loop=gamma"));
    assert!(text.contains("skipped=1"));
    assert!(text.contains("refused=2"));
    assert_eq!(run("missing_root = \"ignore\"").status.code(), Some(3));
}

fn report_count(output: &Output) -> usize {
    output
        .stdout
        .windows(b"RUN-REPORT".len())
        .filter(|window| *window == b"RUN-REPORT")
        .count()
}

/// ´test:integration:help-is-agent-text-success-with-one-terminal-report´
#[test]
fn help_is_agent_text_success_with_one_terminal_report() {
    let output = command().arg("--help").output().expect("help subprocess");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output
            .stdout
            .starts_with(b"Render and transactionally install")
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("--shape-root <PATH>"));
    assert!(output.stdout.ends_with(b"verdict=ok\n"));
    assert_eq!(report_count(&output), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:usage-refusal-is-path-free-and-status-matched´
#[test]
fn usage_refusal_is_path_free_and_status_matched() {
    let output = command()
        .arg("--unknown=SHOULD_NOT_APPEAR")
        .output()
        .expect("usage subprocess");
    let text = String::from_utf8(output.stdout).expect("UTF-8 usage report");

    assert_eq!(output.status.code(), Some(2));
    assert!(text.starts_with("superloop-install: usage_error:"));
    assert!(!text.contains("SHOULD_NOT_APPEAR"));
    assert!(text.ends_with("verdict=FAILED\n"));
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:copy-success-publishes-target-summary-and-terminal-report´
#[test]
fn copy_success_publishes_target_summary_and_terminal_report() {
    let fixture = tempfile::tempdir().expect("subprocess fixture");
    let repository = fixture.path().join("repository");
    let root = fixture.path().join("root");
    std::fs::create_dir(&repository).expect("repository root");
    std::fs::create_dir(&root).expect("destination root");
    std::fs::write(repository.join("source.md"), b"candidate\n").expect("source bytes");
    let map = fixture.path().join("map.toml");
    std::fs::write(
        &map,
        "root = \"/srv/example/example-user/harness\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"target.md\"\nmode = \"0644\"\n",
    )
    .expect("map bytes");

    let output = command()
        .current_dir(&repository)
        .arg("--map")
        .arg(&map)
        .arg("--root")
        .arg(&root)
        .output()
        .expect("install subprocess");
    let text = String::from_utf8(output.stdout).expect("UTF-8 success report");

    assert_eq!(output.status.code(), Some(0));
    assert!(text.starts_with("target=1 outcome=new"));
    assert!(text.contains("summary unchanged=0 new=1 changed=0 refused=0"));
    assert!(text.ends_with("verdict=ok\n"));
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        std::fs::read(root.join("target.md")).expect("installed target"),
        b"candidate\n"
    );
}

/// ´test:integration:source-refusal-uses-its-declared-exit-and-does-not-echo-path´
#[test]
fn source_refusal_uses_its_declared_exit_and_does_not_echo_path() {
    let fixture = tempfile::tempdir().expect("subprocess fixture");
    let repository = fixture.path().join("repository");
    let root = fixture.path().join("root");
    std::fs::create_dir(&repository).expect("repository root");
    std::fs::create_dir(&root).expect("destination root");
    let map = fixture.path().join("map.toml");
    std::fs::write(
        &map,
        "root = \"/srv/example/example-user/harness\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"SHOULD_NOT_APPEAR.md\"\ndestination = \"target.md\"\nmode = \"0644\"\n",
    )
    .expect("map bytes");

    let output = command()
        .current_dir(&repository)
        .arg("--map")
        .arg(&map)
        .arg("--root")
        .arg(&root)
        .output()
        .expect("refusal subprocess");
    let text = String::from_utf8(output.stdout).expect("UTF-8 refusal report");

    assert_eq!(output.status.code(), Some(4));
    assert!(text.contains("outcome=refused class=source reason=source_missing"));
    assert!(!text.contains("SHOULD_NOT_APPEAR"));
    assert!(text.ends_with("verdict=refused\n"));
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!root.join("target.md").exists());
}

/// ´test:integration:home-root-and-destdir-stage-without-live-mutation´
#[test]
fn home_root_and_destdir_stage_without_live_mutation() {
    let fixture = tempfile::tempdir().expect("subprocess fixture");
    let repository = fixture.path().join("repository");
    let home = fixture.path().join("home");
    let stage = fixture.path().join("stage");
    std::fs::create_dir(&repository).expect("repository");
    std::fs::create_dir(&home).expect("home");
    std::fs::create_dir(&stage).expect("stage");
    std::fs::write(repository.join("source.md"), b"staged\n").expect("source");
    let map = fixture.path().join("map.toml");
    std::fs::write(&map, "root = \"~/.local/bin\"\n\n[[targets]]\nkind = \"copy\"\nsource = \"source.md\"\ndestination = \"tool\"\nmode = \"0755\"\n").expect("map");
    let run = || {
        command()
            .current_dir(&repository)
            .env("HOME", &home)
            .arg("--map")
            .arg(&map)
            .arg("--destdir")
            .arg(&stage)
            .output()
            .expect("staged install")
    };
    let first = run();
    assert_eq!(first.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&first.stdout).contains("identity=untagged"));
    let staged = stage
        .join(home.strip_prefix("/").expect("absolute home"))
        .join(".local/bin/tool");
    assert_eq!(std::fs::read(staged).expect("staged output"), b"staged\n");
    assert!(!home.join(".local/bin/tool").exists());
    let second = run();
    assert!(String::from_utf8_lossy(&second.stdout).contains("new=0 changed=0"));
}
