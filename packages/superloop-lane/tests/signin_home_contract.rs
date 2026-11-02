use std::process::Command;

struct CodexHomeFixture {
    root: tempfile::TempDir,
}

impl CodexHomeFixture {
    fn new() -> Self {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let root = tempfile::tempdir().expect("small metadata fixture");
        let owner = root.path();
        std::fs::set_permissions(owner, std::fs::Permissions::from_mode(0o700))
            .expect("protected owner");
        let charter =
            owner.join(".local/share/orchestration-instance/docs/tools/worker-charter.md");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(charter.parent().expect("charter parent"))
            .expect("publication");
        std::fs::write(&charter, "published worker charter\n").expect("charter");
        std::fs::write(owner.join("key"), "synthetic key\n").expect("key");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(owner.join(".config/loops"))
            .expect("configuration directory");
        std::fs::write(owner.join(".config/loops/registry.toml"), "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{name = 'alpha', uid = 2000, launch = 'src', session = 'fixture-session'}]\n").expect("loop configuration");
        let registry = owner.join(".local/share/orchestration-instance");
        std::fs::create_dir_all(&registry).expect("registry directory");
        std::fs::write(registry.join("servers.md"), format!("## Node routes\n|node|status|hostname|port|host_key_algorithm|host_key|loop|account|worker_alias|session_alias|worker_identity|session_identity|\n|---|---|---|---|---|---|---|---|---|---|---|---|\n|node-a|active|192.0.2.1|22|ssh-ed25519|AAAA|alpha|fixture|node-a-worker|node-a-session|{}/key|~/.ssh/session-key|\n", owner.display())).expect("registry");
        Self { root }
    }

    fn home(&self) -> std::path::PathBuf {
        self.root.path().join(".config/loops/alpha/codex")
    }

    fn command(&self, action: &str, home: Option<&std::path::Path>, uid: u32) -> Command {
        self.command_with_project(action, home, uid, true)
    }

    fn command_with_project(
        &self,
        action: &str,
        home: Option<&std::path::Path>,
        uid: u32,
        explicit_project: bool,
    ) -> Command {
        let owner = self.root.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command
            .args([
                action,
                "--backend",
                "codex",
                "alpha",
                "--nodes",
                "node-a",
                "--user",
                "fixture",
            ])
            .arg("--key")
            .arg(owner.join("key"))
            .env("HOME", owner)
            .env("SUPERLOOP_SIGNIN_TEST_OWNER_UID", uid.to_string());
        if explicit_project {
            command.arg("--project").arg(owner);
        }
        if let Some(home) = home {
            command.arg("--home").arg(home);
        }
        command
    }

    fn invoke(
        &self,
        action: &str,
        home: Option<&std::path::Path>,
        uid: u32,
    ) -> std::process::Output {
        self.command(action, home, uid)
            .output()
            .expect("production sign-in command")
    }

    fn check(&self) -> (Option<i32>, serde_json::Value) {
        let output = self.invoke(
            "check-signin-home",
            None,
            nix::unistd::Uid::effective().as_raw(),
        );
        let report = serde_json::from_slice(&output.stdout).expect("check JSON");
        (output.status.code(), report)
    }

    fn prepare(&self) {
        let output = self.invoke(
            "prepare-signin-home",
            None,
            nix::unistd::Uid::effective().as_raw(),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// # Panics
/// Panics only if the fixture or production command violates the record contract.
/// ´test:integration:codex-home-creates-registry-record-once´
#[test]
fn codex_home_creates_registry_record_once() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    let path = owner.join(".local/share/superloop-tools/loops.d/alpha.env");
    let configuration = owner.join(".config/loops/registry.toml");
    let mut command = fixture.command(
        "prepare-signin-home",
        None,
        nix::unistd::Uid::effective().as_raw(),
    );
    // Omit the explicit project so creation must use the configuration row.
    let mut derived = fixture.command_with_project(
        "prepare-signin-home",
        None,
        nix::unistd::Uid::effective().as_raw(),
        false,
    );
    let output = derived.output().expect("creation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = format!(
        "LOOP_NAME=alpha\nLOOP_SID=fixture-session\nLOOP_CWD={}/src\nLOOP_UID=2000\nLOOP_HOME={}/.var/loops/alpha\n",
        owner.display(),
        owner.display()
    );
    assert_eq!(std::fs::read_to_string(&path).expect("record"), expected);
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").mode() & 0o7777,
        0o600
    );
    assert!(
        std::fs::read_to_string(fixture.home().join("config.toml"))
            .expect("config")
            .contains(&format!("[projects.\"{}/src\"]", owner.display()))
    );
    std::fs::write(&configuration, "invalid configuration").expect("invalidate configuration");
    std::fs::write(&path, "LOOP_CWD=/owner/selected\n").expect("owner record");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("owner mode");
    let before = std::fs::metadata(&path).expect("before");
    let output = command.output().expect("repeat preparation");
    assert_eq!(output.status.code(), Some(3));
    let after = std::fs::metadata(&path).expect("after");
    assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
    assert_eq!(
        std::fs::read_to_string(&path).expect("preserved"),
        "LOOP_CWD=/owner/selected\n"
    );
}

/// # Panics
/// Panics only if the fixture or production command violates the refusal contract.
/// ´test:integration:codex-home-record-requires-session´
#[test]
fn codex_home_record_requires_session() {
    let fixture = CodexHomeFixture::new();
    let configuration = fixture.root.path().join(".config/loops/registry.toml");
    let source = std::fs::read_to_string(&configuration).expect("configuration");
    std::fs::write(
        &configuration,
        source.replace(", session = 'fixture-session'", ""),
    )
    .expect("no session");
    let output = fixture.invoke(
        "prepare-signin-home",
        None,
        nix::unistd::Uid::effective().as_raw(),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
        "registry-record: alpha: no session id: {}",
        configuration.display()
    )));
    assert!(!fixture.home().exists());
    assert!(
        !fixture
            .root
            .path()
            .join(".local/share/superloop-tools/loops.d/alpha.env")
            .exists()
    );
}

/// # Panics
/// Panics only if fixture setup or the production command violates the asserted contract.
/// ´test:integration:codex-home-location-findings-never-select-old-homes´
#[test]
fn codex_home_location_findings_never_select_old_homes() {
    use std::fs;
    use std::os::unix::fs::symlink;
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    let expected = fixture.home();
    let old = owner.join(".codex-alpha");
    fs::create_dir(&old).expect("old home");
    fs::write(old.join("config.toml"), "invalid TOML must not be read").expect("old config");
    let (status, report) = fixture.check();
    assert_eq!(status, Some(1));
    assert_eq!(report["home"], expected.to_string_lossy().as_ref());
    assert_eq!(report["missing"], serde_json::json!(["location"]));
    assert_eq!(
        report["location"][0]["actual"],
        old.to_string_lossy().as_ref()
    );
    assert_eq!(
        report["location"][0]["expected"],
        expected.to_string_lossy().as_ref()
    );
    assert!(!expected.exists());
    let refused = fixture.invoke(
        "prepare-signin-home",
        Some(&old),
        nix::unistd::Uid::effective().as_raw(),
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("location:"));
    fixture.prepare();
    assert_eq!(
        fixture.check().1["missing"],
        serde_json::json!(["location"])
    );
    assert_eq!(
        fs::read_to_string(old.join("config.toml")).expect("old config retained"),
        "invalid TOML must not be read"
    );
    fs::remove_dir_all(&old).expect("owner migration removes old location");
    assert_eq!(fixture.check().1["missing"], serde_json::json!(["sign-in"]));
    let outside = owner.join("elsewhere");
    let output = fixture.invoke(
        "check-signin-home",
        Some(&outside),
        nix::unistd::Uid::effective().as_raw(),
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("location JSON");
    assert_eq!(
        report["location"][0]["actual"],
        outside.to_string_lossy().as_ref()
    );
    assert!(!outside.exists());
    fs::rename(&expected, &outside).expect("move fixture home outside custody");
    symlink(&outside, &expected).expect("redirected home");
    assert_eq!(
        fixture.check().1["location"][0]["actual"],
        outside.to_string_lossy().as_ref()
    );
}

fn assert_root_variations(fixture: &CodexHomeFixture, config_path: &std::path::Path, config: &str) {
    use std::fs;
    let listed = "writable_roots = [\"/lane/clone\"]";
    fs::write(config_path, config.replace("writable_roots = []", listed)).expect("listed clone");
    let (status, report) = fixture.check();
    assert_eq!(status, Some(0));
    assert_eq!(report["varied"], serde_json::json!(["config-roots"]));
    assert_eq!(
        report["varied_lines"],
        serde_json::json!([{
            "label": "config-roots",
            "expected": "writable_roots = []",
            "actual": listed,
        }])
    );
    fs::write(config_path, config.replace("writable_roots = []\n", "")).expect("absent roots key");
    let (status, report) = fixture.check();
    assert_eq!(status, Some(0));
    assert_eq!(report["varied"], serde_json::json!(["config-roots"]));
    assert_eq!(
        report["varied_lines"],
        serde_json::json!([{
            "label": "config-roots",
            "expected": "writable_roots = []",
            "actual": null,
        }])
    );
}

/// # Panics
/// Panics only if fixture setup or the production command violates the asserted contract.
/// ´test:integration:codex-home-keeps-canonical-signin-and-owner-custody´
#[test]
fn codex_home_keeps_canonical_signin_and_owner_custody() {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    let expected = fixture.home();
    let uid = nix::unistd::Uid::effective().as_raw();
    fixture.prepare();
    assert_eq!(fs::metadata(&expected).expect("home").uid(), uid);
    assert_eq!(fs::metadata(&expected).expect("home").mode() & 0o777, 0o700);
    let source = owner.join(".config/loops/alpha/lanes/codex");
    fs::create_dir_all(&source).expect("canonical root");
    for path in [
        owner.to_path_buf(),
        owner.join(".config"),
        owner.join(".config/loops"),
        owner.join(".config/loops/alpha"),
        owner.join(".config/loops/alpha/lanes"),
        source.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("protected parent");
    }
    fs::write(source.join("auth.json"), "opaque synthetic credential").expect("canonical file");
    fs::set_permissions(source.join("auth.json"), fs::Permissions::from_mode(0o600))
        .expect("source mode");
    fixture.prepare();
    assert_eq!(
        fs::read_link(expected.join("auth.json")).expect("auth link"),
        source.join("auth.json")
    );
    assert_eq!(fixture.check().0, Some(0));
    assert_eq!(fixture.check().1["varied"], serde_json::json!([]));
    assert_eq!(fixture.check().1["varied_lines"], serde_json::json!([]));
    let config_path = expected.join("config.toml");
    let config = fs::read_to_string(&config_path).expect("config");
    assert_root_variations(&fixture, &config_path, &config);
    let varied = config
        .replace("writable_roots = []", "writable_roots = [\"/lane/clone\"]")
        .replace(
            &format!("[projects.\"{}\"]", owner.display()),
            "[projects.\"/lane/clone\"]",
        );
    fs::write(&config_path, &varied).expect("lane configuration");
    let (status, report) = fixture.check();
    assert_eq!(status, Some(0));
    assert_eq!(report["ok"], true);
    assert_eq!(report["missing"], serde_json::json!([]));
    assert_eq!(
        report["varied"],
        serde_json::json!(["config-roots", "config-project"])
    );
    assert_eq!(
        report["varied_lines"],
        serde_json::json!([
            {"label": "config-roots", "expected": "writable_roots = []", "actual": "writable_roots = [\"/lane/clone\"]"},
            {"label": "config-project", "expected": format!("[projects.\"{}\"]", owner.display()), "actual": "[projects.\"/lane/clone\"]"},
        ])
    );
    fs::write(
        &config_path,
        varied.replace("trust_level = \"trusted\"", "trust_level = \"untrusted\""),
    )
    .expect("owner trust choice");
    assert_eq!(fixture.check().0, Some(0));
    assert_eq!(
        fixture.check().1["varied"],
        serde_json::json!(["config-roots", "config-project", "config-trust"])
    );
    fs::write(&config_path, varied.replace("network_access = true\n", ""))
        .expect("missing required line");
    let (status, report) = fixture.check();
    assert_eq!(status, Some(1));
    assert_eq!(report["ok"], false);
    assert_eq!(report["missing"], serde_json::json!(["config-network"]));
    assert_eq!(
        report["varied"],
        serde_json::json!(["config-roots", "config-project"])
    );
    fs::write(&config_path, config).expect("restore configuration");
    #[cfg(debug_assertions)]
    {
        let foreign = if uid == 41001 { 41002 } else { 41001 };
        assert_ne!(uid, foreign);
        let refused = fixture
            .command("prepare-signin-home", None, uid)
            .env(
                "SUPERLOOP_SIGNIN_TEST_SOURCE_OWNER_UID",
                foreign.to_string(),
            )
            .output()
            .expect("canonical owner refusal");
        assert_eq!(refused.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("sign-in-source:"));
    }
}

/// # Panics
/// Panics only if fixture setup or the production command violates the asserted contract.
/// ´test:integration:codex-home-links-the-selected-charter-publication´
#[test]
fn codex_home_links_the_selected_charter_publication() {
    use std::fs;
    use std::os::unix::fs::symlink;
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    fixture.prepare();
    let agents = fixture.home().join("AGENTS.md");
    let charter = owner.join(".local/share/orchestration-instance/docs/tools/worker-charter.md");
    assert_eq!(fs::read_link(&agents).expect("charter route"), charter);
    assert_eq!(fixture.check().1["charter"], serde_json::json!(charter));
    assert_eq!(
        fs::read_to_string(&agents).expect("published bytes"),
        "published worker charter\n"
    );
    assert_eq!(fixture.check().1["missing"], serde_json::json!(["sign-in"]));
    fs::remove_file(&agents).expect("unlink charter");
    fs::create_dir(owner.join(".codex")).expect("old host directory");
    fs::write(owner.join(".codex/AGENTS.md"), "published worker charter\n")
        .expect("old charter copy");
    symlink(owner.join(".codex/AGENTS.md"), &agents).expect("retired charter route");
    assert_eq!(
        fixture.check().1["missing"],
        serde_json::json!(["sign-in", "AGENTS.md"])
    );
}

/// # Panics
/// Panics only if fixture setup or the command violates the no-write charter contract.
/// ´test:integration:codex-home-refuses-missing-or-nonfile-charter-before-creation´
#[test]
fn codex_home_refuses_missing_or_nonfile_charter_before_creation() {
    let fixture = CodexHomeFixture::new();
    let charter = fixture
        .root
        .path()
        .join(".local/share/orchestration-instance/docs/tools/worker-charter.md");
    std::fs::remove_file(&charter).expect("remove charter");
    for directory in [false, true] {
        if directory {
            std::fs::create_dir(&charter).expect("nonfile charter");
        }
        let output = fixture.invoke(
            "prepare-signin-home",
            None,
            nix::unistd::Uid::effective().as_raw(),
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
            "worker charter not found at {}; pass --charter or install the instance publication",
            charter.display()
        )));
        assert!(!fixture.home().exists());
        assert!(
            !fixture
                .root
                .path()
                .join(".local/share/superloop-tools/loops.d/alpha.env")
                .exists()
        );
    }
}

/// # Panics
/// Panics only if fixture setup or the command loses the supplied charter path.
/// ´test:integration:codex-home-resolves-explicit-relative-charter´
#[test]
fn codex_home_resolves_explicit_relative_charter() {
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    let selected = owner.join("selected.md");
    std::fs::write(&selected, "selected charter").expect("selected input");
    std::fs::remove_file(
        owner.join(".local/share/orchestration-instance/docs/tools/worker-charter.md"),
    )
    .expect("remove default");
    let uid = nix::unistd::Uid::effective().as_raw();
    let output = fixture
        .command("prepare-signin-home", None, uid)
        .current_dir(owner)
        .args(["--charter", "selected.md"])
        .output()
        .expect("prepare");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_link(fixture.home().join("AGENTS.md")).expect("link"),
        selected
    );
    let checked = fixture
        .command("check-signin-home", None, uid)
        .arg("--charter")
        .arg(&selected)
        .output()
        .expect("check");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).expect("report");
    assert_eq!(report["charter"], serde_json::json!(selected));
    assert_eq!(report["missing"], serde_json::json!(["sign-in"]));
}

/// # Panics
/// Panics only if the production command accepts a foreign owner or an unsafe parent.
/// ´test:integration:codex-home-refuses-foreign-owners-and-writable-parents´
#[test]
#[cfg(debug_assertions)]
fn codex_home_refuses_foreign_owners_and_writable_parents() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = CodexHomeFixture::new();
    let uid = nix::unistd::Uid::effective().as_raw();
    let foreign = if uid == 41001 { 41002 } else { 41001 };
    let refused = fixture.invoke("prepare-signin-home", None, foreign);
    assert_eq!(refused.status.code(), Some(2));
    let diagnostic = String::from_utf8_lossy(&refused.stderr);
    assert!(diagnostic.contains("protected-path"), "{diagnostic}");
    assert!(
        diagnostic.contains(&format!("expected owner uid {foreign}")),
        "{diagnostic}"
    );
    assert!(!fixture.home().exists());
    let home = fixture.home();
    let parent = home.parent().expect("loop parent");
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o770))
        .expect("writable parent");
    let refused = fixture.invoke("prepare-signin-home", None, uid);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("sign-in-parent-owner-mode-type"));
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).expect("safe parent");
    fixture.prepare();
    let refused = fixture.invoke("prepare-signin-home", None, foreign);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("sign-in-home-owner-mode-type"));
}

/// # Panics
/// Panics only if replacing the loop pathname redirects staging or publication.
/// ´test:integration:codex-home-publication-stays-on-the-pinned-parent´
#[test]
#[cfg(debug_assertions)]
fn codex_home_publication_stays_on_the_pinned_parent() {
    let fixture = CodexHomeFixture::new();
    let output = fixture
        .command(
            "prepare-signin-home",
            None,
            nix::unistd::Uid::effective().as_raw(),
        )
        .env("SUPERLOOP_SIGNIN_TEST_REPLACE_PARENT", "1")
        .output()
        .expect("production publication");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let home = fixture.home();
    let parent = home.parent().expect("loop parent");
    assert!(!home.exists());
    assert_eq!(
        std::fs::read_dir(parent)
            .expect("replacement parent")
            .count(),
        0
    );
    let held = parent.with_extension("pinned");
    assert_eq!(std::fs::read_dir(&held).expect("held parent").count(), 1);
    assert!(held.join("codex/config.toml").is_file());
    assert!(held.join("codex/ssh_config").is_file());
    assert_eq!(
        std::fs::read_link(held.join("codex/AGENTS.md")).expect("charter link"),
        fixture
            .root
            .path()
            .join(".local/share/orchestration-instance/docs/tools/worker-charter.md")
    );
}

fn prepare_signin_fixture() -> (tempfile::TempDir, u32, u32, String) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir_in("/tmp").expect("small protected metadata fixture");
    let home = root.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("protected owner home");
    let config = home.join(".config/loops");
    let canonical = config.join("alpha/lanes/codex");
    fs::create_dir_all(&canonical).expect("canonical root");
    for directory in [
        home.join(".config"),
        config.clone(),
        config.join("alpha"),
        config.join("alpha/lanes"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protected parent");
    }
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o750)).expect("old root mode");
    let auth = canonical.join("auth.json");
    fs::write(&auth, b"synthetic credential").expect("synthetic source");
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o640)).expect("old file mode");
    let gid = nix::unistd::Gid::effective().as_raw();
    let registry = config.join("registry.toml");
    let write_registry = |group| {
        fs::write(&registry, format!("namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{name = 'alpha', uid = {group}, launch = 'src', runs_root = '{}'}}]\n", home.join("runs").display())).expect("registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
    };
    let loop_gid = if gid == 41001 { 41002 } else { 41001 };
    assert_ne!(gid, loop_gid);
    write_registry(loop_gid);
    let mapping = format!("0 {gid} 1\n1 100000 65535\n");
    let settings = config.join("alpha/workers.toml");
    fs::write(
        &settings,
        "driver_argv = ['/usr/bin/true']\nvendor_hosts = { codex = [] }\n",
    )
    .expect("existing driver selection; no executable is launched");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    (root, gid, loop_gid, mapping)
}

fn assert_unboxed_group(absent: &serde_json::Value, gid: u32) {
    let root_entry = &absent["sign_in_metadata"]["entries"][0];
    assert_eq!(root_entry["group_required"], false);
    assert_eq!(root_entry["complete"], true);
    assert_eq!(root_entry["gid"], gid);
    assert!(root_entry["wanted_gid"].is_null());
    assert!(absent["sign_in_metadata"]["group_repair"].is_null());
    assert_eq!(root_entry["findings"], serde_json::json!([]));
    assert!(
        root_entry["group_reason"]
            .as_str()
            .expect("reason")
            .contains("no installed box")
    );
}

fn assert_group_report_shape(report: &serde_json::Value) {
    for entry in report["sign_in_metadata"]["entries"]
        .as_array()
        .expect("entries")
    {
        if let Some(required) = entry["group_required"].as_bool() {
            assert_eq!(entry.get("group_reason").is_some(), !required);
            if required {
                assert_eq!(
                    report["sign_in_metadata"]["group_repair"],
                    "install private convergence"
                );
            }
        }
    }
}

fn assert_invalid_generation(
    generation: &std::path::Path,
    invoke: &impl Fn(bool, &str) -> serde_json::Value,
) {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let assert_invalid = || {
        let report = invoke(true, "invalid evidence must not read the gid map");
        let root = &report["sign_in_metadata"]["entries"][0];
        assert_eq!(root["group_required"], true);
        assert_eq!(root["complete"], false);
        assert!(root["wanted_gid"].is_null());
        assert_eq!(root["findings"][0]["name"], "install-generation");
    };
    fs::write(generation, "{\"schema\":1,\"phase\":\"invalid\"}").expect("invalid evidence");
    assert_invalid();
    fs::remove_file(generation).expect("remove malformed evidence");
    let target = generation.with_extension("target");
    symlink(&target, generation).expect("dangling evidence link");
    assert_invalid();
    fs::write(&target, "{\"schema\":1,\"phase\":\"complete\"}").expect("valid linked content");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    assert_invalid();
    fs::remove_file(generation).expect("remove evidence link");
    fs::remove_file(target).expect("remove linked target");
    fs::write(generation, "{\"schema\":1,\"phase\":\"complete\"}").expect("valid evidence");
    fs::set_permissions(generation, fs::Permissions::from_mode(0o640))
        .expect("unsafe evidence mode");
    assert_invalid();
    fs::set_permissions(generation, fs::Permissions::from_mode(0o600))
        .expect("restore evidence mode");
}

/// # Panics
/// Panics only if the fixture cannot be created or prepare violates the metadata contract.
///
/// ´test:integration:prepare-sets-canonical-modes-and-reports-namespace-group´
#[test]
fn prepare_sets_canonical_modes_and_reports_namespace_group() {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (fixture, gid, loop_gid, mapping) = prepare_signin_fixture();
    let home = fixture.path();
    let config = home.join(".config/loops");
    let canonical = config.join("alpha/lanes/codex");
    let auth = canonical.join("auth.json");
    let invoke = |dry: bool, mapping: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command
            .args(["prepare", "alpha"])
            .env("HOME", home)
            .env("SUPERLOOP_SIGNIN_TEST_GID_MAP", mapping)
            .env_remove("ENTER_LOOP_REGISTRY");
        if dry {
            command.arg("--dry-run");
        }
        let output = command.output().expect("production prepare entry");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report =
            serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("prepare report");
        assert_group_report_shape(&report);
        report
    };
    let preview = invoke(true, &mapping);
    assert_eq!(
        preview["sign_in_metadata"]["entries"][0]["group_required"],
        false
    );
    assert_eq!(
        preview["sign_in_metadata"]["entries"][0]["would_change"],
        true
    );
    assert_eq!(fs::metadata(&auth).expect("file").mode() & 0o7777, 0o640);
    let absent = invoke(false, "invalid map is not read without a box");
    assert_unboxed_group(&absent, gid);
    let generation = config.join("alpha/install-generation.json");
    fs::write(&generation, "{\"schema\":1,\"phase\":\"complete\"}")
        .expect("installed box evidence");
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o600)).expect("generation mode");
    let preview = invoke(true, &mapping);
    assert_eq!(
        preview["sign_in_metadata"]["entries"][0]["findings"][0]["name"],
        "sign-in-group"
    );
    let applied = invoke(false, &mapping);
    let root_entry = &applied["sign_in_metadata"]["entries"][0];
    assert_eq!(root_entry["complete"], false);
    assert_eq!(root_entry["group_required"], true);
    assert_eq!(root_entry["gid"], gid);
    assert_eq!(root_entry["wanted_gid"], 100_000 + loop_gid - 1);
    assert_eq!(root_entry["findings"][0]["name"], "sign-in-group");
    let file_entry = &applied["sign_in_metadata"]["entries"][1];
    assert_ne!(file_entry["gid"], root_entry["wanted_gid"]);
    assert_eq!(file_entry["complete"], true);
    assert_eq!(file_entry["group_required"], false);
    assert!(file_entry["wanted_gid"].is_null());
    assert_eq!(file_entry["findings"], serde_json::json!([]));
    assert_invalid_generation(&generation, &invoke);
    fs::write(&generation, "{\"schema\":1,\"phase\":\"preparing\"}").expect("pending evidence");
    assert_eq!(
        invoke(true, &mapping)["sign_in_metadata"]["entries"][0]["group_required"],
        true
    );
    fs::write(&generation, "{\"schema\":1,\"phase\":\"complete\"}").expect("restore evidence");
    assert_eq!(
        fs::metadata(&canonical).expect("root").mode() & 0o7777,
        0o700
    );
    assert_eq!(fs::metadata(&auth).expect("file").mode() & 0o7777, 0o600);
    assert_eq!(invoke(false, &mapping)["sign_in_metadata"]["changed"], 0);
    for path in [&canonical, &auth] {
        assert_eq!(fs::metadata(path).expect("host group retained").gid(), gid);
    }
    let unmapped = invoke(false, &format!("0 {gid} 1\n"));
    assert_eq!(
        unmapped["sign_in_metadata"]["wanted_namespace_gid"],
        loop_gid
    );
    let root_entry = &unmapped["sign_in_metadata"]["entries"][0];
    assert_eq!(root_entry["complete"], false);
    assert!(root_entry["wanted_gid"].is_null());
    assert_eq!(root_entry["findings"][0]["name"], "sign-in-group-map");
    let file_entry = &unmapped["sign_in_metadata"]["entries"][1];
    assert_eq!(file_entry["complete"], true);
    assert_eq!(file_entry["findings"], serde_json::json!([]));
    assert_eq!(
        fs::read(&auth).expect("synthetic source retained"),
        b"synthetic credential"
    );
}

/// ´test:integration:signin-home-faults-preserve-identity-and-recovery-ledger´
#[test]
fn signin_home_faults_preserve_identity_and_recovery_ledger() {
    let output = Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/loop-codex-home-run.sh"
        ))
        .env("SIGNIN_TEST_BINARY", env!("CARGO_BIN_EXE_superloop-lane"))
        .env("SIGNIN_TEST_FAULTS", "1")
        .output()
        .expect("sign-in fixture");
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// # Panics
/// Panics only if the fixture or production check violates the refusal-only contract.
/// ´test:integration:codex-route-refusal-stands-alone´
#[test]
fn codex_route_refusal_stands_alone() {
    let fixture = CodexHomeFixture::new();
    let owner = fixture.root.path();
    let registry = owner.join(".local/share/orchestration-instance/servers.md");
    let source = std::fs::read_to_string(&registry).expect("route registry");
    std::fs::remove_file(owner.join("key")).expect("unresolved key");
    std::fs::remove_file(owner.join(".config/loops/registry.toml")).expect("absent configuration");
    std::fs::create_dir(owner.join(".codex-alpha")).expect("old home location");
    for (rows, refusal) in [
        (
            source.replace("node-a", "node-b"),
            "registry-node: node-a: no active row",
        ),
        (
            source.replace("|22|", "|0|"),
            "registry-row: alpha line 4: port must be a canonical decimal port from 1 to 65535 (got an invalid form)",
        ),
    ] {
        std::fs::write(&registry, rows).expect("refusing route");
        let output = fixture
            .command_with_project(
                "check-signin-home",
                None,
                nix::unistd::Uid::effective().as_raw(),
                false,
            )
            .output()
            .expect("check");
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stderr, [] as [u8; 0]);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(report["missing"], serde_json::json!([refusal]));
        assert_eq!(report["ok"], false);
        assert_eq!(report["varied"], serde_json::json!([]));
    }
}

/// # Panics
/// Panics only if the fixture or production registry refusal violates the no-write contract.
/// ´test:integration:codex-registry-selection-refuses-unpinned-hosts´
#[test]
fn codex_registry_selection_refuses_unpinned_hosts() {
    let fixture = CodexHomeFixture::new();
    let uid = nix::unistd::Uid::effective().as_raw();
    for hosts in [
        "node-a:192.0.2.9:22",
        "node-a:192.0.2.1:23",
        "node-a:192.0.2.1:22,extra:192.0.2.2:22",
    ] {
        let output = fixture
            .command("prepare-signin-home", None, uid)
            .args(["--hosts", hosts])
            .output()
            .expect("refusal");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("registry-node:"),
            "{output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("--hosts"));
        assert!(!fixture.home().exists());
    }
    let registry = fixture
        .root
        .path()
        .join(".local/share/orchestration-instance/servers.md");
    let source = std::fs::read_to_string(&registry).expect("registry");
    // `--user` must repeat the row's account, as `--hosts` must repeat its endpoint.
    std::fs::write(
        &registry,
        source.replace("|alpha|fixture|", "|alpha|other|"),
    )
    .expect("differing account");
    let output = fixture
        .command("prepare-signin-home", None, uid)
        .output()
        .expect("refusal");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("registry-node: node-a: --user differs from active row account"),
        "{output:?}"
    );
    assert!(!fixture.home().exists());
    for replacement in ["node-b|active", "node-a|retired"] {
        // Keep a second active row so registry selection reaches the selected-node check.
        let other = source
            .lines()
            .last()
            .expect("row")
            .replace("node-a", "node-b");
        std::fs::write(
            &registry,
            format!(
                "{}{}\n",
                if replacement == "node-b|active" {
                    source.replace("node-a", "node-b")
                } else {
                    source.replace("node-a|active", replacement)
                },
                if replacement == "node-a|retired" {
                    other.as_str()
                } else {
                    ""
                }
            ),
        )
        .expect("missing active row");
        for hosts in ["", "node-a:192.0.2.1:22"] {
            let output = fixture
                .command("prepare-signin-home", None, uid)
                .args(["--hosts", hosts])
                .output()
                .expect("refusal");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("registry-node: node-a: no active row"),
                "{output:?}"
            );
            assert!(!fixture.home().exists());
        }
    }
}
