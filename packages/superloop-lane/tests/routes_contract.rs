#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

fn registry() -> String {
    String::from(
        "# Servers\n\n|Name|Location|Specs|Restrictions|\n|----|--------|-----|------------|\n|old|somewhere|historical|none|\n\n## Node routes\n\n|node|status|hostname|port|host_key_algorithm|host_key|loop|account|worker_alias|session_alias|worker_identity|session_identity|\n|---|---|---|---|---|---|---|---|---|---|---|---|\n|jay|active|192.0.2.1|2222|ssh-ed25519|AAAA|alpha|staff|jay-worker|jay-alpha|/fixture/worker-key|/fixture/session-key|\n|owl|active|192.0.2.2|22|ssh-ed25519|BBBB|alpha|staff|owl-worker|owl-alpha|/fixture/worker-key|/fixture/session-key|\n",
    ).replace("/fixture/session-key", "~/.ssh/session-key")
        + "|jay|active|192.0.2.3|22|ssh-ed25519|CCCC|stranger|staff|jay-worker|jay-stranger|/fixture/worker-key|/home/stranger/private-key|\n"
}

fn canonical_signin(home: &std::path::Path) {
    let canonical = home.join(".config/loops/alpha/lanes/codex");
    fs::create_dir_all(&canonical).expect("canonical root");
    for directory in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        home.join(".config/loops/alpha"),
        home.join(".config/loops/alpha/lanes"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protected canonical parents");
    }
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).expect("root mode");
    fs::write(canonical.join("auth.json"), "{}").expect("fixture auth");
    fs::set_permissions(
        canonical.join("auth.json"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("mode");
}

fn render_fixture(home: &std::path::Path) {
    for dir in [
        "out",
        ".local/share/orchestration-instance/docs/tools",
        ".config/loops/alpha/claude",
    ] {
        fs::create_dir_all(home.join(dir)).expect("directory");
    }
    fs::set_permissions(
        home.join(".config/loops/alpha/claude"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("mode");
    fs::write(home.join("worker-key"), "fixture only").expect("key");
    fs::write(
        home.join(".local/share/orchestration-instance/docs/tools/worker-charter.md"),
        "fixture",
    )
    .expect("charter");
    fs::write(
        home.join("servers.md"),
        registry().replace("/fixture", home.to_str().expect("path")),
    )
    .expect("registry");
    install_instance_registry(home);
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["render-routes", "--loop", "alpha", "--owner-home"])
        .arg(home)
        .arg("--registry")
        .arg(home.join("servers.md"))
        .arg("--output")
        .arg(home.join("out"))
        .output()
        .expect("render");
    assert!(output.status.success(), "{output:?}");
}

/// # Panics
/// Panics only if fixture setup or the production sign-in commands fail.
///
/// ´test:integration:rendered-routes-pass-signin-check-and-reconcile´
#[test]
fn rendered_routes_pass_signin_check_and_reconcile() {
    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let home = root.path();
    render_fixture(home);
    let records = home.join(".local/share/superloop-tools/loops.d");
    fs::create_dir_all(&records).expect("existing records");
    fs::write(
        records.join("alpha.env"),
        format!("LOOP_CWD={}\n", home.display()),
    )
    .expect("existing loop record");
    for (source, target) in [
        ("claude.ssh_config", ".config/loops/alpha/claude/ssh_config"),
        (
            "claude.known_hosts",
            ".config/loops/alpha/claude/known_hosts.routes",
        ),
    ] {
        fs::copy(home.join("out").join(source), home.join(target)).expect("install fixture");
    }
    let signin = |action: &str, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .env("HOME", home)
            .args([
                action,
                "--backend",
                "codex",
                "alpha",
                "--nodes",
                "owl,jay",
                "--project",
            ])
            .arg(home)
            .args(extra)
            .output()
            .expect("sign-in command")
    };
    canonical_signin(home);
    let prepared = signin("prepare-signin-home", &[]);
    assert!(prepared.status.success(), "{prepared:?}");
    for (source, target) in [
        ("codex.ssh_config", ".config/loops/alpha/codex/ssh_config"),
        (
            "codex.known_hosts",
            ".config/loops/alpha/codex/known_hosts.routes",
        ),
    ] {
        fs::copy(home.join("out").join(source), home.join(target)).expect("install fixture");
    }
    let checked = signin("check-signin-home", &[]);
    assert!(checked.status.success(), "{checked:?}");
    let preview = signin("prepare-signin-home", &["--reconcile", "--dry-run"]);
    assert!(preview.status.success(), "{preview:?}");
    let report: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("preview");
    assert_eq!(report["changed"], 0);
    assert_charter_reconciled(home, &signin);
    for (kind, installed) in [
        ("codex", ".config/loops/alpha/codex/ssh_config"),
        ("claude", ".config/loops/alpha/claude/ssh_config"),
    ] {
        assert_reconciled_render(home, kind, installed);
    }
    assert!(signin("check-signin-home", &[]).status.success());
    reconcile_both_orders(home, signin);
    for status in ["active", "retired"] {
        let bad = registry()
            .replace("/fixture", home.to_str().expect("home"))
            .replacen("|jay|active|", &format!("|jay|{status}|"), 1)
            .replacen("~/.ssh/session-key", "/home/alpha/private-key", 1);
        fs::write(home.join("servers.md"), bad).expect("selected invalid row");
        install_instance_registry(home);
        for refused in [
            signin("prepare-signin-home", &["--reconcile", "--dry-run"]),
            signin("check-signin-home", &[]),
            claude_call(home, &["--reconcile", "--dry-run"]),
            invoke(home),
        ] {
            assert!(!refused.status.success(), "{refused:?}");
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&refused.stdout),
                String::from_utf8_lossy(&refused.stderr)
            );
            assert!(output.contains("registry-row: alpha line 11: session_identity must be an entry-relative ~/.ssh path (got an absolute path)"), "{output}");
            assert!(!output.contains("/home/alpha/private-key"), "{output}");
        }
    }
}

fn assert_charter_reconciled(
    home: &std::path::Path,
    signin: &impl Fn(&str, &[&str]) -> std::process::Output,
) {
    let charter = home.join(".local/share/orchestration-instance/docs/tools/worker-charter.md");
    let agents = home.join(".config/loops/alpha/codex/AGENTS.md");
    fs::remove_file(&agents).expect("old link");
    std::os::unix::fs::symlink(home.join("old-charter.md"), &agents).expect("retired charter link");
    let preview = signin("prepare-signin-home", &["--reconcile", "--dry-run"]);
    assert!(preview.status.success(), "{preview:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("charter preview");
    assert_eq!(report["changed"], 1);
    assert_eq!(
        report["plan"]["links"][0]["target"],
        serde_json::json!(charter)
    );
    assert_eq!(
        fs::read_link(&agents).expect("preview preserves link"),
        home.join("old-charter.md")
    );
    fs::remove_file(&charter).expect("remove input before apply");
    let refused = signin(
        "prepare-signin-home",
        &[
            "--reconcile",
            "--expect-digest",
            report["digest"].as_str().expect("digest"),
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("worker charter not found at"));
    assert_eq!(
        fs::read_link(&agents).expect("refusal preserves link"),
        home.join("old-charter.md")
    );
    fs::write(&charter, "fixture").expect("restore input");
    let applied = signin(
        "prepare-signin-home",
        &[
            "--reconcile",
            "--expect-digest",
            report["digest"].as_str().expect("digest"),
        ],
    );
    assert!(applied.status.success(), "{applied:?}");
    let result: serde_json::Value = serde_json::from_slice(&applied.stdout).expect("apply report");
    assert_eq!(result["charter"], serde_json::json!(charter));
    assert_eq!(result["replaced"], 1);
    assert_eq!(fs::read_link(&agents).expect("new link"), charter);
    let preview = signin("prepare-signin-home", &["--reconcile", "--dry-run"]);
    assert!(preview.status.success(), "{preview:?}");
    let report: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("unchanged");
    assert_eq!(report["changed"], 0);
}

fn assert_reconciled_render(home: &std::path::Path, kind: &str, installed: &str) {
    assert_eq!(
        fs::read(home.join("out").join(format!("{kind}.ssh_config"))).expect("rendered"),
        fs::read(home.join(installed)).expect("installed")
    );
}

fn install_instance_registry(home: &std::path::Path) {
    fs::create_dir_all(home.join(".local/share/orchestration-instance")).expect("instance");
    fs::copy(
        home.join("servers.md"),
        home.join(".local/share/orchestration-instance/servers.md"),
    )
    .expect("instance registry");
}

fn reconcile_both_orders(
    home: &std::path::Path,
    signin: impl Fn(&str, &[&str]) -> std::process::Output,
) {
    for claude_first in [true, false] {
        let codex = || {
            let preview = signin("prepare-signin-home", &["--reconcile", "--dry-run"]);
            assert!(preview.status.success(), "{preview:?}");
            let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("preview");
            assert_eq!(plan["changed"], 0);
            assert!(
                signin(
                    "prepare-signin-home",
                    &[
                        "--reconcile",
                        "--expect-digest",
                        plan["digest"].as_str().expect("digest")
                    ]
                )
                .status
                .success()
            );
        };
        let claude = || {
            let preview = claude_call(home, &["--reconcile", "--dry-run"]);
            assert!(preview.status.success(), "{preview:?}");
            let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("preview");
            let applied = claude_call(
                home,
                &[
                    "--reconcile",
                    "--expect-digest",
                    plan["digest"].as_str().expect("digest"),
                ],
            );
            assert!(applied.status.success(), "{applied:?}");
            let preview = claude_call(home, &["--reconcile", "--dry-run"]);
            let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("preview");
            assert_eq!(plan["changed"], 0);
        };
        if claude_first {
            claude();
            codex();
        } else {
            codex();
            claude();
        }
    }
}

fn claude_call(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .env("HOME", home)
        .env("SUPERLOOP_CLAUDE_MOVE_TEST_PROC", home.join("processes"))
        .args(["prepare-signin-home", "--backend", "claude", "alpha"])
        .args(args)
        .output()
        .expect("Claude home command")
}

fn claude_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner home");
    fs::create_dir(root.path().join("processes")).expect("process table");
    let instance = root.path().join(".local/share/orchestration-instance");
    fs::create_dir_all(instance.join("docs/tools")).expect("instance");
    fs::write(
        instance.join("docs/tools/worker-charter.md"),
        "fixture charter",
    )
    .expect("charter");
    fs::write(
        instance.join("servers.md"),
        registry().replace(
            "/fixture/worker-key",
            &root.path().join("worker-key").to_string_lossy(),
        ),
    )
    .expect("routes");
    fs::write(root.path().join("worker-key"), "fixture key").expect("key");
    root
}

/// # Panics
/// Panics only if fixture setup or preparation violates the charter preflight contract.
/// ´test:integration:claude-home-requires-selected-charter-before-preparation´
#[test]
fn claude_home_requires_selected_charter_before_preparation() {
    let root = claude_fixture();
    let owner = root.path();
    let default = owner.join(".local/share/orchestration-instance/docs/tools/worker-charter.md");
    fs::remove_file(&default).expect("remove default");
    let missing = claude_call(owner, &["--dry-run"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains(&format!(
        "worker charter not found at {}; pass --charter or install the instance publication",
        default.display()
    )));
    assert!(!owner.join(".config/loops/alpha/claude").exists());
    let selected = owner.join("selected.md");
    fs::write(&selected, "selected charter").expect("input");
    let args = ["--charter", selected.to_str().expect("path")];
    let report = claude_apply(owner, &args);
    assert_eq!(report["charter"], serde_json::json!(selected));
    let home = owner.join(".config/loops/alpha/claude");
    assert!(home.is_dir());
    assert!(!home.join("CLAUDE.md").exists());
    fs::remove_file(&selected).expect("remove selected input");
    let missing = claude_call(owner, &["--charter", args[1], "--reconcile", "--dry-run"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("worker charter not found at"));
}

fn claude_apply(home: &std::path::Path, args: &[&str]) -> serde_json::Value {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let sha256 = |text: &str| {
        let mut digest = String::new();
        for byte in sha2::Sha256::digest(text.as_bytes()) {
            write!(digest, "{byte:02x}").expect("digest hex");
        }
        digest
    };
    let mut words = args.to_vec();
    words.push("--dry-run");
    let preview = claude_call(home, &words);
    assert!(preview.status.success(), "{preview:?}");
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("plan");
    let preview_files = if args.contains(&"--move-from") {
        &[][..]
    } else {
        plan["plan"]["files"].as_array().expect("files").as_slice()
    };
    if !args.contains(&"--move-from") {
        let file_digests = plan["plan"]["file_digests"]
            .as_array()
            .expect("file digests");
        assert_eq!(preview_files.len(), file_digests.len());
        for (file, digests) in preview_files.iter().zip(file_digests) {
            let path = std::path::Path::new(file["path"].as_str().expect("path"));
            assert!(path.ends_with(digests["path"].as_str().expect("digest name")));
            assert_eq!(
                digests["after"],
                sha256(file["after"].as_str().expect("after"))
            );
            if file["before"].is_null() {
                assert!(digests["before"].is_null());
            } else {
                assert_eq!(
                    digests["before"],
                    sha256(file["before"].as_str().expect("before"))
                );
            }
        }
        let mut legacy = plan["plan"].clone();
        legacy["files"] = legacy
            .as_object_mut()
            .expect("plan object")
            .remove("file_digests")
            .expect("retained file digests");
        assert_eq!(plan["digest"], sha256(&legacy.to_string()));
    }
    for file in preview_files {
        let path = std::path::Path::new(file["path"].as_str().expect("path"));
        assert!(path.is_absolute());
        assert_eq!(file.as_object().expect("file").len(), 5);
        assert_eq!(file["mode"], 0o600);
        match fs::read_to_string(path) {
            Ok(before) => {
                assert_eq!(file["before"], before);
                assert_eq!(file["action"], "replace");
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                assert!(file["before"].is_null());
                assert_eq!(file["action"], "write");
            }
        }
    }
    words.pop();
    words.extend(["--expect-digest", plan["digest"].as_str().expect("digest")]);
    let applied = claude_call(home, &words);
    assert!(applied.status.success(), "{applied:?}");
    for file in preview_files {
        assert_eq!(
            fs::read(file["path"].as_str().expect("path")).expect("applied file"),
            file["after"].as_str().expect("after bytes").as_bytes()
        );
    }
    plan
}

/// # Panics
/// Panics only if fixture setup or the preparation lock refusal contract fails.
/// ´test:integration:claude-preparation-preview-and-apply-refuse-locked-loop´
#[test]
fn claude_preparation_preview_and_apply_refuse_locked_loop() {
    use nix::fcntl::{Flock, FlockArg};
    let root = claude_fixture();
    let parent = root.path().join(".config/loops/alpha");
    fs::create_dir_all(&parent).expect("loop directory");
    for path in [".config", ".config/loops", ".config/loops/alpha"] {
        fs::set_permissions(root.path().join(path), fs::Permissions::from_mode(0o700))
            .expect("protected loop directory");
    }
    let preview = claude_call(root.path(), &["--dry-run"]);
    assert!(preview.status.success(), "{preview:?}");
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("preview");
    let digest = plan["digest"].as_str().expect("digest");
    let held = Flock::lock(
        fs::File::open(&parent).expect("loop"),
        FlockArg::LockExclusiveNonblock,
    )
    .expect("live loop lock");
    for args in [vec!["--dry-run"], vec!["--expect-digest", digest]] {
        let started = std::time::Instant::now();
        let refused = claude_call(root.path(), &args);
        assert!(!refused.status.success(), "{refused:?}");
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains(&format!("claude-home-locked: {}", parent.display()))
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(6));
        assert_eq!(fs::read_dir(&parent).expect("unchanged loop").count(), 0);
    }
    drop(held);
    let applied = claude_call(root.path(), &["--expect-digest", digest]);
    assert!(applied.status.success(), "{applied:?}");
}

/// # Panics
/// Panics only if fixture setup or the move preview lock refusal contract fails.
/// ´test:integration:claude-move-preview-refuses-locked-loop´
#[test]
fn claude_move_preview_refuses_locked_loop() {
    use nix::fcntl::{Flock, FlockArg};
    let root = claude_fixture();
    let source = previous_claude(root.path());
    let parent = root.path().join(".config/loops/alpha");
    fs::create_dir_all(&parent).expect("loop directory");
    for path in [".config", ".config/loops", ".config/loops/alpha"] {
        fs::set_permissions(root.path().join(path), fs::Permissions::from_mode(0o700))
            .expect("protected loop directory");
    }
    let held = Flock::lock(
        fs::File::open(&parent).expect("loop"),
        FlockArg::LockExclusiveNonblock,
    )
    .expect("live loop lock");
    let started = std::time::Instant::now();
    let refused = claude_call(
        root.path(),
        &["--move-from", source.to_str().expect("source"), "--dry-run"],
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains(&format!("claude-home-locked: {}", parent.display()))
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(6));
    assert!(!source.join("move-record.json").exists());
    assert_eq!(fs::read_dir(&parent).expect("unchanged loop").count(), 0);
    drop(held);
}

fn previous_claude(root: &std::path::Path) -> std::path::PathBuf {
    let old = root.join(".claude-alpha");
    fs::create_dir(&old).expect("previous home");
    fs::set_permissions(&old, fs::Permissions::from_mode(0o700)).expect("private home");
    fs::write(
        old.join(".credentials.json"),
        "credential canary, never inspect",
    )
    .expect("credential");
    fs::set_permissions(
        old.join(".credentials.json"),
        fs::Permissions::from_mode(0o0),
    )
    .expect("credential unreadable");
    fs::write(old.join("ssh_config"), format!("Host jay-worker\n  IdentityFile {}/keys/key\n  UserKnownHostsFile ~/.claude-alpha/known_hosts.routes\n", old.display())).expect("ssh");
    let alias = format!(
        "/home/{}/.claude-alpha",
        root.file_name().expect("name").to_string_lossy()
    );
    let settings = serde_json::json!({"permissions":{"allow":[format!("Bash(ssh -F {alias}/ssh_config jay-worker *)")]},"sandbox":{"excludedCommands":["ssh -F $HOME/.claude-alpha/ssh_config jay-worker"]},"owner":"settings canary, never print"});
    fs::write(
        old.join("settings.json"),
        serde_json::to_vec(&settings).expect("settings json"),
    )
    .expect("settings");
    fs::write(old.join(".claude.json"), serde_json::to_vec(&serde_json::json!({"projects":{old.join("project").to_string_lossy().into_owned():{"trust":true}},"account":"account canary, never print"})).expect("account json")).expect("account");
    fs::write(
        old.join("settings.json.pre-deploy"),
        old.to_string_lossy().as_bytes(),
    )
    .expect("backup");
    fs::create_dir(old.join("projects")).expect("transcripts");
    fs::write(
        old.join("projects/transcript"),
        old.to_string_lossy().as_bytes(),
    )
    .expect("transcript");
    for file in ["ssh_config", "settings.json", ".claude.json"] {
        fs::set_permissions(old.join(file), fs::Permissions::from_mode(0o600))
            .expect("private configuration");
    }
    old
}

/// # Panics
/// Panics only if fixture setup or a migration invariant fails.
/// ´test:integration:claude-home-move-rewrites-only-config-and-retains-credential-inode´
#[test]
fn claude_home_move_rewrites_only_config_and_retains_credential_inode() {
    use std::os::unix::fs::MetadataExt as _;
    let root = claude_fixture();
    let old = previous_claude(root.path());
    let original = fs::metadata(old.join(".credentials.json")).expect("credential metadata");
    let directory = fs::metadata(&old).expect("directory");
    let home = root.path().join(".config/loops/alpha/claude");
    let plan = claude_apply(root.path(), &["--move-from", old.to_str().expect("path")]);
    assert_eq!(plan["sign_in"], "present");
    assert_eq!(plan["credential_metadata"]["mode"], 0);
    let output = plan.to_string();
    assert!(!output.contains("account canary"));
    assert!(!output.contains("settings canary"));
    assert!(!output.contains("credential canary"));
    assert_eq!(plan["plan"]["files"].as_array().expect("files").len(), 3);
    assert!(!old.exists());
    assert_eq!(fs::metadata(&home).expect("home").ino(), directory.ino());
    let credential = fs::metadata(home.join(".credentials.json")).expect("credential metadata");
    assert_eq!(
        (
            credential.dev(),
            credential.ino(),
            credential.mode(),
            credential.len(),
            credential.mtime(),
            credential.mtime_nsec()
        ),
        (
            original.dev(),
            original.ino(),
            original.mode(),
            original.len(),
            original.mtime(),
            original.mtime_nsec()
        )
    );
    for file in ["ssh_config", "settings.json", ".claude.json"] {
        let text = fs::read_to_string(home.join(file)).expect("rewritten file");
        assert!(!text.contains(".claude-alpha"), "{file}");
        assert!(
            text.contains(&home.to_string_lossy().into_owned()),
            "{file}"
        );
    }
    for file in ["settings.json.pre-deploy", "projects/transcript"] {
        assert_eq!(
            fs::read_to_string(home.join(file)).expect("history"),
            old.to_string_lossy()
        );
    }
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join("move-record.json")).expect("record"))
            .expect("json");
    assert_eq!(record["state"], "complete");
    assert_eq!(
        fs::metadata(home.join("move-record.json"))
            .expect("mode")
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        claude_apply(root.path(), &["--move-from", old.to_str().expect("path")])["changed"],
        0
    );
}

/// # Panics
/// Panics only if fixture setup or a recovery boundary fails.
/// ´test:integration:claude-home-move-recovers-every-record-and-rewrite-boundary´
#[test]
fn claude_home_move_recovers_every_record_and_rewrite_boundary() {
    for stage in [
        "record",
        "rename",
        ".claude.json",
        "settings.json",
        "ssh_config",
    ] {
        let root = claude_fixture();
        let old = previous_claude(root.path());
        let args = ["--move-from", old.to_str().expect("path"), "--dry-run"];
        let preview = claude_call(root.path(), &args);
        assert!(preview.status.success(), "{preview:?}");
        let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).expect("plan");
        let interrupted = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .env("HOME", root.path())
            .env(
                "SUPERLOOP_CLAUDE_MOVE_TEST_PROC",
                root.path().join("processes"),
            )
            .env("SUPERLOOP_CLAUDE_MOVE_TEST_STOP", stage)
            .args([
                "prepare-signin-home",
                "--backend",
                "claude",
                "alpha",
                "--move-from",
                old.to_str().expect("path"),
                "--expect-digest",
                plan["digest"].as_str().expect("digest"),
            ])
            .output()
            .expect("interrupted migration");
        assert!(!interrupted.status.success());
        assert!(
            String::from_utf8_lossy(&interrupted.stderr).contains("claude-home-move-interrupted"),
            "{interrupted:?}"
        );
        if stage == "rename" {
            let settings = root.path().join(".config/loops/alpha/claude/settings.json");
            let retained = fs::read(&settings).expect("pending settings");
            fs::write(&settings, b"{}").expect("third digest");
            let refused = claude_call(root.path(), &args);
            assert!(
                String::from_utf8_lossy(&refused.stderr)
                    .contains("claude-home-move-file-changed: settings.json")
            );
            fs::write(&settings, retained).expect("restore pending digest");
        }
        let plan = claude_apply(root.path(), &["--move-from", old.to_str().expect("path")]);
        assert!(plan["changed"].as_u64().expect("changed") > 0);
        assert_eq!(
            claude_apply(root.path(), &["--move-from", old.to_str().expect("path")])["changed"],
            0
        );
    }
}

struct HomeProcess(std::process::Child);
impl Drop for HomeProcess {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

/// # Panics
/// Panics only if fixture setup or a move refusal fails.
/// ´test:integration:claude-home-move-refuses-occupied-live-and-foreign-homes´
#[test]
fn claude_home_move_refuses_occupied_live_and_foreign_homes() {
    let root = claude_fixture();
    let old = previous_claude(root.path());
    let args = ["--move-from", old.to_str().expect("path"), "--dry-run"];
    let other = claude_call(
        root.path(),
        &[
            "--move-from",
            root.path().to_str().expect("path"),
            "--dry-run",
        ],
    );
    assert!(String::from_utf8_lossy(&other.stderr).contains("claude-home-move-source"));
    let process = HomeProcess(
        Command::new("/bin/sleep")
            .arg("60")
            .env("CLAUDE_CONFIG_DIR", &old)
            .spawn()
            .expect("home user"),
    );
    let process_entry = root
        .path()
        .join("processes")
        .join(process.0.id().to_string());
    std::os::unix::fs::symlink(format!("/proc/{}", process.0.id()), &process_entry)
        .expect("fixture process entry");
    let refused = claude_call(root.path(), &args);
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("claude-home-driver-live"),
        "{refused:?}"
    );
    assert!(old.exists());
    assert!(!old.join("move-record.json").exists());
    drop(process);
    fs::remove_file(process_entry).expect("remove exited fixture process");
    let destination = root.path().join(".config/loops/alpha/claude");
    fs::create_dir_all(&destination).expect("occupied destination");
    for relative in [".config", ".config/loops", ".config/loops/alpha"] {
        fs::set_permissions(
            root.path().join(relative),
            fs::Permissions::from_mode(0o700),
        )
        .expect("protected parents");
    }
    let refused = claude_call(root.path(), &args);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("claude-home-destination-occupied"));
    fs::rename(&old, root.path().join("held-source")).expect("hold fixture source");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
        .expect("private destination");
    let refused = claude_call(root.path(), &args);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("claude-home-destination-occupied"));
}

/// # Panics
/// Panics only if fixture setup or the preparation contract fails.
/// ´test:integration:claude-home-preparation-retains-owner-settings-and-credential´
#[test]
fn claude_home_preparation_retains_owner_settings_and_credential() {
    use std::os::unix::fs::MetadataExt as _;
    let root = claude_fixture();
    let home = root.path().join(".config/loops/alpha/claude");
    let plan = claude_apply(root.path(), &[]);
    assert_eq!(plan["report"]["sign_in"], "absent");
    assert_eq!(
        fs::metadata(&home).expect("metadata").mode() & 0o7777,
        0o700
    );
    assert!(!home.join("CLAUDE.md").exists());
    assert!(!home.join("keys").exists());
    let credential = home.join(".credentials.json");
    fs::write(&credential, "unreadable credential canary").expect("credential");
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o0)).expect("unreadable");
    let original = fs::metadata(&credential).expect("metadata");
    fs::write(home.join("CLAUDE.md"), "charter map only").expect("charter");
    fs::create_dir(home.join("keys")).expect("retained keys directory");
    let settings_path = home.join("settings.json");
    let mut settings: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings_path).expect("settings")).expect("json");
    settings["owner-field"] = serde_json::json!({"keep":true});
    fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&settings).expect("json"),
    )
    .expect("settings");
    let retained = fs::read(&settings_path).expect("settings");
    let plan = claude_apply(root.path(), &["--reconcile"]);
    assert_eq!(plan["changed"], 0);
    assert_eq!(plan["report"]["sign_in"], "present");
    assert_eq!(plan["report"]["credential_metadata"]["mode"], 0);
    assert_eq!(plan["report"]["charter_present"], true);
    assert_eq!(
        plan["report"]["findings"],
        serde_json::json!([{"name":"keys-not-a-link"}])
    );
    assert_eq!(fs::read(&settings_path).expect("settings"), retained);
    assert_eq!(
        fs::metadata(&credential).expect("metadata").ino(),
        original.ino()
    );
    settings["permissions"]["allow"]
        .as_array_mut()
        .expect("rules")
        .remove(0);
    fs::write(&settings_path, serde_json::to_vec(&settings).expect("json")).expect("settings");
    let retained = fs::read(&settings_path).expect("settings");
    let plan = claude_apply(root.path(), &["--reconcile"]);
    assert!(plan["report"]["findings"].as_array().expect("findings").contains(&serde_json::json!({"name":"owner-settings-drift","node":"jay","field":"/permissions/allow"})));
    assert_eq!(fs::read(&settings_path).expect("settings"), retained);
    fs::remove_file(&settings_path).expect("owner removes settings");
    let plan = claude_apply(root.path(), &["--reconcile"]);
    assert_eq!(plan["changed"], 0);
    assert!(
        plan["report"]["findings"]
            .as_array()
            .expect("findings")
            .contains(&serde_json::json!({"name":"owner-settings-absent"}))
    );
    assert!(!settings_path.exists());
}

/// # Panics
/// Panics only if fixture setup or the selection/refusal contract fails.
/// ´test:integration:claude-home-node-selection-and-previous-layout-refuse-before-write´
#[test]
fn claude_home_node_selection_and_previous_layout_refuse_before_write() {
    let root = claude_fixture();
    let home = root.path().join(".config/loops/alpha/claude");
    let refused = claude_call(root.path(), &["--nodes", "missing", "--dry-run"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("registry-node"));
    assert!(!home.exists());
    fs::create_dir(root.path().join(".claude-alpha")).expect("previous home");
    let refused = claude_call(root.path(), &["--dry-run"]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("claude-home-previous-layout"));
    assert!(!home.exists());
    fs::remove_dir(root.path().join(".claude-alpha")).expect("remove fixture");
    let refused = claude_call(root.path(), &["--expect-digest", &"0".repeat(64)]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("claude-home-digest"));
    assert!(!home.exists());
    let plan = claude_apply(root.path(), &["--nodes", "jay"]);
    assert_eq!(
        plan["plan"]["file_digests"]
            .as_array()
            .expect("file digests")
            .iter()
            .map(|file| file["path"].as_str().expect("name"))
            .collect::<Vec<_>>(),
        ["known_hosts.routes", "settings.json", "ssh_config"]
    );
    let ssh = fs::read_to_string(home.join("ssh_config")).expect("ssh");
    assert!(ssh.contains("Host jay-worker"));
    assert!(!ssh.contains("Host owl-worker"));
    let plan = claude_apply(root.path(), &["--reconcile"]);
    let ssh_file = plan["plan"]["files"]
        .as_array()
        .expect("files")
        .iter()
        .find(|file| file["path"] == serde_json::json!(home.join("ssh_config")))
        .expect("SSH replacement preview");
    assert_eq!(ssh_file["action"], "replace");
    let known_hosts = fs::read(home.join("known_hosts.routes")).expect("both pinned nodes");
    assert!(String::from_utf8_lossy(&known_hosts).contains("[192.0.2.1]:2222 ssh-ed25519 AAAA"));
    assert!(String::from_utf8_lossy(&known_hosts).contains("192.0.2.2 ssh-ed25519 BBBB"));
    claude_apply(root.path(), &["--reconcile", "--nodes", "jay"]);
    assert_eq!(
        fs::read(home.join("known_hosts.routes")).expect("retained pinned nodes"),
        known_hosts
    );
    assert!(
        fs::read_to_string(home.join("ssh_config"))
            .expect("retained owl route")
            .contains("Host owl-worker")
    );
    let instance = root
        .path()
        .join(".local/share/orchestration-instance/servers.md");
    fs::write(
        &instance,
        fs::read_to_string(&instance)
            .expect("registry")
            .replace("|owl|active|", "|owl|retired|"),
    )
    .expect("retirement");
    claude_apply(root.path(), &["--reconcile"]);
    assert!(
        !fs::read_to_string(home.join("ssh_config"))
            .expect("ssh")
            .contains("Host owl-worker")
    );
    let plan = claude_apply(root.path(), &["--reconcile"]);
    assert_eq!(plan["changed"], 0);
}

fn invoke(root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args([
            "render-routes",
            "--loop",
            "alpha",
            "--owner-home",
            "/fixture",
        ])
        .arg("--registry")
        .arg(root.join("servers.md"))
        .arg("--output")
        .arg(root.join("out"))
        .output()
        .expect("render subprocess")
}

/// # Panics
/// Panics only if fixture setup or a rendering assertion fails.
///
/// ´test:integration:registry-routes-render-two-nodes-idempotently´
#[test]
fn registry_routes_render_two_nodes_idempotently() {
    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    fs::create_dir(root.path().join("out")).expect("output");
    fs::write(root.path().join("servers.md"), registry()).expect("registry");
    let first = invoke(root.path());
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stderr, [] as [u8; 0]);
    assert_eq!(first.stdout.last(), Some(&b'\n'));
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).expect("report");
    assert_eq!(report["fields"]["changed"], 7);
    assert_rendered_files(root.path());
    let before = fs::metadata(root.path().join("out/codex.ssh_config"))
        .expect("metadata")
        .modified()
        .expect("mtime");
    let second = invoke(root.path());
    assert!(second.status.success());
    let report: serde_json::Value = serde_json::from_slice(&second.stdout).expect("report");
    assert_eq!(report["fields"]["changed"], 0);
    assert_eq!(
        before,
        fs::metadata(root.path().join("out/codex.ssh_config"))
            .expect("metadata")
            .modified()
            .expect("mtime")
    );
    for (bad, reason) in registry_refusal_fixtures() {
        fs::write(root.path().join("servers.md"), bad).expect("bad registry");
        let refused = invoke(root.path());
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(refused.stdout, [] as [u8; 0]);
        let report: serde_json::Value = serde_json::from_slice(&refused.stderr).expect("refusal");
        assert_eq!(report["class"], "failure");
        assert_eq!(report["reason"], reason);
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("/home/"));
        assert_eq!(
            before,
            fs::metadata(root.path().join("out/codex.ssh_config"))
                .expect("metadata")
                .modified()
                .expect("mtime")
        );
    }
    fs::write(
        root.path().join("servers.md"),
        registry().replace("|owl|active|", "|owl|retired|"),
    )
    .expect("replacement");
    assert!(invoke(root.path()).status.success());
    let settings: serde_json::Value = serde_json::from_slice(
        &fs::read(root.path().join("out/claude.owner-settings.json")).expect("retired settings"),
    )
    .expect("json");
    assert_eq!(
        settings,
        serde_json::json!({"permissions":{"allow":["Bash(ssh -F /fixture/.config/loops/alpha/claude/ssh_config jay-worker *)"]},"sandbox":{"excludedCommands":["ssh -F /fixture/.config/loops/alpha/claude/ssh_config jay-worker"]}})
    );
    for kind in ["codex", "claude", "session"] {
        assert_eq!(
            fs::read_to_string(root.path().join(format!("out/{kind}.known_hosts")))
                .expect("retired keys"),
            "[192.0.2.1]:2222 ssh-ed25519 AAAA\n"
        );
    }
    assert!(
        !fs::read_to_string(root.path().join("out/codex.ssh_config"))
            .expect("config")
            .contains("owl")
    );
}

fn registry_refusal_fixtures() -> Vec<(String, &'static str)> {
    vec![
        (
            registry().replace("|jay|active|", "||active|"),
            "registry-row: line 11: node must be a present valid token",
        ),
        (
            registry().replace("|port|", "|unknown|"),
            "registry-field: line 9: missing port",
        ),
        (
            String::from("|Name|Location|Specs|Restrictions|\n"),
            "registry-table: missing ## Node routes",
        ),
        (
            registry().replace("|---|", "|--|"),
            "registry-table: invalid separator at line 10 (field count 12, expected 12)",
        ),
        (
            registry().replace("|2222|", "||"),
            "registry-row: alpha line 11: port must be a canonical decimal port from 1 to 65535 (got an empty value)",
        ),
        (
            registry().replace("|2222|", "|0|"),
            "registry-row: alpha line 11: port must be a canonical decimal port from 1 to 65535 (got an invalid form)",
        ),
        (
            registry().replacen("/fixture/worker-key", "/home/alpha/../private-key", 1),
            "registry-row: alpha line 11: worker_identity must be an absolute path without dot components or unsafe characters (got an absolute path with a dot component)",
        ),
        (
            registry().replacen("/fixture/worker-key", "/home/alpha/private key", 1),
            "registry-row: alpha line 11: worker_identity must be an absolute path without dot components or unsafe characters (got an absolute path with an unsafe character)",
        ),
        (
            registry().replace("|/home/stranger/private-key|", "|"),
            "registry-row: line 13: field count 11, expected 12",
        ),
        (
            registry().replace("private-key|\n", "private-key|extra|\n"),
            "registry-row: line 13: field count 13, expected 12",
        ),
        (
            registry().replacen("|2222|", "|0|", 1).replacen(
                "session-key|\n",
                "session-key|extra|\n",
                1,
            ),
            "registry-row: line 11: field count 13, expected 12",
        ),
        (
            registry().replace("|stranger|", "||"),
            "registry-row: line 13: loop must be a present valid token",
        ),
        (
            registry().replace("|jay-alpha|", "|owl-worker|"),
            "registry-row: alpha line 12: worker_alias must be unique (duplicate alias)",
        ),
    ]
}

/// # Panics
/// Panics only if fixture setup or the heading contract fails.
///
/// ´test:integration:registry-routes-heading-accepts-only-bare-or-labelled-title´
#[test]
fn registry_routes_heading_accepts_only_bare_or_labelled_title() {
    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    fs::create_dir(root.path().join("out")).expect("output");
    for (heading, changed) in [
        ("## Node routes", 7),
        ("## Node routes · `sec:servers:node-routes`", 0),
    ] {
        fs::write(
            root.path().join("servers.md"),
            registry().replace("## Node routes", heading),
        )
        .expect("registry");
        let output = invoke(root.path());
        assert!(output.status.success(), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(report["fields"]["changed"], changed);
        assert_rendered_files(root.path());
    }
    for heading in [
        "## Node routes extra",
        "## Node routes · `sec:servers:node-routes` extra",
        "## Node routes · ``sec:servers:node-routes``",
        "## Node routes · `not a label`",
        "## Other routes · `sec:servers:node-routes`",
    ] {
        fs::write(
            root.path().join("servers.md"),
            registry().replace("## Node routes", heading),
        )
        .expect("bad registry");
        let refused = invoke(root.path());
        assert_eq!(refused.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("registry-table: missing ## Node routes"),
            "{refused:?}"
        );
    }
}

/// # Panics
/// Panics only if the fixture terminal or subprocess assertions fail.
///
/// ´test:integration:route-report-refuses-raw-arguments-and-terminal-stdout´
#[test]
fn route_report_refuses_raw_arguments_and_terminal_stdout() {
    use std::io::Read as _;
    let refused = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["render-routes", "--secret-fixture-value", "payload"])
        .output()
        .expect("usage refusal");
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(refused.stdout, [] as [u8; 0]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&refused.stderr).expect("report"),
        serde_json::json!({"schema":1,"command":"superloop-lane render-routes","kind":"refusal","class":"usage","reason":"arguments: unknown or duplicate option"})
    );
    let pty = nix::pty::openpty(None, None).expect("terminal");
    let refused = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .arg("render-routes")
        .stdout(std::process::Stdio::from(pty.slave))
        .output()
        .expect("terminal refusal");
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&refused.stderr).expect("report"),
        serde_json::json!({"schema":1,"command":"superloop-lane render-routes","kind":"refusal","class":"usage","reason":"arguments: terminal stdout refused"})
    );
    let mut bytes = Vec::new();
    // Linux returns EIO once the last slave closes; any preceding bytes are retained.
    let _closed = fs::File::from(pty.master).read_to_end(&mut bytes);
    assert_eq!(bytes, [] as [u8; 0]);
}

fn assert_rendered_files(root: &std::path::Path) {
    for kind in ["codex", "claude", "session"] {
        let config =
            fs::read_to_string(root.join(format!("out/{kind}.ssh_config"))).expect("config");
        let (alias, key, home) = if kind == "session" {
            ("alpha", "session", String::from(".ssh"))
        } else if kind == "codex" {
            (
                "worker",
                "worker",
                String::from(".config/loops/alpha/codex"),
            )
        } else {
            ("worker", "worker", format!(".config/loops/alpha/{kind}"))
        };
        let mut expected = if kind == "codex" {
            String::from(
                "# Worker-server access for the alpha superloop's Codex lanes.\n# Selected estate nodes; the brief scopes which alias a lane may use. Values\n# selected from the instance routes registry (jay,owl);\n# registry of record: ~/.local/share/orchestration-instance/servers.md. The key is the loop's own worker\n# key, opening only the loop's own confined account.\n",
            )
        } else {
            String::new()
        };
        let identity = match kind {
            "codex" => String::from("/fixture/.config/loops/alpha/codex/keys/worker-key"),
            "session" => String::from("~/.ssh/session-key"),
            _ => format!("/fixture/{key}-key"),
        };
        let known = if kind == "session" {
            String::from("~/.ssh/known_hosts.clients")
        } else {
            format!("/fixture/{home}/known_hosts.routes")
        };
        let policy = "yes";
        for (node, host, port) in [("jay", "192.0.2.1", "2222"), ("owl", "192.0.2.2", "22")] {
            use std::fmt::Write as _;
            write!(expected, "Host {node}-{alias}\n  HostName {host}\n  Port {port}\n  User staff\n  IdentityFile {identity}\n  IdentitiesOnly yes\n  UserKnownHostsFile {known}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking {policy}\n  UpdateHostKeys no\n\n").expect("string");
        }
        assert_eq!(config, expected);
        assert_eq!(
            fs::read_to_string(root.join(format!("out/{kind}.known_hosts"))).expect("keys"),
            "[192.0.2.1]:2222 ssh-ed25519 AAAA\n[192.0.2.2]:22 ssh-ed25519 BBBB\n192.0.2.2 ssh-ed25519 BBBB\n"
        );
    }
    let settings: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("out/claude.owner-settings.json")).expect("settings"),
    )
    .expect("json");
    assert_eq!(
        settings,
        serde_json::json!({"permissions":{"allow":["Bash(ssh -F /fixture/.config/loops/alpha/claude/ssh_config jay-worker *)", "Bash(ssh -F /fixture/.config/loops/alpha/claude/ssh_config owl-worker *)"]},"sandbox":{"excludedCommands":["ssh -F /fixture/.config/loops/alpha/claude/ssh_config jay-worker","ssh -F /fixture/.config/loops/alpha/claude/ssh_config owl-worker"]}})
    );
}

/// # Panics
/// Panics only if fixture setup or the prepublication refusal contract fails.
///
/// ´test:integration:route-output-encoding-refuses-before-publication´
#[test]
fn route_output_encoding_refuses_before_publication() {
    use std::os::unix::ffi::OsStringExt as _;

    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let output = root
        .path()
        .join(std::ffi::OsString::from_vec(b"out-\xff".to_vec()));
    fs::create_dir(&output).expect("output directory");
    fs::write(output.join("codex.ssh_config"), b"unchanged").expect("existing output");
    fs::write(root.path().join("servers.md"), registry()).expect("registry");
    let refused = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args([
            "render-routes",
            "--loop",
            "alpha",
            "--owner-home",
            "/fixture",
            "--registry",
        ])
        .arg(root.path().join("servers.md"))
        .arg("--output")
        .arg(&output)
        .output()
        .expect("render subprocess");
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(refused.stdout, [] as [u8; 0]);
    let report: serde_json::Value = serde_json::from_slice(&refused.stderr).expect("JSON refusal");
    assert_eq!(report["reason"], "arguments: non-UTF-8 output");
    assert_eq!(fs::read_dir(&output).expect("output entries").count(), 1);
    assert_eq!(
        fs::read(output.join("codex.ssh_config")).expect("existing output"),
        b"unchanged"
    );
}
