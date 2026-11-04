//! Exercise private command forms through the installed binary entry, including descriptor binding.

#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

// These fixtures exercise the production convergence function, not the namespace
// root transition or the binary's _install-private descriptor entry.
struct SignInFixture {
    home: tempfile::TempDir,
    root: std::path::PathBuf,
    target: std::path::PathBuf,
}

impl SignInFixture {
    fn new() -> Self {
        let home = tempfile::tempdir_in(temporary_root::temporary_root()).expect("sign-in fixture");
        let root = home.path().join(".config/loops/alpha/lanes/codex");
        fs::create_dir_all(&root).expect("sign-in directory");
        for relative in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
            ".config/loops/alpha/lanes/codex",
        ] {
            fs::set_permissions(
                home.path().join(relative),
                fs::Permissions::from_mode(0o700),
            )
            .expect("protected custody");
        }
        for name in ["auth.json", "config.toml", "state.sqlite"] {
            fs::write(root.join(name), b"synthetic sign-in state").expect("sign-in file");
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600))
                .expect("file mode");
        }
        let target = home.path().join("outside-dispatch-target");
        fs::write(&target, b"synthetic executable outside the sign-in").expect("outside target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).expect("target mode");
        Self { home, root, target }
    }

    fn converge(
        &self,
        worker: u32,
        dry_run: bool,
    ) -> Result<serde_json::Value, superloop_lane::error::LaneError> {
        let owner = nix::unistd::Uid::effective().as_raw();
        assert_ne!(owner, worker, "fixture worker differs from the owner");
        superloop_lane::sign_in::converge(
            self.home.path(),
            "alpha",
            owner,
            nix::unistd::Gid::effective().as_raw(),
            worker,
            dry_run,
        )
    }

    fn scratch(&self, suffix: &str) -> std::path::PathBuf {
        let dispatch = self.root.join("tmp/arg0").join(suffix);
        fs::create_dir_all(&dispatch).expect("dispatch scratch");
        fs::set_permissions(&dispatch, fs::Permissions::from_mode(0o700)).expect("dispatch mode");
        fs::write(dispatch.join(".lock"), b"synthetic dispatch lock").expect("lock");
        fs::set_permissions(dispatch.join(".lock"), fs::Permissions::from_mode(0o644))
            .expect("scratch lock is not converged");
        for name in [
            "apply_patch",
            "apply-patch",
            "dispatch-three",
            "dispatch-four",
        ] {
            symlink(&self.target, dispatch.join(name)).expect("outside executable link");
        }
        dispatch
    }

    fn refuse(&self, name: &str) {
        for worker in [3000, 3001] {
            for dry_run in [true, false] {
                let error = self
                    .converge(worker, dry_run)
                    .expect_err("unsafe path refuses");
                assert_eq!(error.kind, "sign-in-path");
                assert!(error.detail.starts_with(&format!("{name}: ")), "{error:?}");
            }
        }
    }
}

fn inode_metadata(path: &Path) -> (u64, u64, u32, u32, u32, i64, i64) {
    let metadata = fs::symlink_metadata(path).expect("inode metadata");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

/// ´test:integration:sign-in-convergence-preserves-dispatch-scratch-and-repeats´
#[test]
fn sign_in_convergence_preserves_dispatch_scratch_and_repeats() {
    for worker in [3000, 3001] {
        let fixture = SignInFixture::new();
        let dispatch = fixture.scratch("codex-arg0XXXXXX");
        let arg0 = fixture.root.join("tmp/arg0");
        // Listing this directory would fail; the changing run still repairs its mode.
        fs::set_permissions(&arg0, fs::Permissions::from_mode(0o300)).expect("unlistable scratch");
        let auth = fixture.root.join("auth.json");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o644))
            .expect("repairable credential");
        let names = [
            ".lock",
            "apply_patch",
            "apply-patch",
            "dispatch-three",
            "dispatch-four",
        ];
        let scratch_before = names.map(|name| inode_metadata(&dispatch.join(name)));
        let target_before = inode_metadata(&fixture.target);
        let auth_before = inode_metadata(&auth);
        let arg0_before = inode_metadata(&arg0);
        let preview = fixture.converge(worker, true).expect("scratch preview");
        assert_eq!(preview["complete"], false);
        assert_eq!(inode_metadata(&auth), auth_before);
        assert_eq!(inode_metadata(&arg0), arg0_before);
        let changed = fixture
            .converge(worker, false)
            .expect("scratch convergence");
        assert_eq!(changed["complete"], true);
        assert_eq!(changed["changes"], preview["changes"]);
        assert_eq!(inode_metadata(&auth).4 & 0o7777, 0o600);
        assert_eq!(inode_metadata(&arg0).4 & 0o7777, 0o700);
        assert_eq!(
            names.map(|name| inode_metadata(&dispatch.join(name))),
            scratch_before
        );
        assert_eq!(inode_metadata(&fixture.target), target_before);
        assert_eq!(
            fs::read(&auth).expect("credential preserved"),
            b"synthetic sign-in state"
        );
        assert_eq!(
            fs::read(dispatch.join(".lock")).expect("lock preserved"),
            b"synthetic dispatch lock"
        );
        for name in &names[1..] {
            assert_eq!(
                fs::read_link(dispatch.join(name)).expect("link preserved"),
                fixture.target
            );
        }
        fixture.scratch("codex-arg0LATER");
        for dry_run in [true, false] {
            let repeated = fixture
                .converge(worker, dry_run)
                .expect("later login scratch");
            assert_eq!(repeated["complete"], true);
            assert_eq!(repeated["changes"], serde_json::json!([]));
        }
    }
}

/// ´test:integration:sign-in-convergence-refuses-links-outside-dispatch-scratch´
#[test]
fn sign_in_convergence_refuses_links_outside_dispatch_scratch() {
    for name in [
        "auth.json",
        "config.toml",
        "state.sqlite",
        "sessions/linked",
        "log/linked",
        "tmp/linked",
        "tmp/other/linked",
        "nested/tmp/arg0/linked",
    ] {
        let fixture = SignInFixture::new();
        fixture.scratch("codex-arg0XXXXXX");
        let path = fixture.root.join(name);
        fs::create_dir_all(path.parent().expect("link parent")).expect("parent");
        if path.exists() {
            fs::remove_file(&path).expect("replace fixture file");
        }
        symlink(&fixture.target, &path).expect("forbidden link");
        let before = inode_metadata(&fixture.target);
        fixture.refuse(path.file_name().expect("name").to_str().expect("text name"));
        assert_eq!(inode_metadata(&fixture.target), before);
        assert_eq!(
            fs::read_link(&path).expect("refused link remains"),
            fixture.target
        );
    }
}

/// ´test:integration:sign-in-convergence-refuses-linked-or-nondirectory-scratch-root´
#[test]
fn sign_in_convergence_refuses_linked_or_nondirectory_scratch_root() {
    for name in ["tmp", "tmp/arg0"] {
        let fixture = SignInFixture::new();
        let path = fixture.root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("scratch parent");
        symlink(fixture.home.path(), &path).expect("linked scratch boundary");
        fixture.refuse(path.file_name().expect("name").to_str().expect("text name"));
        assert_eq!(
            fs::read_link(&path).expect("boundary remains"),
            fixture.home.path()
        );
    }
    let fixture = SignInFixture::new();
    fs::create_dir(fixture.root.join("tmp")).expect("temporary directory");
    let arg0 = fixture.root.join("tmp/arg0");
    fs::write(&arg0, b"not a directory").expect("regular arg0");
    let before = inode_metadata(&arg0);
    for worker in [3000, 3001] {
        for dry_run in [true, false] {
            let error = fixture
                .converge(worker, dry_run)
                .expect_err("regular arg0 refuses");
            assert_eq!(error.kind, "sign-in-path");
            assert_eq!(
                error.detail,
                format!("{} is not a dispatch scratch directory", arg0.display())
            );
        }
    }
    assert_eq!(inode_metadata(&arg0), before);
}

fn enter(body: &[String], home: &Path, runs: &Path, extra: Option<&Path>) -> Output {
    let home_fd = File::open(home).expect("owner home");
    let runs_fd = File::open(runs).expect("runs root");
    let extra_fd = extra.map(|path| File::open(path).expect("external parent"));
    let runs_number = runs_fd.as_raw_fd();
    let extra_number = extra_fd.as_ref().map(AsRawFd::as_raw_fd);
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    command.args(body).args([
        "--verified-home-fd",
        "0",
        "--verified-runs-root",
        runs.to_str().expect("runs path"),
        "--verified-runs-root-fd",
        "3",
    ]);
    if let Some(parent) = extra {
        command.args([
            "--verified-letter-dir",
            parent.to_str().expect("external parent path"),
            "--verified-letter-fd",
            "4",
        ]);
    }
    command.stdin(Stdio::from(home_fd));
    // The child receives the two held directory descriptors at stable numbers.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(runs_number, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(number) = extra_number
                && (libc::dup2(number, 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output().expect("private binary entry")
}

/// ´test:integration:home-layout-private-entry-binds-owner-home-and-record´
#[test]
fn home_layout_private_entry_binds_owner_home_and_record() {
    let fixture = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let home = fixture.path().join("owner");
    let runs = home.join("runs");
    fs::create_dir(&home).expect("home");
    fs::create_dir(&runs).expect("runs");
    let identity = format!("1:2:{}", "a".repeat(64));
    let body =
        superloop_lane::launch::exercise::home_layout_private_argv("alpha", "R", &identity, &home)
            .expect("public builder");
    let (loop_name, run, parsed_identity, parsed_home) =
        superloop_lane::launch::exercise::parse_home_layout_private_argv(&body)
            .expect("private parser");
    assert_eq!(
        (loop_name, run, parsed_identity),
        ("alpha", "R", identity.as_str())
    );
    assert_eq!(parsed_home, home);
    assert_eq!(parsed_home.join(".cache/work"), home.join(".cache/work"));
    assert_eq!(
        parsed_home.join(".local/outbox"),
        home.join(".local/outbox")
    );
    assert_eq!(
        parsed_home.join(".config/loops/alpha/lanes/codex"),
        home.join(".config/loops/alpha/lanes/codex")
    );
    let output = enter(&body, &home, &runs, None);
    let refusal = String::from_utf8(output.stderr).expect("refusal text");
    assert!(!output.status.success(), "private fixture has no run");
    assert!(refusal.contains(&home.display().to_string()), "{refusal}");
    assert!(!refusal.contains(&identity), "{refusal}");

    let mut malformed = body;
    malformed[3] = "--wrong-record".into();
    let output = enter(&malformed, &home, &runs, None);
    assert_eq!(output.status.code(), Some(2));
    let refusal = String::from_utf8(output.stderr).expect("malformed refusal");
    assert!(
        refusal.contains("exercise-home-layout-form: private form is malformed"),
        "{refusal}"
    );
}

/// ´test:integration:harvest-case-private-entry-binds-owner-home-and-record´
#[test]
fn harvest_case_private_entry_binds_owner_home_and_record() {
    let fixture = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let home = fixture.path().join("owner");
    let runs = home.join("runs");
    fs::create_dir(&home).expect("home");
    fs::create_dir(&runs).expect("runs");
    let identity = format!("1:2:{}", "a".repeat(64));
    let body =
        superloop_lane::launch::exercise::harvest_private_argv("alpha", "R", &identity, &home)
            .expect("public builder");
    let (loop_name, run, parsed_identity, parsed_home) =
        superloop_lane::launch::exercise::parse_harvest_private_argv(&body)
            .expect("private parser");
    assert_eq!(
        (loop_name, run, parsed_identity),
        ("alpha", "R", identity.as_str())
    );
    assert_eq!(parsed_home, home);
    let output = enter(&body, &home, &runs, None);
    let refusal = String::from_utf8(output.stderr).expect("refusal text");
    assert!(!output.status.success(), "fixture has no private run");
    assert!(refusal.contains(&home.display().to_string()), "{refusal}");
    assert!(!refusal.contains(&identity), "{refusal}");
    let mut malformed = body;
    malformed[3] = "--wrong-record".into();
    let output = enter(&malformed, &home, &runs, None);
    assert_eq!(output.status.code(), Some(2));
    let refusal = String::from_utf8(output.stderr).expect("malformed refusal");
    assert!(
        refusal.contains("exercise-harvest-form: private form is malformed"),
        "{refusal}"
    );
}

/// ´test:integration:other-bite-private-entries-bind-their-owner-home´
#[test]
#[allow(clippy::too_many_lines)]
fn other_bite_private_entries_bind_their_owner_home() {
    let fixture = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let home = fixture.path().join("owner");
    let runs = home.join("runs");
    let outside = fixture.path().join("outside");
    fs::create_dir(&home).expect("home");
    fs::create_dir(&runs).expect("runs");
    fs::create_dir(&outside).expect("outside");
    let home_word = home.display().to_string();
    let object = "a".repeat(40);
    let forms: [(&str, Vec<String>, bool); 6] = [
        (
            "checkpoint",
            superloop_lane::launch::checkpoint::private_checkpoint_argv(
                &superloop_lane::launch::checkpoint::CheckpointRequest {
                    loop_name: "alpha".into(),
                    run: "R".into(),
                    dry_run: true,
                    invocation_token: None,
                },
                &home,
                None,
            )
            .expect("public checkpoint builder"),
            false,
        ),
        (
            "checkout",
            superloop_lane::launch::checkout::private_checkout_argv(
                &superloop_lane::launch::checkout::CheckoutRequest {
                    loop_name: "alpha".into(),
                    run: "R".into(),
                    repo: "tools".into(),
                    into: outside.join("R"),
                    dry_run: true,
                    invocation_token: None,
                },
                &home,
                None,
            )
            .expect("public checkout builder"),
            true,
        ),
        (
            "harvest",
            superloop_lane::launch::harvest::private_harvest_argv(
                &superloop_lane::launch::harvest::HarvestRequest {
                    loop_name: "alpha".into(),
                    run: "R".into(),
                    gate_object: object.clone(),
                    dry_run: true,
                },
                &home,
                false,
            )
            .expect("public harvest builder"),
            false,
        ),
        (
            "import",
            superloop_lane::launch::imports::private_import_argv(
                &superloop_lane::launch::imports::MarkImportedRequest {
                    loop_name: "alpha".into(),
                    run: "R".into(),
                    object,
                },
                &home,
            )
            .expect("public import builder"),
            false,
        ),
        (
            "follow",
            superloop_lane::launch::follow::private_follow_argv(
                &home, "alpha", "R", "dispatch", &outside, "1:2:abc",
            )
            .expect("public follow builder"),
            false,
        ),
        (
            "rotation",
            superloop_lane::launch::rotation::private_handover_argv(
                "alpha", "R", &home, &runs, "1:2:abc",
            )
            .expect("public rotation builder"),
            false,
        ),
    ];
    for (name, body, external) in forms {
        let output = enter(&body, &home, &runs, external.then_some(outside.as_path()));
        let refusal = String::from_utf8(output.stderr).expect("refusal text");
        assert!(refusal.contains(&home_word), "{name}: {refusal}");
        assert!(!refusal.contains("verified-prefix:"), "{name}: {refusal}");
        assert!(!refusal.contains("private form is"), "{name}: {refusal}");
        assert!(!output.status.success(), "{name}: fixture has no run");
        let (flag_index, refusal_kind) = match name {
            "checkpoint" => (3, "checkpoint-private"),
            "checkout" => (3, "checkout-private"),
            "harvest" => (3, "harvest-private"),
            "import" => (3, "import-private"),
            "follow" => (3, "follow-private"),
            "rotation" => (5, "rotate-private"),
            _ => panic!("unexpected private form"),
        };
        let mut drifted = body;
        drifted[flag_index] = "--wrong-option".into();
        let output = enter(
            &drifted,
            &home,
            &runs,
            external.then_some(outside.as_path()),
        );
        let refusal = String::from_utf8(output.stderr).expect("drifted form refusal");
        assert!(refusal.contains(refusal_kind), "{name}: {refusal}");
        assert!(!refusal.contains("verified-prefix:"), "{name}: {refusal}");
    }
}
