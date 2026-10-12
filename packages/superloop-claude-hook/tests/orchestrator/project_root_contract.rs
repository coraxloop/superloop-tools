mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use support::{OLD_MTIME_NS, OLD_RULEBOOK, TestDir, run_cli_at, run_hook_bytes, write_rulebook};

fn create_git_directory(root: &Path) {
    let marker = root.join(".git");
    std::fs::create_dir_all(&marker).expect("create repository marker");
    std::fs::write(marker.join("HEAD"), "ref: refs/heads/main\n").expect("create repository HEAD");
}

fn project_flag(directory: &TestDir, cwd: &Path) -> PathBuf {
    directory.state_dir().join(format!(
        "orchestrator-disabled{}",
        cwd.to_string_lossy().replace('/', "-")
    ))
}

fn startup(cwd: &Path, session: &str) -> Value {
    json!({
        "hook_event_name": "SessionStart",
        "session_id": session,
        "source": "startup",
        "cwd": cwd
    })
}

fn run_fixture_hook(directory: &TestDir, payload: &Value) -> std::process::Output {
    run_hook_bytes(
        directory,
        &serde_json::to_vec(payload).expect("serialize resolver payload"),
        [],
    )
}

/// ´test:integration:subdirectory-toggle-and-root-hook-share-one-project-flag´
#[test]
fn subdirectory_toggle_and_root_hook_share_one_project_flag() {
    let directory = TestDir::new("project-root-hook");
    let root = directory.home().join("project");
    let nested = root.join("nested/deeper");
    create_git_directory(&root);
    std::fs::create_dir_all(&nested).expect("create nested working directory");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);

    let on = run_cli_at(&directory, ["on"], &nested);
    let status = run_cli_at(&directory, ["status"], &nested);
    let off = run_cli_at(&directory, ["off"], &nested);

    assert_eq!(on.status.code(), Some(0));
    assert_eq!(
        on.stdout,
        format!("orchestrator ON for {}\n", root.to_string_lossy()).into_bytes()
    );
    assert_eq!(status.status.code(), Some(0));
    assert!(
        String::from_utf8(status.stdout)
            .expect("status UTF-8")
            .starts_with(&format!(
                "ON ({})\nglobal: on\nproject: on\n",
                root.display()
            ))
    );
    assert_eq!(off.status.code(), Some(0));
    assert_eq!(
        off.stdout,
        format!("orchestrator OFF for {}\n", root.to_string_lossy()).into_bytes()
    );

    let hook = run_fixture_hook(&directory, &startup(&root, "root-hook"));
    assert_eq!(hook.status.code(), Some(0));
    assert_eq!(hook.stdout, [] as [u8; 0]);
    assert!(!directory.exists("state/orchestrator-scope-root-hook.json"));
}

/// ´test:integration:root-cwd-retains-deployed-folded-flag-name´
#[test]
fn root_cwd_retains_deployed_folded_flag_name() {
    let directory = TestDir::new("root-flag-literal");
    let root = directory.home().join("project");
    create_git_directory(&root);

    let toggle = run_cli_at(&directory, ["off"], &root);
    let expected_name = format!(
        "orchestrator-disabled{}",
        root.to_string_lossy().replace('/', "-")
    );
    let expected = directory.state_dir().join(&expected_name);

    assert_eq!(toggle.status.code(), Some(0));
    assert_eq!(
        toggle.stdout,
        format!("orchestrator OFF for {}\n", root.to_string_lossy()).into_bytes()
    );
    assert_eq!(expected.file_name(), Some(OsStr::new(&expected_name)));
    assert!(expected.exists());
}

/// ´test:integration:nested-worktree-marker-selects-its-directory-as-project-root´
#[test]
fn nested_worktree_marker_selects_its_directory_as_project_root() {
    let directory = TestDir::new("nested-worktree");
    let outer = directory.home().join("outer");
    let worktree = outer.join("worktree");
    let nested = worktree.join("source/module");
    create_git_directory(&outer);
    std::fs::create_dir_all(&nested).expect("create nested worktree directory");
    std::fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/example\n")
        .expect("create worktree marker");

    let toggle = run_cli_at(&directory, ["off"], &nested);

    assert_eq!(toggle.status.code(), Some(0));
    assert_eq!(
        toggle.stdout,
        format!("orchestrator OFF for {}\n", worktree.to_string_lossy()).into_bytes()
    );
    assert!(project_flag(&directory, &worktree).exists());
}

/// ´test:integration:implausible-git-entry-stops-before-outer-project´
#[test]
fn implausible_git_entry_stops_before_outer_project() {
    let directory = TestDir::new("implausible-marker");
    let outer = directory.home().join("outer");
    let checkout = outer.join("checkout");
    let cwd = checkout.join("nested");
    create_git_directory(&outer);
    std::fs::create_dir_all(checkout.join(".git")).expect("create implausible marker");
    std::fs::create_dir_all(&cwd).expect("create nested working directory");

    let toggle = run_cli_at(&directory, ["off"], &cwd);

    assert_eq!(toggle.status.code(), Some(0));
    assert_eq!(
        toggle.stdout,
        format!("orchestrator OFF for {}\n", cwd.to_string_lossy()).into_bytes()
    );
    assert!(project_flag(&directory, &cwd).exists());
    assert!(!project_flag(&directory, &outer).exists());
}

/// ´test:integration:cwd-outside-home-walks-unbounded-to-nearest-project´
#[test]
fn cwd_outside_home_walks_unbounded_to_nearest_project() {
    let directory = TestDir::new("outside-home");
    let project = directory.path().join("outside/project");
    let cwd = project.join("nested");
    std::fs::create_dir_all(directory.home()).expect("create fixture home");
    create_git_directory(&project);
    std::fs::create_dir_all(&cwd).expect("create cwd outside home");

    let toggle = run_cli_at(&directory, ["off"], &cwd);

    assert_eq!(toggle.status.code(), Some(0));
    assert_eq!(
        toggle.stdout,
        format!("orchestrator OFF for {}\n", project.to_string_lossy()).into_bytes()
    );
    assert!(project_flag(&directory, &project).exists());
}

/// ´test:integration:relative-cwd-is-returned-without-filesystem-probe´
#[test]
fn relative_cwd_is_returned_without_filesystem_probe() {
    let directory = TestDir::new("relative-cwd");
    let cwd = Path::new("relative/project");
    std::fs::create_dir_all(directory.state_dir()).expect("create fixture state directory");
    std::fs::write(project_flag(&directory, cwd), []).expect("create relative project flag");

    let hook = run_fixture_hook(&directory, &startup(cwd, "relative-cwd"));

    assert_eq!(hook.status.code(), Some(0));
    assert_eq!(hook.stdout, [] as [u8; 0]);
    assert!(!directory.exists("state/orchestrator-scope-relative-cwd.json"));
}

/// ´test:integration:empty-hook-cwd-is-returned-without-filesystem-probe´
#[test]
fn empty_hook_cwd_is_returned_without_filesystem_probe() {
    let directory = TestDir::new("empty-hook-cwd");
    std::fs::create_dir_all(directory.state_dir()).expect("create fixture state directory");
    std::fs::write(project_flag(&directory, Path::new("")), []).expect("create empty project flag");

    let hook = run_fixture_hook(&directory, &startup(Path::new(""), "empty-hook-cwd"));

    assert_eq!(hook.status.code(), Some(0));
    assert_eq!(hook.stdout, [] as [u8; 0]);
    assert!(!directory.exists("state/orchestrator-scope-empty-hook-cwd.json"));
}

/// ´test:integration:empty-pwd-falls-back-to-marked-process-directory´
#[test]
fn empty_pwd_falls_back_to_marked_process_directory() {
    let directory = TestDir::new("empty-cwd");
    let project = directory
        .project()
        .canonicalize()
        .expect("canonicalize fixture project");

    let toggle = run_cli_at(&directory, ["off"], Path::new(""));

    assert_eq!(toggle.status.code(), Some(0));
    assert_eq!(
        toggle.stdout,
        format!("orchestrator OFF for {}\n", project.display()).into_bytes()
    );
    assert!(project_flag(&directory, &project).exists());
    assert!(!directory.state_dir().join("orchestrator-disabled").exists());
}

/// ´test:integration:session-record-keeps-raw-subdirectory-working-directory´
#[test]
fn session_record_keeps_raw_subdirectory_working_directory() {
    let directory = TestDir::new("raw-session-cwd");
    let root = directory.home().join("project");
    let nested = root.join("nested/deeper");
    create_git_directory(&root);
    std::fs::create_dir_all(&nested).expect("create nested working directory");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);

    let hook = run_fixture_hook(&directory, &startup(&nested, "raw-cwd"));

    assert_eq!(hook.status.code(), Some(0));
    assert_ne!(hook.stdout, [] as [u8; 0]);
    assert_eq!(
        directory.state("raw-cwd")["cwd"],
        nested.to_string_lossy().as_ref()
    );
}
