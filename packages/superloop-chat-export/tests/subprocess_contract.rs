use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_superloop-chat-export");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run_into(chats: &Path, registry: &Path, projects: &Path, args: &[&str]) -> Output {
    Command::new(BINARY)
        .arg("--registry")
        .arg(registry)
        .arg("--projects")
        .arg(projects)
        .arg("--chats")
        .arg(chats)
        .args(args)
        .env_remove("HOME")
        .output()
        .expect("run superloop-chat-export")
}

fn run_in(registry: &Path, projects: &Path, args: &[&str]) -> Output {
    let chats = tempfile::tempdir().expect("temporary directory");
    run_into(chats.path(), registry, projects, args)
}

fn run(args: &[&str]) -> Output {
    let fixtures = fixtures();
    run_in(&fixtures.join("registry"), &fixtures.join("projects"), args)
}

fn stdout_lines(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn without_wall(line: &str) -> &str {
    line.split_once(" wall_ms=")
        .map_or(line, |(fields, _)| fields)
}

/// ´test:integration:version-names-the-program-and-its-version´
#[test]
fn version_names_the_program_and_its_version() {
    let output = Command::new(BINARY)
        .arg("--version")
        .output()
        .expect("run superloop-chat-export");
    assert!(output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stderr).expect("version record"),
        serde_json::json!({
            "schema": 1,
            "command": "superloop-chat-export",
            "kind": "version",
            "message": "version requested",
            "fields": {
                "type": "version",
                "version": format!("superloop-chat-export {}", env!("CARGO_PKG_VERSION")),
            },
        })
    );
}

/// ´test:integration:the-least-block-limit-renders-and-counts-what-it-cuts´
#[test]
fn the_least_block_limit_renders_and_counts_what_it_cuts() {
    let chats = tempfile::tempdir().expect("temporary directory");
    let fixtures = fixtures();
    let output = run_into(
        chats.path(),
        &fixtures.join("registry"),
        &fixtures.join("projects"),
        &["--loop", "gamma", "--max-block-bytes", "64"],
    );
    assert!(output.status.success(), "{output:?}");
    let cut = std::fs::read_dir(chats.path().join("gamma"))
        .expect("the loop's folder")
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .any(|page| page.contains(" bytes omitted]</span>"));
    assert!(cut);
}

/// ´test:integration:a-registered-loop-prints-its-report-line´
#[test]
fn a_registered_loop_prints_its_report_line() {
    let output = run(&["--loop", "alpha"]);
    assert!(output.status.success(), "{output:?}");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(without_wall(&lines[0]), ALPHA);
    assert_eq!(without_wall(&lines[1]), "loops=1");
    assert!(lines.iter().all(|line| line.contains(" wall_ms=")));
}

const ALPHA: &str = "loop=alpha files=4 records=28 copies_dropped=4 malformed=5 oversized=0 ignored=0 skipped=0 meta_skipped=0 conversations=5 segments=5 turns=8 prompts=6 pages=5 branches=0 agents=0 agents_nested=0 agents_unattached=0 held_back=1 missing_logical_parents=0 links=parent:23,logical:0,tail:0,previous:0,root:5,dangling:0 exchanges=3 groups=2 unanswered=0 pages_rendered=5 files_written=15 files_unchanged=0 files_removed=0 files_foreign=0";

const GAMMA_TREE: &str = "loop=gamma files=5 records=31 copies_dropped=11 malformed=0 oversized=0 ignored=0 skipped=0 meta_skipped=0 conversations=2 segments=5 turns=10 prompts=7 pages=9 branches=1 agents=3 agents_nested=1 agents_unattached=1 held_back=0 missing_logical_parents=2 links=parent:26,logical:1,tail:1,previous:1,root:2,dangling:0 exchanges=4 groups=3 unanswered=1";

const GAMMA: &str = "loop=gamma files=5 records=31 copies_dropped=11 malformed=0 oversized=0 ignored=0 skipped=0 meta_skipped=0 conversations=2 segments=5 turns=10 prompts=7 pages=9 branches=1 agents=3 agents_nested=1 agents_unattached=1 held_back=0 missing_logical_parents=2 links=parent:26,logical:1,tail:1,previous:1,root:2,dangling:0 exchanges=4 groups=3 unanswered=1 pages_rendered=9 files_written=16 files_unchanged=0 files_removed=0 files_foreign=0";

/// ´test:integration:a-second-run-writes-nothing-and-leaves-foreign-files´
#[test]
fn a_second_run_writes_nothing_and_leaves_foreign_files() {
    let chats = tempfile::tempdir().expect("temporary directory");
    let fixtures = fixtures();
    let (registry, projects) = (fixtures.join("registry"), fixtures.join("projects"));
    let again = || run_into(chats.path(), &registry, &projects, &["--loop", "gamma"]);
    let first = again();
    assert_eq!(without_wall(&stdout_lines(&first)[0]), GAMMA);
    let second = again();
    assert_eq!(
        without_wall(&stdout_lines(&second)[0]),
        format!(
            "{GAMMA_TREE} pages_rendered=0 files_written=0 files_unchanged=16 files_removed=0 files_foreign=0"
        )
    );
    std::fs::write(chats.path().join("gamma/SESSION-ID-OLD.html"), "old").expect("foreign page");
    std::fs::write(chats.path().join("kept.html"), "kept").expect("outside file");
    let third = again();
    assert!(third.status.success(), "{third:?}");
    assert_eq!(
        without_wall(&stdout_lines(&third)[0]),
        format!(
            "{GAMMA_TREE} pages_rendered=0 files_written=0 files_unchanged=16 files_removed=0 files_foreign=1"
        )
    );
    let told = String::from_utf8_lossy(&third.stderr);
    assert!(told.contains("loop gamma: left 1 files in "), "{told}");
    assert!(
        told.contains("that the program does not own: \"SESSION-ID-OLD.html\"\n"),
        "{told}"
    );
    assert!(chats.path().join("gamma/SESSION-ID-OLD.html").exists());
    assert!(chats.path().join("kept.html").exists());
    let loops = std::fs::read_to_string(chats.path().join("index.html")).expect("loops index");
    assert!(loops.contains(r#"<a href="gamma&#x2f;index.html">gamma</a>"#));
    assert!(!loops.contains("alpha&#x2f;index.html"));
    assert!(loops.contains(r#"<link rel="stylesheet" href="chat-export.css">"#));
    assert!(!loops.contains("<style"));
    let shared = std::fs::read(chats.path().join("chat-export.css")).expect("shared stylesheet");
    let own = std::fs::read(chats.path().join("gamma/chat-export.css")).expect("loop stylesheet");
    assert_eq!(shared, own);
}

/// ´test:integration:a-foreign-file-in-the-way-refuses-its-loop-and-the-run-goes-on´
#[test]
fn a_foreign_file_in_the_way_refuses_its_loop_and_the_run_goes_on() {
    let chats = tempfile::tempdir().expect("temporary directory");
    let fixtures = fixtures();
    std::fs::create_dir_all(chats.path().join("alpha")).expect("loop folder");
    std::fs::write(chats.path().join("alpha/index.html"), "mine").expect("foreign index");
    let output = run_into(
        chats.path(),
        &fixtures.join("registry"),
        &fixtures.join("projects"),
        &["--loop", "alpha", "--loop", "gamma"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let lines = stdout_lines(&output);
    let fields: Vec<_> = lines.iter().map(|line| without_wall(line)).collect();
    assert_eq!(fields, ["loop=alpha status=refused", GAMMA, "loops=2"]);
    let told = String::from_utf8_lossy(&output.stderr);
    assert!(
        told.contains("superloop-chat-export: refused loop alpha: "),
        "{told}"
    );
    assert!(
        told.contains("alpha/index.html\" stands where the run writes"),
        "{told}"
    );
    assert!(
        told.contains("refused 1 loops, 0 files at the output root and 0 registered names"),
        "{told}"
    );
    assert_eq!(
        std::fs::read_to_string(chats.path().join("alpha/index.html")).expect("kept"),
        "mine"
    );
    assert!(!chats.path().join("alpha/p0001.html").exists());
}

/// ´test:integration:a-registered-name-outside-the-grammar-is-left-out´
#[test]
fn a_registered_name_outside_the_grammar_is_left_out() {
    let registry = tempfile::tempdir().expect("temporary directory");
    let fixtures = fixtures();
    std::fs::copy(
        fixtures.join("registry/alpha.env"),
        registry.path().join("alpha.env"),
    )
    .expect("alpha");
    for (file, name) in [
        ("scheme", "javascript:alert(1)"),
        ("parent", ".."),
        ("separator", "a/b"),
        ("query", "q?x"),
    ] {
        std::fs::write(
            registry.path().join(format!("{file}.env")),
            format!("LOOP_NAME={name}\nLOOP_CWD=/home/alpha/dev/gamma\n"),
        )
        .expect("registry entry");
    }
    let chats = tempfile::tempdir().expect("temporary directory");
    let output = run_into(
        chats.path(),
        registry.path(),
        &fixtures.join("projects"),
        &["--all"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let lines = stdout_lines(&output);
    let fields: Vec<_> = lines.iter().map(|line| without_wall(line)).collect();
    assert_eq!(fields, [ALPHA, "loops=1"]);
    let told = String::from_utf8_lossy(&output.stderr);
    for name in ["\"javascript:alert(1)\"", "\"..\"", "\"a/b\"", "\"q?x\""] {
        assert!(
            told.contains(&format!("left out registered loop {name}")),
            "{told}"
        );
    }
    assert!(told.contains("and 4 registered names"), "{told}");
    let loops = std::fs::read_to_string(chats.path().join("index.html")).expect("loops index");
    let hrefs: Vec<&str> = loops
        .split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(href, _)| href))
        .collect();
    assert_eq!(
        hrefs,
        [
            "chat-export.css",
            "alpha&#x2f;index.html",
            "alpha&#x2f;latest.html"
        ]
    );
    assert!(!loops.contains("javascript"));
    let entries: Vec<String> = std::fs::read_dir(chats.path())
        .expect("chats")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries
            .iter()
            .all(|entry| !entry.contains(':') && !entry.contains('?')),
        "{entries:?}"
    );
}

/// ´test:integration:the-plan-dump-refuses-an-input-path-and-an-existing-file´
#[test]
fn the_plan_dump_refuses_an_input_path_and_an_existing_file() {
    let root = tempfile::tempdir().expect("temporary directory");
    let fixtures = fixtures();
    let projects = root.path().join("projects");
    let gamma = projects.join("-home-alpha-dev-gamma");
    std::fs::create_dir_all(&gamma).expect("project");
    let session = gamma.join("SESSION-ID-A.jsonl");
    std::fs::copy(
        fixtures.join("projects/-home-alpha-dev-gamma/SESSION-ID-A.jsonl"),
        &session,
    )
    .expect("session");
    let before = std::fs::read(&session).expect("session bytes");
    let existing = root.path().join("existing.jsonl");
    std::fs::write(&existing, "keep").expect("existing file");
    let chats = root.path().join("chats");
    for target in [&session, &existing] {
        let output = run_into(
            &chats,
            &fixtures.join("registry"),
            &projects,
            &[
                "--loop",
                "gamma",
                "--dump-plan",
                target.to_str().expect("UTF-8 path"),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("refused plan dump"),
            "{output:?}"
        );
    }
    assert_eq!(std::fs::read(&session).expect("session bytes"), before);
    assert_eq!(std::fs::read_to_string(&existing).expect("kept"), "keep");
}

/// ´test:integration:the-plan-dump-lists-every-page-of-the-loop´
#[test]
fn the_plan_dump_lists_every_page_of_the_loop() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let dump = directory.path().join("plan.jsonl");
    let output = run(&[
        "--loop",
        "gamma",
        "--dump-plan",
        dump.to_str().expect("UTF-8 path"),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(without_wall(&stdout_lines(&output)[0]), GAMMA);
    let text = std::fs::read_to_string(&dump).expect("plan dump");
    let pages: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON line"))
        .collect();
    let kinds: Vec<_> = pages
        .iter()
        .map(|page| page["kind"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "main", "main", "main", "main", "branch", "main", "agent", "agent", "agent"
        ]
    );
    let help = Command::new(BINARY)
        .arg("--help")
        .output()
        .expect("run superloop-chat-export");
    assert!(!String::from_utf8_lossy(&help.stdout).contains("dump-plan"));
}

/// ´test:integration:every-loop-reports-and-a-loop-without-sessions-says-so´
#[test]
fn every_loop_reports_and_a_loop_without_sessions_says_so() {
    let output = run(&["--all"]);
    assert!(output.status.success(), "{output:?}");
    let lines = stdout_lines(&output);
    let fields: Vec<_> = lines.iter().map(|line| without_wall(line)).collect();
    assert_eq!(fields.len(), 5, "{fields:?}");
    assert_eq!(fields[0], ALPHA);
    assert_eq!(fields[1], "loop=beta files=0 status=no-projects-directory");
    assert_eq!(fields[2], GAMMA);
    assert!(fields[3].starts_with("loop=hostile files=1 records=13 copies_dropped=0 malformed=0 "));
    assert_eq!(fields[4], "loops=4");
}

/// ´test:integration:an-unknown-or-invalid-selection-is-a-usage-error´
#[test]
fn an_unknown_or_invalid_selection_is_a_usage_error() {
    for (args, message) in [
        (&["--loop", "delta"][..], "unknown loop: delta"),
        (&[][..], "--loop"),
        (&["--all", "--loop", "alpha"][..], "cannot be used with"),
        (
            &["--all", "--max-block-bytes", "0"][..],
            "--max-block-bytes",
        ),
        (
            &["--all", "--max-block-bytes", "63"][..],
            "63 is below the least block limit, 64 bytes",
        ),
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// ´test:integration:an-unreadable-directory-fails-with-status-one´
#[test]
fn an_unreadable_directory_fails_with_status_one() {
    let missing = tempfile::tempdir().expect("temporary directory");
    let absent = missing.path().join("absent");
    let fixtures = fixtures();
    let (registry, projects) = (fixtures.join("registry"), fixtures.join("projects"));
    for (role, registry, projects) in [
        ("registry", absent.as_path(), projects.as_path()),
        ("projects", registry.as_path(), absent.as_path()),
    ] {
        let output = run_in(registry, projects, &["--all"]);
        assert_eq!(output.status.code(), Some(1), "{role}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            format!(
                "superloop-chat-export: unreadable {role} directory: {}\n",
                absent.display()
            )
        );
    }
}

/// ´test:integration:the-home-defaults-need-home´
#[test]
fn the_home_defaults_need_home() {
    let output = Command::new(BINARY)
        .args(["--all"])
        .env_remove("HOME")
        .output()
        .expect("run superloop-chat-export");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HOME is unset"));
}

/// A registry naming the loop `delta` and a projects folder holding its one
/// session of a prompt and a response.
fn delta(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let registry = root.join("registry");
    let projects = root.join("projects");
    let project = projects.join("-home-alpha-dev-delta");
    std::fs::create_dir_all(&registry).expect("registry");
    std::fs::create_dir_all(&project).expect("project");
    std::fs::write(
        registry.join("delta.env"),
        "LOOP_NAME=delta\nLOOP_CWD=/home/alpha/dev/delta\n",
    )
    .expect("registry entry");
    std::fs::write(
        project.join("SESSION-ID.jsonl"),
        concat!(
            r#"{"type":"user","uuid":"00000000-0000-4000-8000-000000000001","parentUuid":null,"message":{"content":"Hello."},"timestamp":"2026-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"assistant","uuid":"00000000-0000-4000-8000-000000000002","parentUuid":"00000000-0000-4000-8000-000000000001","message":{"id":"MESSAGE-ID-1","content":[{"type":"text","text":"Hello back."}]},"timestamp":"2026-01-01T00:00:01Z"}"#,
            "\n"
        ),
    )
    .expect("session");
    (registry, projects, project)
}

/// ´test:integration:links-and-pipes-in-a-project-are-named-counted-and-left-unread´
#[test]
fn links_and_pipes_in_a_project_are_named_counted_and_left_unread() {
    let root = tempfile::tempdir().expect("temporary directory");
    let (registry, projects, project) = delta(root.path());
    let gamma = fixtures().join("projects/-home-alpha-dev-gamma");
    std::os::unix::fs::symlink(
        gamma.join("SESSION-ID-A.jsonl"),
        project.join("LINKED.jsonl"),
    )
    .expect("linked transcript");
    nix::unistd::mkfifo(
        &project.join("PIPE.jsonl"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("pipe");
    std::fs::create_dir_all(project.join("SESSION-ID")).expect("session folder");
    std::os::unix::fs::symlink(
        gamma.join("SESSION-ID-A/subagents"),
        project.join("SESSION-ID/subagents"),
    )
    .expect("linked agents' folder");
    let output = run_into(
        &root.path().join("chats"),
        &registry,
        &projects,
        &["--loop", "delta"],
    );
    assert!(output.status.success(), "{output:?}");
    let line = &stdout_lines(&output)[0];
    for field in [" files=1 ", " skipped=3 ", " agents=0 "] {
        assert!(line.contains(field), "{line}");
    }
    let errors = String::from_utf8_lossy(&output.stderr);
    for name in ["LINKED.jsonl", "PIPE.jsonl", "SESSION-ID/subagents"] {
        assert!(errors.contains(name), "{errors}");
    }
}

/// ´test:integration:a-run-under-a-umask-of-0777-leaves-no-staging-folder´
#[test]
fn a_run_under_a_umask_of_0777_leaves_no_staging_folder() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("temporary directory");
    let (registry, projects, _) = delta(root.path());
    let chats = root.path().join("chats");
    std::fs::create_dir_all(chats.join("delta")).expect("output folders");
    let output = Command::new("sh")
        .arg("-c")
        .arg(r#"umask 0777 && exec "$0" "$@""#)
        .arg(BINARY)
        .arg("--registry")
        .arg(&registry)
        .arg("--projects")
        .arg(&projects)
        .arg("--chats")
        .arg(&chats)
        .args(["--loop", "delta"])
        .env_remove("HOME")
        .output()
        .expect("run superloop-chat-export under sh");
    assert!(output.status.success(), "{output:?}");
    let page = std::fs::metadata(chats.join("delta/p0001.html")).expect("page");
    assert_eq!(page.permissions().mode() & 0o777, 0, "the umask applied");
    for folder in [chats.clone(), chats.join("delta")] {
        let staged = std::fs::read_dir(&folder)
            .expect("folder")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".chat-export-")
            })
            .count();
        assert_eq!(staged, 0, "{}", folder.display());
    }
}
