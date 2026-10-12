//! End-to-end contract tests for `superloop-gate-submit` using only PATH-injected Git and
//! SSH executables. No test can address a real remote.

mod support;

use support::SerializedCommand as _;

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::process::{Command, Output};

use superloop_gate_submit::{
    MISSING_CLONE_PATH_DIAGNOSTIC, MISSING_REMOTE_RUNNER_DIAGNOSTIC, MISSING_RUST_ENV_DIAGNOSTIC,
    MISSING_SSH_ALIAS_DIAGNOSTIC,
};
use support::{Harness, argument};

const USAGE_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: invalid command-line arguments\n";
const DETACHED_HEAD_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: --push-remote requires an attached HEAD\n";
const SNAPSHOT_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: snapshot_failure: worktree snapshot failed\n";
const PUSH_DIAGNOSTIC: &[u8] = b"superloop-gate-submit: push_failure: snapshot push failed\n";
const REMOTE_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: remote_failure: remote verification failed\n";
const INTERNAL_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: internal_failure: unexpected internal failure\n";
const TARGET_SETUP_START: &str = "# superloop-gate-submit target-dir begin\n";
const TARGET_SETUP_END: &str = "# superloop-gate-submit target-dir end\n";

fn fixture(case: &str, suffix: &str) -> Vec<u8> {
    fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/expected")
            .join(format!("{case}.{suffix}")),
    )
    .expect("read shell-oracle fixture")
}

fn fixture_status(case: &str) -> i32 {
    std::str::from_utf8(&fixture(case, "status"))
        .expect("ASCII status fixture")
        .trim()
        .parse()
        .expect("decimal status fixture")
}

fn normalize_wall(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = bytes.to_vec();
    let prefix = b" wall=";
    let suffix = b"s verdict=";
    let Some(start) = normalized
        .windows(prefix.len())
        .rposition(|window| window == prefix)
        .map(|position| position + prefix.len())
    else {
        return normalized;
    };
    let Some(relative_end) = normalized[start..]
        .windows(suffix.len())
        .position(|window| window == suffix)
    else {
        return normalized;
    };
    normalized.splice(start..start + relative_end, b"N".iter().copied());
    normalized
}

fn normalize_profile_values(bytes: &[u8], replacements: &[(&str, &str)]) -> String {
    let mut normalized = String::from_utf8(bytes.to_vec()).expect("profile record is UTF-8");
    for (value, placeholder) in replacements {
        normalized = normalized.replace(value, placeholder);
    }
    normalized
}

fn assert_profile_rendering(example: &Harness, alternate: &Harness) {
    let example_argv = example.read("ssh-argv");
    let alternate_argv = alternate.read("ssh-argv");
    assert_eq!(
        example_argv,
        b"[\"sagofink-orchestration\",\"/srv/orchestration-pack/bin/run-report bash -s\"]\n"
    );
    assert_eq!(
        alternate_argv,
        b"[\"mondreiher-analysis\",\"/srv/alternate-pack/bin/report-wrapper bash -s\"]\n"
    );
    assert_eq!(
        normalize_profile_values(
            &example_argv,
            &[
                ("sagofink-orchestration", "$SSH_ALIAS"),
                (
                    "/srv/orchestration-pack/bin/run-report bash -s",
                    "$REMOTE_RUNNER",
                ),
            ],
        ),
        normalize_profile_values(
            &alternate_argv,
            &[
                ("mondreiher-analysis", "$SSH_ALIAS"),
                (
                    "/srv/alternate-pack/bin/report-wrapper bash -s",
                    "$REMOTE_RUNNER",
                ),
            ],
        )
    );

    let example_stdin = example.read("ssh-stdin");
    let alternate_stdin = alternate.read("ssh-stdin");
    assert!(example_stdin.starts_with(
        b"set -e; . /srv/orchestration-pack/env/rust.sh; cd /srv/orchestration-pack/worktree\n"
    ));
    assert!(alternate_stdin.starts_with(
        b"set -e; . /srv/alternate-pack/env/toolchain.sh; cd /srv/alternate-pack/checkout\n"
    ));
    assert_eq!(
        normalize_profile_values(
            &example_stdin,
            &[
                ("/srv/orchestration-pack/worktree", "$CLONE_PATH"),
                ("/srv/orchestration-pack/env/rust.sh", "$RUST_ENV"),
            ],
        ),
        normalize_profile_values(
            &alternate_stdin,
            &[
                ("/srv/alternate-pack/checkout", "$CLONE_PATH"),
                ("/srv/alternate-pack/env/toolchain.sh", "$RUST_ENV"),
            ],
        )
    );
}

fn run(command: &mut Command, arguments: &[&OsStr]) -> Output {
    command
        .args(arguments)
        .output_serialized()
        .expect("superloop-gate-submit subprocess runs")
}

fn report(name: &str, status: u8) -> Vec<u8> {
    let verdict = match status {
        0 => "ok",
        3 => "PUSH-FAILED",
        _ => "FAILED",
    };
    format!(
        "RUN-REPORT lane=verify-{name} exit={status} wall=Ns verdict={verdict} ref=refs/lanes/verify-{name}\n"
    )
    .into_bytes()
}

fn assert_final_report(stdout: &[u8], expected: &[u8]) {
    assert!(stdout.ends_with(expected), "owned report is not final");
    assert_eq!(
        stdout
            .windows(b"RUN-REPORT lane=verify-".len())
            .filter(|window| *window == b"RUN-REPORT lane=verify-")
            .count(),
        1,
        "owned report must occur exactly once"
    );
}

fn assert_stream(actual: &[u8], expected: &[u8], label: &str) {
    assert!(
        actual == expected,
        "{label}: actual:\n{}\nexpected:\n{}",
        String::from_utf8_lossy(actual),
        String::from_utf8_lossy(expected)
    );
}

fn assert_oracle_records(harness: &Harness, case: &str) {
    for role in ["git", "ssh-argv", "ssh-stdin"] {
        let actual = harness.read(role);
        let actual = if role == "ssh-stdin" {
            without_target_setup(&actual)
        } else {
            actual
        };
        let actual = if case == "committed-head-success" && role == "ssh-stdin" {
            normalize_probe(&actual, &probe_token(harness))
        } else {
            actual
        };
        assert_eq!(actual, fixture(case, role), "case {case} {role}");
    }
    assert_eq!(fixture(case, "temp-index"), b"clean\n");
    assert!(harness.temporary_index_is_clean());
}

fn probe_token(harness: &Harness) -> Vec<u8> {
    let script = harness.read("ssh-stdin");
    let prefix = b"# superloop-gate-submit probe token=";
    let tokens = script
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(prefix))
        .collect::<Vec<_>>();
    let [token] = tokens.as_slice() else {
        panic!("one committed probe token is required");
    };
    assert_eq!(token.len(), 32);
    token.to_vec()
}

fn normalize_probe(bytes: &[u8], token: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for part in bytes.split(|byte| *byte == b'\n') {
        if !result.is_empty() {
            result.push(b'\n');
        }
        result.extend_from_slice(
            String::from_utf8_lossy(part)
                .replace(
                    std::str::from_utf8(token).expect("ASCII token"),
                    "PROBE_TOKEN",
                )
                .as_bytes(),
        );
    }
    result
}

fn without_target_setup(bytes: &[u8]) -> Vec<u8> {
    let script = std::str::from_utf8(bytes).expect("remote script is UTF-8");
    let mut in_setup = false;
    let mut normalized = String::new();
    for line in script.split_inclusive('\n') {
        if line == TARGET_SETUP_START || line == "# gate sampler begin\n" {
            in_setup = true;
        } else if line == TARGET_SETUP_END || line == "# gate sampler end\n" {
            in_setup = false;
        } else if line != "locked_flag=\n"
            && line
                != "if git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then locked_flag=--locked; fi\n"
            && !in_setup
        {
            let mut line = line.replace("$locked_flag", "--locked").replace(
                "status=$?; samp_finish; final_head=",
                "status=$?; final_head=",
            );
            for (battery, heading) in [
                ("fmt", "fmt"),
                ("clippy", "clippy"),
                ("test", "test"),
                ("doc", "doc"),
                ("release-build", "release build"),
            ] {
                line = line.replace(
                    &format!("sec {battery}; time"),
                    &format!("echo '== {heading} =='; time"),
                );
            }
            normalized.push_str(&line);
        }
    }
    normalized.into_bytes()
}

#[derive(Clone, Copy)]
enum LockfileState {
    TrackedPresent,
    TrackedAbsent,
    UntrackedStale,
}

fn run_git(worktree: &std::path::Path, arguments: &[&str]) {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(worktree)
        .output_serialized()
        .expect("Git setup runs");
    assert!(
        output.status.success(),
        "Git setup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sampler_setup(script: &str) -> &str {
    script
        .split_once("# gate sampler begin\n")
        .expect("sampler begins")
        .1
        .split_once("# gate sampler end\n")
        .expect("sampler ends")
        .0
}

fn generated_cargo_invocations(state: LockfileState) -> Vec<u8> {
    let label = match state {
        LockfileState::TrackedPresent => "tracked-lockfile-present",
        LockfileState::TrackedAbsent => "tracked-lockfile-absent",
        LockfileState::UntrackedStale => "untracked-stale-lockfile",
    };
    let harness = Harness::new(label);
    harness.set_ssh_result(b"ok\n", 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("-A"),
            OsStr::new("-D"),
            OsStr::new("--release-build"),
            argument(harness.worktree()),
        ],
    );
    assert!(
        output.status.success(),
        "superloop-gate-submit run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let script = String::from_utf8(harness.read("ssh-stdin")).expect("remote script is UTF-8");
    let checkout = script
        .lines()
        .find(|line| line.starts_with("git checkout -qf --detach "))
        .expect("generated checkout precedes lockfile decision");
    let (_, clean) = checkout
        .split_once(" && ")
        .expect("generated checkout and clean are one step");
    let (_, decision_and_gates) = script
        .split_once("locked_flag=\n")
        .expect("lockfile setup precedes generated gates");
    let sampler = sampler_setup(&script);
    let gates = format!("{sampler}\n{clean}\nlocked_flag=\n{decision_and_gates}");

    fs::remove_dir_all(harness.worktree().join(".git")).expect("remove synthetic Git directory");
    run_git(harness.worktree(), &["init", "-q"]);
    fs::write(harness.worktree().join(".gitignore"), b"Cargo.lock\n")
        .expect("write lockfile ignore rule");
    run_git(harness.worktree(), &["add", ".gitignore"]);
    match state {
        LockfileState::TrackedPresent => {
            fs::write(harness.worktree().join("Cargo.lock"), b"tracked\n")
                .expect("write tracked lockfile");
            run_git(harness.worktree(), &["add", "-f", "Cargo.lock"]);
        }
        LockfileState::TrackedAbsent => {}
        LockfileState::UntrackedStale => {
            fs::write(harness.worktree().join("Cargo.lock"), b"stale\n")
                .expect("write stale untracked lockfile");
        }
    }

    let runtime_root = harness
        .worktree()
        .parent()
        .expect("worktree has a harness root");
    let tools = runtime_root.join("runtime-bin");
    fs::create_dir(&tools).expect("create runtime tool directory");
    let cargo = tools.join("cargo");
    support::write_executable(
        &cargo,
        b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CARGO_LOG\"\n",
        0o755,
    )
    .expect("write recording Cargo stub");

    let cargo_log = runtime_root.join("cargo.log");
    let mut search_path = vec![tools];
    if let Some(inherited) = std::env::var_os("PATH") {
        search_path.extend(std::env::split_paths(&inherited));
    }
    let output = Command::new("bash")
        .args(["--noprofile", "--norc"])
        .env_remove("BASH_ENV")
        .arg("-c")
        .arg(gates)
        .current_dir(harness.worktree())
        .env(
            "PATH",
            std::env::join_paths(search_path).expect("join runtime search path"),
        )
        .env("CARGO_LOG", &cargo_log)
        .output_serialized()
        .expect("generated gates run");
    assert!(
        output.status.success(),
        "generated gates failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        harness.worktree().join("Cargo.lock").exists(),
        matches!(state, LockfileState::TrackedPresent),
        "only a tracked lockfile survives generated cleanup"
    );
    assert_battery_sampler_evidence(&output.stdout);
    fs::read(cargo_log).expect("read recorded Cargo invocations")
}

fn assert_battery_sampler_evidence(stdout: &[u8]) {
    let evidence = std::str::from_utf8(stdout).expect("sampler evidence");
    for battery in ["gate", "fmt", "clippy", "test", "doc", "release-build"] {
        assert_eq!(
            evidence
                .matches(&format!("SAMPLE {battery} start "))
                .count(),
            1
        );
        assert_eq!(
            evidence.matches(&format!("SAMPLE {battery} end ")).count(),
            1
        );
        assert_eq!(
            evidence.matches(&format!("DELTA {battery} wall=")).count(),
            1
        );
    }
}

/// ´test:integration:default-success-matches-shell-report-and-object-flow´
#[test]
fn default_success_matches_shell_report_and_object_flow() {
    let harness = Harness::new("oracle-default");
    harness.set_ssh_result(
        b"server evidence\nRUN-REPORT exit=0 wall=1s rootfs_tmp_left=1T workspace_left=2T\n",
        0,
    );
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha,beta"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(fixture_status("default-success"))
    );
    assert_eq!(
        normalize_wall(&output.stdout),
        fixture("default-success", "stdout")
    );
    assert_eq!(output.stderr, fixture("default-success", "stderr"));
    assert_oracle_records(&harness, "default-success");
}

/// ´test:integration:committed-head-success-matches-aligned-object-flow´
#[test]
fn committed_head_success_matches_aligned_object_flow() {
    let harness = Harness::new("committed-head-success");
    harness.set_ssh_result(
        b"server evidence\nCHECKED-OUT object=1111111111111111111111111111111111111111 ref=refs/heads/lane/R token=PROBE_TOKEN\nRUN-REPORT exit=0 wall=1s rootfs_tmp_left=1T workspace_left=2T\n",
        0,
    );
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha,beta"),
            OsStr::new("--committed-head"),
            OsStr::new("refs/heads/lane/R"),
            argument(harness.worktree()),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(fixture_status("committed-head-success"))
    );
    assert_eq!(
        normalize_probe(&normalize_wall(&output.stdout), &probe_token(&harness)),
        fixture("committed-head-success", "stdout")
    );
    assert_eq!(output.stderr, fixture("committed-head-success", "stderr"));
    assert_oracle_records(&harness, "committed-head-success");
    assert!(
        !harness
            .read("git")
            .windows(b"commit-tree".len())
            .any(|part| part == b"commit-tree")
    );
    assert!(
        !harness
            .read("git")
            .windows(b"$TMP_INDEX".len())
            .any(|part| part == b"$TMP_INDEX")
    );
}

/// ´test:integration:committed-head-seed-check-precedes-gate-and-names-failure´
#[test]
fn committed_head_seed_check_precedes_gate_and_names_failure() {
    let seed = "a".repeat(40);
    for (label, foreign, expected_status, expected_object) in [
        ("descendant", false, 0, "1".repeat(40)),
        ("foreign", true, 1, "2".repeat(40)),
    ] {
        let harness = Harness::new(label);
        let mut command = harness.remote_execution_command();
        command.env("ORACLE_GIT_HEAD_OBJECT", &expected_object);
        if foreign {
            command.env("ORACLE_SSH_REMOTE_SEED_FOREIGN", "1");
        }
        let output = run(
            &mut command,
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
                OsStr::new("--seed-object"),
                OsStr::new(&seed),
                argument(harness.worktree()),
            ],
        );
        assert_eq!(output.status.code(), Some(expected_status));
        let stdout = String::from_utf8(output.stdout).expect("report text");
        let token = String::from_utf8(probe_token(&harness)).expect("probe token");
        let result = if foreign { "foreign" } else { "descendant" };
        assert!(stdout.contains(&format!(
            "SEED-ANCESTRY object={expected_object} seed={seed} token={token} result={result}"
        )));
        assert!(stdout.contains(&format!(
            "CHECKED-OUT object={expected_object} ref=refs/heads/lane/R token={token}"
        )));
        assert!(stdout.lines().any(|line| line.starts_with("RUN-REPORT ")
            && line.contains(&format!("object={expected_object}"))));
        if foreign {
            assert!(stdout.contains(
                "superloop-gate-submit: seed_ancestry: checked-out lane commit does not descend from seed"
            ));
            assert!(stdout.contains("verdict=FAILED"));
            assert!(!stdout.contains("== fmt =="));
        } else {
            assert!(!stdout.contains("superloop-gate-submit: seed_ancestry:"));
            assert!(stdout.contains("verdict=ok"));
        }
        let script = String::from_utf8(harness.read("ssh-stdin")).expect("script text");
        assert!(script.contains(&format!(
            "git merge-base --is-ancestor '{seed}' \"$checked_out\""
        )));
        assert!(
            script
                .find("git merge-base --is-ancestor")
                .expect("seed check")
                < script.find("sec fmt; time").expect("fmt gate")
        );
    }
    for (label, variable) in [
        ("missing", "ORACLE_SSH_SUPPRESS_SEED_LINE"),
        ("unbound", "ORACLE_SSH_UNBIND_SEED_LINE"),
        ("mismatch", "ORACLE_SSH_MISMATCH_SEED_LINE"),
        ("server_error", "ORACLE_SSH_REMOTE_SEED_ERROR"),
        ("server_missing", "ORACLE_SSH_SEED_RESULT_MISSING"),
        ("malformed", "ORACLE_SSH_DUPLICATE_SEED_LINE"),
    ] {
        let harness = Harness::new(label);
        let mut command = harness.remote_execution_command();
        command.env(variable, "1");
        let output = run(
            &mut command,
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
                OsStr::new("--seed-object"),
                OsStr::new(&seed),
                argument(harness.worktree()),
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8(output.stdout).expect("report text");
        assert!(stdout.contains(&format!("superloop-gate-submit: seed_ancestry_{label}:")));
        assert!(!stdout.contains("superloop-gate-submit: seed_ancestry:"));
        assert!(stdout.contains("superloop-gate-submit: seed_result_failure:"));
        assert!(stdout.contains("verdict=FAILED"));
        assert!(stdout.contains("CHECKED-OUT object=1111111111111111111111111111111111111111"));
    }
}

/// ´test:integration:committed-head-seed-input-refuses-before-remote-run´
#[test]
fn committed_head_seed_input_refuses_before_remote_run() {
    let seed = "a".repeat(40);
    for (label, option_words, committed) in [
        (
            "short",
            vec!["--seed-object".to_owned(), "a".to_owned()],
            true,
        ),
        (
            "nonhex",
            vec!["--seed-object".to_owned(), "g".repeat(40)],
            true,
        ),
        (
            "repeated",
            vec![
                "--seed-object".to_owned(),
                seed.clone(),
                "--seed-object".to_owned(),
                seed.clone(),
            ],
            true,
        ),
        (
            "without-head",
            vec!["--seed-object".to_owned(), seed.clone()],
            false,
        ),
        ("attached", vec![format!("--seed-object={seed}")], true),
        ("missing-value", vec!["--seed-object".to_owned()], true),
    ] {
        let invalid = Harness::new(label);
        let mut words = vec!["-p".to_owned(), "alpha".to_owned()];
        if committed {
            words.extend([
                "--committed-head".to_owned(),
                "refs/heads/lane/R".to_owned(),
            ]);
        }
        words.extend(option_words);
        let mut arguments = words.iter().map(OsStr::new).collect::<Vec<_>>();
        arguments.push(argument(invalid.worktree()));
        let invalid_output = run(&mut invalid.command(), &arguments);
        assert_eq!(invalid_output.status.code(), Some(2), "{label}");
        assert_eq!(invalid.read("git"), [] as [u8; 0], "{label}");
        assert_eq!(invalid.read("ssh-argv"), [] as [u8; 0], "{label}");
    }
    let foreign = Harness::new("foreign-seed");
    let mut foreign_command = foreign.command();
    foreign_command.env("ORACLE_GIT_SEED_FOREIGN", "1");
    let foreign_output = run(
        &mut foreign_command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--committed-head"),
            OsStr::new("refs/heads/lane/R"),
            OsStr::new("--seed-object"),
            OsStr::new(&seed),
            argument(foreign.worktree()),
        ],
    );
    assert_eq!(foreign_output.status.code(), Some(1));
    assert!(
        foreign_output
            .stdout
            .windows(b"superloop-gate-submit: seed_ancestry:".len())
            .any(|part| part == b"superloop-gate-submit: seed_ancestry:")
    );
    assert_eq!(foreign.read("ssh-argv"), [] as [u8; 0]);
    assert!(
        !foreign
            .read("git")
            .windows(b"\"push\"".len())
            .any(|part| part == b"\"push\"")
    );
}

/// ´test:integration:committed-head-refuses-dirty-and-mismatched-checkouts´
#[test]
fn committed_head_refuses_dirty_and_mismatched_checkouts() {
    for (variable, value, diagnostic) in [
        ("ORACLE_GIT_DIRTY", "yes", "dirty_checkout"),
        (
            "ORACLE_GIT_HEAD_REF",
            "refs/heads/lane/other",
            "head_mismatch",
        ),
    ] {
        let harness = Harness::new(diagnostic);
        let mut command = harness.command();
        command.env(variable, value);
        let output = run(
            &mut command,
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
                argument(harness.worktree()),
            ],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(
            output
                .stdout
                .windows(diagnostic.len())
                .any(|part| part == diagnostic.as_bytes())
        );
        assert_eq!(harness.read("ssh-argv"), [] as [u8; 0]);
        assert!(
            !harness
                .read("git")
                .windows(b"\"push\"".len())
                .any(|part| part == b"\"push\"")
        );
    }
}

/// ´test:integration:committed-head-refuses-missing-or-mismatched-server-object´
#[test]
fn committed_head_refuses_missing_or_mismatched_server_object() {
    for (label, output, reason) in [
        (
            "missing",
            b"server evidence\n".as_slice(),
            "checked_out_missing",
        ),
        (
            "mismatch",
            b"CHECKED-OUT object=2222222222222222222222222222222222222222 ref=refs/heads/lane/R token=PROBE_TOKEN\n"
                .as_slice(),
            "checked_out_mismatch",
        ),
    ] {
        let harness = Harness::new(label);
        harness.set_ssh_result(output, 0);
        let result = run(
            &mut harness.command(),
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
                argument(harness.worktree()),
            ],
        );
        assert_eq!(result.status.code(), Some(1));
        assert!(
            result
                .stdout
                .windows(reason.len())
                .any(|part| part == reason.as_bytes())
        );
        assert!(
            result
                .stdout
                .windows(b"verdict=FAILED".len())
                .any(|part| part == b"verdict=FAILED")
        );
        assert!(normalize_wall(&result.stdout).ends_with(&report("worktree", 1)));
    }
}

/// ´test:integration:committed-head-refuses-gate-authored-marker-on-failure´
#[test]
fn committed_head_refuses_gate_authored_marker_on_failure() {
    let harness = Harness::new("gate-authored-marker");
    harness.set_ssh_result(
        b"gate says CHECKED-OUT\nCHECKED-OUT object=1111111111111111111111111111111111111111 ref=refs/heads/lane/R\nCHECKED-OUT object=1111111111111111111111111111111111111111 ref=refs/heads/lane/R token=PROBE_TOKEN\n",
        1,
    );
    let result = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--committed-head"),
            OsStr::new("refs/heads/lane/R"),
            argument(harness.worktree()),
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(
        result
            .stdout
            .windows(b"checked_out_unbound".len())
            .any(|part| part == b"checked_out_unbound")
    );
    let output = String::from_utf8_lossy(&result.stdout);
    let report = output.lines().last().expect("final report");
    assert!(report.contains("verdict=FAILED"));
    assert!(!report.contains(" object="));
}

/// ´test:integration:committed-head-refuses-successful-gate-that-moves-head´
#[test]
fn committed_head_refuses_successful_gate_that_moves_head() {
    for (remote_status, expected_status) in [(1, 1), (2, 2)] {
        let harness = Harness::new("gate-moved-head");
        harness.set_ssh_result(
            b"gate moved HEAD and returned success\nCHECKED-OUT-DRIFT token=PROBE_TOKEN\nCHECKED-OUT object=2222222222222222222222222222222222222222 ref=refs/heads/lane/R token=PROBE_TOKEN\n",
            remote_status,
        );
        let result = run(
            &mut harness.command(),
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
                argument(harness.worktree()),
            ],
        );
        assert_eq!(result.status.code(), Some(expected_status));
        assert!(
            result
                .stdout
                .windows(b"checked_out_drift".len())
                .any(|part| part == b"checked_out_drift")
        );
        assert!(
            result
                .stdout
                .windows(b"verdict=FAILED".len())
                .any(|part| part == b"verdict=FAILED")
        );
        let script = harness.read("ssh-stdin");
        assert!(
            script
                .windows(b"final_head=$(git rev-parse HEAD".len())
                .any(|part| part == b"final_head=$(git rev-parse HEAD")
        );
        assert!(
            script
                .windows(b"final_status=$(git status --porcelain".len())
                .any(|part| part == b"final_status=$(git status --porcelain")
        );
    }
}

/// ´test:integration:committed-head-exit-probe-observes-gate-head-move´
#[test]
fn committed_head_exit_probe_observes_gate_head_move() {
    let harness = Harness::new("real-head-move");
    harness.set_ssh_result(
        b"CHECKED-OUT object=1111111111111111111111111111111111111111 ref=refs/heads/lane/R token=PROBE_TOKEN\n",
        0,
    );
    let result = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--committed-head"),
            OsStr::new("refs/heads/lane/R"),
            argument(harness.worktree()),
        ],
    );
    assert!(result.status.success());
    let script = String::from_utf8(harness.read("ssh-stdin")).expect("script text");
    let sampler = sampler_setup(&script);
    let probe = script
        .lines()
        .find(|line| line.starts_with("checked_out=$(git rev-parse HEAD)"))
        .expect("exit probe");
    let repository = harness
        .worktree()
        .parent()
        .expect("fixture root")
        .join("probe-repo");
    fs::create_dir(&repository).expect("probe repository");
    let git = |arguments: &[&str]| {
        let output = Command::new("/usr/bin/git")
            .args(arguments)
            .current_dir(&repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Lane Worker")
            .env("GIT_AUTHOR_EMAIL", "worker@invalid")
            .env("GIT_COMMITTER_NAME", "Lane Worker")
            .env("GIT_COMMITTER_EMAIL", "worker@invalid")
            .output()
            .expect("local fixture Git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git output")
            .trim()
            .to_owned()
    };
    git(&["init", "-q"]);
    git(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "first",
    ]);
    let first = git(&["rev-parse", "HEAD"]);
    git(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "second",
    ]);
    let second = git(&["rev-parse", "HEAD"]);
    git(&["reset", "--hard", &first]);
    let shell = format!("set -e\n{sampler}\n{probe}\ngit checkout -q --detach {second}\n");
    let output = Command::new("/bin/bash")
        .args(["--noprofile", "--norc"])
        .env_remove("BASH_ENV")
        .args(["-c", &shell])
        .current_dir(&repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("gate shell");
    assert_gate_exit_probe_reports_drift(&output, &second);
    git(&["reset", "--hard", &first]);
    let dirty_shell = format!("set -e\n{sampler}\n{probe}\nprintf dirty > gate-output\n");
    let dirty = Command::new("/bin/bash")
        .args(["--noprofile", "--norc"])
        .env_remove("BASH_ENV")
        .args(["-c", &dirty_shell])
        .current_dir(&repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("dirty gate shell");
    assert_gate_exit_probe_reports_drift(&dirty, &first);
}

fn assert_gate_exit_probe_reports_drift(output: &std::process::Output, head: &str) {
    assert_eq!(output.status.code(), Some(1));
    let evidence = std::str::from_utf8(&output.stdout).expect("probe evidence");
    assert!(evidence.contains("CHECKED-OUT-DRIFT token="));
    assert!(evidence.contains(&format!("CHECKED-OUT object={head}")));
}

/// ´test:integration:second-profile-changes-only-profile-rendering´
#[test]
fn second_profile_changes_only_profile_rendering() {
    let example = Harness::new("example-profile");
    example.set_ssh_result(b"profile evidence\n", 0);
    let example_output = run(
        &mut example.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha,beta"),
            OsStr::new("-n"),
            OsStr::new("profile"),
            argument(example.worktree()),
        ],
    );

    let alternate = Harness::new("alternate-profile");
    alternate.set_ssh_result(b"profile evidence\n", 0);
    let mut alternate_command = alternate.command();
    alternate_command
        .env("LANE_VERIFY_SSH", "mondreiher-analysis")
        .env("LANE_VERIFY_CLONE", "/srv/alternate-pack/checkout")
        .env(
            "LANE_VERIFY_REMOTE_RUNNER",
            "/srv/alternate-pack/bin/report-wrapper bash -s",
        )
        .env(
            "LANE_VERIFY_RUST_ENV",
            "/srv/alternate-pack/env/toolchain.sh",
        );
    let alternate_output = run(
        &mut alternate_command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha,beta"),
            OsStr::new("-n"),
            OsStr::new("profile"),
            argument(alternate.worktree()),
        ],
    );

    assert_eq!(example_output.status.code(), Some(0));
    assert_eq!(alternate_output.status.code(), example_output.status.code());
    assert_eq!(
        normalize_wall(&alternate_output.stdout),
        normalize_wall(&example_output.stdout)
    );
    assert_final_report(
        &normalize_wall(&alternate_output.stdout),
        &report("profile", 0),
    );
    assert_eq!(alternate_output.stderr, example_output.stderr);
    assert_eq!(alternate.read("git"), example.read("git"));

    assert_profile_rendering(&example, &alternate);
}

/// ´test:integration:missing-profile-fields-fail-before-transport-with-named-usage´
#[test]
fn missing_profile_fields_fail_before_transport_with_named_usage() {
    for (variable, diagnostic) in [
        ("LANE_VERIFY_SSH", MISSING_SSH_ALIAS_DIAGNOSTIC),
        ("LANE_VERIFY_CLONE", MISSING_CLONE_PATH_DIAGNOSTIC),
        (
            "LANE_VERIFY_REMOTE_RUNNER",
            MISSING_REMOTE_RUNNER_DIAGNOSTIC,
        ),
        ("LANE_VERIFY_RUST_ENV", MISSING_RUST_ENV_DIAGNOSTIC),
    ] {
        let harness = Harness::new(variable);
        let output = harness
            .command()
            .env_remove(variable)
            .args([
                OsStr::new("-p"),
                OsStr::new("alpha"),
                argument(harness.worktree()),
            ])
            .output_serialized()
            .expect("missing-profile subprocess runs");
        let mut expected = diagnostic.to_vec();
        expected.extend(report("unknown", 2));
        assert_eq!(output.status.code(), Some(2), "missing {variable}");
        assert_eq!(
            normalize_wall(&output.stdout),
            expected,
            "missing {variable}"
        );
        assert_eq!(output.stderr, [] as [u8; 0], "missing {variable}");
        assert_eq!(harness.read("git"), [] as [u8; 0], "missing {variable}");
        assert_eq!(
            harness.read("ssh-argv"),
            [] as [u8; 0],
            "missing {variable}"
        );
    }

    assert_eq!(fixture_status("usage-missing-profile"), 2);
    assert_eq!(
        fixture("usage-missing-profile", "stderr"),
        b"superloop-gate-submit: usage_error: LANE_VERIFY_SSH is required\n"
    );
    assert_eq!(fixture("usage-missing-profile", "git"), [] as [u8; 0]);
    assert_eq!(fixture("usage-missing-profile", "ssh-argv"), [] as [u8; 0]);
}

/// ´test:integration:options-and-environment-overrides-match-shell´
#[test]
fn options_and_environment_overrides_match_shell() {
    let harness = Harness::new("oracle-overrides");
    harness.set_ssh_result(
        b"remote failed\nRUN-REPORT exit=1 wall=2s rootfs_tmp_left=1T workspace_left=2T\n",
        1,
    );
    let mut command = harness.command();
    command
        .env("LANE_VERIFY_SSH", "mondreiher-analysis")
        .env("LANE_VERIFY_REMOTE", "hub-override")
        .env("LANE_VERIFY_CLONE", "/srv/example/worktree")
        .env(
            "LANE_VERIFY_REMOTE_RUNNER",
            "/srv/example/bin/run-report bash -s",
        )
        .env("LANE_VERIFY_RUST_ENV", "/srv/example/env/rust.sh");
    let output = run(
        &mut command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("-n"),
            OsStr::new("named"),
            OsStr::new("-A"),
            OsStr::new("-D"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(fixture_status("overrides-failure"))
    );
    assert_eq!(
        normalize_wall(&output.stdout),
        fixture("overrides-failure", "stdout")
    );
    assert_eq!(output.stderr, fixture("overrides-failure", "stderr"));
    assert_oracle_records(&harness, "overrides-failure");
}

/// ´test:integration:tail-cap-matches-shell-last-sixty-lines´
#[test]
fn tail_cap_matches_shell_last_sixty_lines() {
    let harness = Harness::new("oracle-tail");
    let mut evidence = String::new();
    for number in 1..=70 {
        writeln!(&mut evidence, "remote-line-{number:02}")
            .expect("writing to a String cannot fail");
    }
    harness.set_ssh_result(evidence.as_bytes(), 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("-n"),
            OsStr::new("tail"),
            argument(harness.worktree()),
        ],
    );

    assert_stream(
        &normalize_wall(&output.stdout),
        &fixture("tail-cap", "stdout"),
        "tail-cap stdout",
    );
    assert_stream(
        &output.stderr,
        &fixture("tail-cap", "stderr"),
        "tail-cap stderr",
    );
    assert_oracle_records(&harness, "tail-cap");
}

/// ´test:integration:usage-error-matrix-returns-two-with-governed-report´
#[test]
fn usage_error_matrix_returns_two_with_governed_report() {
    let harness = Harness::new("usage-matrix");
    let worktree = argument(harness.worktree()).to_os_string();
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec!["-p".into(), "alpha".into()],
        vec![worktree.clone()],
        vec!["-p".into(), "".into(), worktree.clone()],
        vec![
            "-p".into(),
            "alpha".into(),
            worktree.clone(),
            "extra".into(),
        ],
        vec!["-p".into(), "alpha".into(), "-Z".into(), worktree.clone()],
        vec![
            "-p".into(),
            "alpha".into(),
            "--unknown".into(),
            worktree.clone(),
        ],
        vec!["-p".into()],
        vec!["-p".into(), "alpha".into(), "-n".into()],
        vec!["-p".into(), "alpha,,beta".into(), worktree.clone()],
        vec![
            "-p".into(),
            "alpha".into(),
            "-n".into(),
            "bad name".into(),
            worktree,
        ],
    ];

    for arguments in cases {
        let output = harness
            .command()
            .args(&arguments)
            .output_serialized()
            .expect("usage subprocess runs");
        let mut expected = USAGE_DIAGNOSTIC.to_vec();
        expected.extend(report("unknown", 2));
        assert_eq!(output.status.code(), Some(2), "arguments {arguments:?}");
        assert_eq!(
            normalize_wall(&output.stdout),
            expected,
            "arguments {arguments:?}"
        );
        assert_eq!(output.stderr, [] as [u8; 0], "arguments {arguments:?}");
    }
    assert_eq!(harness.read("git"), [] as [u8; 0]);
    assert_eq!(harness.read("ssh-argv"), [] as [u8; 0]);
}

/// ´test:integration:shell-usage-fixtures-name-the-governed-divergence´
#[test]
fn shell_usage_fixtures_name_the_governed_divergence() {
    for case in [
        "usage-no-packages",
        "usage-extra-argument",
        "usage-unknown-option",
    ] {
        assert_eq!(fixture_status(case), 2);
        assert_eq!(fixture(case, "stdout"), [] as [u8; 0]);
        assert!(!fixture(case, "stderr").starts_with(USAGE_DIAGNOSTIC));
    }
    assert_eq!(fixture_status("unsafe-name"), 0);
    assert!(
        fixture("unsafe-name", "stdout")
            .windows(b"lane=verify-bad name".len())
            .any(|window| window == b"lane=verify-bad name")
    );
}

/// ´test:integration:push-remote-from-detached-head-is-a-usage-error-before-verification´
#[test]
fn push_remote_from_detached_head_is_a_usage_error_before_verification() {
    let harness = Harness::new("detached-push");
    let output = harness
        .command()
        .env("ORACLE_GIT_DETACHED", "1")
        .args([
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--push-remote"),
            OsStr::new("reachable"),
            argument(harness.worktree()),
        ])
        .output_serialized()
        .expect("detached-HEAD subprocess runs");

    let mut expected = DETACHED_HEAD_DIAGNOSTIC.to_vec();
    expected.extend(report("unknown", 2));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(normalize_wall(&output.stdout), expected);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(harness.read("ssh-argv"), [] as [u8; 0]);
    assert_eq!(
        String::from_utf8(harness.read("git")).expect("Git record is UTF-8"),
        concat!(
            "{\"argv\":[\"-C\",\"$WORKTREE\",\"symbolic-ref\",\"--quiet\",\"--short\",\"HEAD\"],",
            "\"git_index\":null,\"index_matches\":null}\n"
        )
    );
}

/// ´test:integration:failed-gates-structurally-skip-every-branch-push´
#[test]
fn failed_gates_structurally_skip_every_branch_push() {
    let harness = Harness::new("failed-gates-skip-push");
    harness.set_ssh_result(b"gate failed\n", 1);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--push-remote"),
            OsStr::new("first"),
            OsStr::new("--push-remote"),
            OsStr::new("second"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    assert_final_report(&normalize_wall(&output.stdout), &report("worktree", 1));
    let git = String::from_utf8(harness.read("git")).expect("Git record is UTF-8");
    assert!(!git.contains("\"argv\":[\"push\",\"first\""));
    assert!(!git.contains("\"argv\":[\"push\",\"second\""));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PUSH-REPORT"));
}

/// ´test:integration:green-gates-push-all-remotes-in-order-despite-partial-failure´
#[test]
fn green_gates_push_all_remotes_in_order_despite_partial_failure() {
    let harness = Harness::new("partial-push-failure");
    harness.set_ssh_result(b"all gates green\n", 0);
    let output = harness
        .command()
        .env("ORACLE_GIT_FAIL_REMOTE", "middle")
        .args([
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--push-remote"),
            OsStr::new("first"),
            OsStr::new("--push-remote"),
            OsStr::new("middle"),
            OsStr::new("--push-remote"),
            OsStr::new("last"),
            argument(harness.worktree()),
        ])
        .output_serialized()
        .expect("partial branch-push subprocess runs");

    assert_eq!(output.status.code(), Some(3));
    let normalized = normalize_wall(&output.stdout);
    assert_final_report(&normalized, &report("worktree", 3));
    let stdout = String::from_utf8(normalized).expect("published output is UTF-8");
    assert_push_report(&stdout, "first", "ok");
    assert_push_report(&stdout, "middle", "FAILED");
    assert_push_report(&stdout, "last", "ok");
    let first_report = stdout.find("remote=first").expect("first report exists");
    let middle_report = stdout.find("remote=middle").expect("middle report exists");
    let last_report = stdout.find("remote=last").expect("last report exists");
    assert!(first_report < middle_report && middle_report < last_report);

    let git = String::from_utf8(harness.read("git")).expect("Git record is UTF-8");
    let first_push = git
        .find("\"argv\":[\"push\",\"first\",\"HEAD:lane/vfix2\"]")
        .expect("first push exists");
    let middle_push = git
        .find("\"argv\":[\"push\",\"middle\",\"HEAD:lane/vfix2\"]")
        .expect("middle push exists");
    let last_push = git
        .find("\"argv\":[\"push\",\"last\",\"HEAD:lane/vfix2\"]")
        .expect("last push exists");
    assert!(first_push < middle_push && middle_push < last_push);
}

/// ´test:integration:green-gates-and-green-pushes-keep-success-status´
#[test]
fn green_gates_and_green_pushes_keep_success_status() {
    let harness = Harness::new("green-pushes");
    harness.set_ssh_result(b"all gates green\n", 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("--push-remote"),
            OsStr::new("first"),
            OsStr::new("--push-remote"),
            OsStr::new("second"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    let normalized = normalize_wall(&output.stdout);
    assert_final_report(&normalized, &report("worktree", 0));
    let stdout = String::from_utf8(normalized).expect("published output is UTF-8");
    assert_push_report(&stdout, "first", "ok");
    assert_push_report(&stdout, "second", "ok");
}

fn assert_push_report(stdout: &str, remote: &str, verdict: &str) {
    let prefix = format!("PUSH-REPORT remote={remote} wall=");
    let report = stdout
        .lines()
        .find(|line| line.starts_with(&prefix))
        .expect("push report exists");
    assert!(report.ends_with(&format!("s verdict={verdict}")));
}

/// ´test:integration:snapshot-failure-cleans-temp-index-and-replaces-shell-diagnostic´
#[test]
fn snapshot_failure_cleans_temp_index_and_replaces_shell_diagnostic() {
    let harness = Harness::new("snapshot-failure");
    let mut command = harness.command();
    command.env("ORACLE_GIT_FAIL", "add");
    let output = run(
        &mut command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    let mut expected = b"superloop-gate-submit: git add -A . failed\ngit-add-failed\n".to_vec();
    expected.extend(SNAPSHOT_DIAGNOSTIC);
    expected.extend(report("worktree", 1));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(normalize_wall(&output.stdout), expected);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(harness.read("git"), fixture("snapshot-add-failure", "git"));
    assert!(harness.temporary_index_is_clean());
    assert_eq!(fixture("snapshot-add-failure", "temp-index"), b"clean\n");
    assert_eq!(fixture("snapshot-add-failure", "stdout"), [] as [u8; 0]);
}

/// ´test:integration:push-failure-cleans-temp-index-and-replaces-shell-diagnostic´
#[test]
fn push_failure_cleans_temp_index_and_replaces_shell_diagnostic() {
    let harness = Harness::new("push-failure");
    let mut command = harness.command();
    command.env("ORACLE_GIT_FAIL", "push");
    let output = run(
        &mut command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    let mut expected = b"superloop-gate-submit: git push failed\ngit-push-failed\n".to_vec();
    expected.extend(PUSH_DIAGNOSTIC);
    expected.extend(report("worktree", 1));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(normalize_wall(&output.stdout), expected);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(harness.read("git"), fixture("push-failure", "git"));
    assert!(harness.temporary_index_is_clean());
    assert_eq!(fixture("push-failure", "temp-index"), b"clean\n");
}

/// ´test:integration:real-index-content-and-mtime-are-unchanged´
#[test]
fn real_index_content_and_mtime_are_unchanged() {
    let harness = Harness::new("index-isolation");
    harness.set_ssh_result(b"verified\n", 0);
    let index = harness.real_index();
    let before_bytes = fs::read(&index).expect("read real index before run");
    let before_mtime = fs::metadata(&index)
        .expect("inspect real index before run")
        .modified()
        .expect("real index has mtime");

    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );
    assert!(output.status.success());
    assert_eq!(
        fs::read(&index).expect("read real index after run"),
        before_bytes
    );
    assert_eq!(
        fs::metadata(&index)
            .expect("inspect real index after run")
            .modified()
            .expect("real index has mtime"),
        before_mtime
    );
    assert!(harness.temporary_index_is_clean());
}

/// ´test:integration:each-environment-override-is-independent´
#[test]
fn each_environment_override_is_independent() {
    for (variable, value, expected) in [
        ("LANE_VERIFY_SSH", "only-ssh", "only-ssh"),
        ("LANE_VERIFY_REMOTE", "only-hub", "only-hub"),
        ("LANE_VERIFY_CLONE", "/only/clone", "/only/clone"),
        (
            "LANE_VERIFY_REMOTE_RUNNER",
            "/only/runner bash -s",
            "/only/runner bash -s",
        ),
        (
            "LANE_VERIFY_RUST_ENV",
            "/only/rust-env.sh",
            "/only/rust-env.sh",
        ),
        (
            "LANE_VERIFY_TARGET_DIR",
            "/only/operator-target",
            "export CARGO_TARGET_DIR='/only/operator-target'",
        ),
    ] {
        let harness = Harness::new(variable);
        harness.set_ssh_result(b"ok\n", 0);
        let mut command = harness.command();
        command.env(variable, value);
        let output = run(
            &mut command,
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                argument(harness.worktree()),
            ],
        );
        assert!(output.status.success());
        let records = [
            harness.read("git"),
            harness.read("ssh-argv"),
            harness.read("ssh-stdin"),
        ]
        .concat();
        assert!(
            String::from_utf8_lossy(&records).contains(expected),
            "{variable} override was not conveyed"
        );
    }
}

/// ´test:integration:default-target-dir-hashes-the-canonical-checkout-path´
#[test]
fn default_target_dir_hashes_the_canonical_checkout_path() {
    let harness = Harness::new("target-default");
    harness.set_ssh_result(b"ok\n", 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    assert!(output.status.success());
    let script = String::from_utf8(harness.read("ssh-stdin")).expect("remote script is UTF-8");
    assert!(script.contains("checkout_path=$(pwd -P)\n"));
    assert!(script.contains("checkout_digest=$(printf '%s' \"$checkout_path\" | sha256sum)\n"));
    assert!(script.contains(
        "export CARGO_TARGET_DIR=\"$target_root/superloop-gate-submit-${checkout_digest:0:16}\"\n"
    ));
}

/// ´test:integration:explicit-target-dir-override-wins-without-derivation´
#[test]
fn explicit_target_dir_override_wins_without_derivation() {
    let harness = Harness::new("target-override");
    harness.set_ssh_result(b"ok\n", 0);
    let mut command = harness.command();
    command.env("LANE_VERIFY_TARGET_DIR", "/srv/operator/target");
    let output = run(
        &mut command,
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    assert!(output.status.success());
    let script = String::from_utf8(harness.read("ssh-stdin")).expect("remote script is UTF-8");
    assert!(script.contains("export CARGO_TARGET_DIR='/srv/operator/target'\n"));
    assert!(!script.contains("checkout_path=$(pwd -P)"));
    assert!(!script.contains("sha256sum"));
}

/// ´test:integration:tracked-lockfile-presence-keeps-locked-on-all-generated-cargo-steps´
#[test]
fn tracked_lockfile_presence_keeps_locked_on_all_generated_cargo_steps() {
    assert_eq!(
        generated_cargo_invocations(LockfileState::TrackedPresent),
        concat!(
            "fmt --all -- --check\n",
            "clippy --workspace --all-targets --locked -- -D warnings\n",
            "test -p alpha --all-features --locked\n",
            "doc --no-deps -p alpha --locked\n",
            "build --release --locked --workspace\n",
        )
        .as_bytes()
    );
}

/// ´test:integration:tracked-lockfile-absence-omits-locked-from-all-generated-cargo-steps´
#[test]
fn tracked_lockfile_absence_omits_locked_from_all_generated_cargo_steps() {
    assert_eq!(
        generated_cargo_invocations(LockfileState::TrackedAbsent),
        concat!(
            "fmt --all -- --check\n",
            "clippy --workspace --all-targets -- -D warnings\n",
            "test -p alpha --all-features\n",
            "doc --no-deps -p alpha\n",
            "build --release --workspace\n",
        )
        .as_bytes()
    );
}

/// ´test:integration:untracked-stale-lockfile-is-cleaned-and-omits-locked´
#[test]
fn untracked_stale_lockfile_is_cleaned_and_omits_locked() {
    assert_eq!(
        generated_cargo_invocations(LockfileState::UntrackedStale),
        concat!(
            "fmt --all -- --check\n",
            "clippy --workspace --all-targets -- -D warnings\n",
            "test -p alpha --all-features\n",
            "doc --no-deps -p alpha\n",
            "build --release --workspace\n",
        )
        .as_bytes()
    );
}

/// ´test:integration:release-build-flag-appends-a-separately-timed-workspace-build´
#[test]
fn release_build_flag_appends_a_separately_timed_workspace_build() {
    let harness = Harness::new("release-build");
    harness.set_ssh_result(b"ok\n", 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            OsStr::new("-D"),
            OsStr::new("--release-build"),
            argument(harness.worktree()),
        ],
    );

    assert!(output.status.success());
    let script = String::from_utf8(harness.read("ssh-stdin")).expect("remote script is UTF-8");
    let test = script.find("sec test; time").expect("test step exists");
    let doc = script
        .find("sec doc; time")
        .expect("documentation step exists");
    let release = script
        .find("sec release-build; time nice -n19 cargo build --release $locked_flag --workspace\n")
        .expect("release-build step exists");
    assert!(test < doc && doc < release);
}

/// ´test:integration:remote-status-two-is-declared-failed-verdict´
#[test]
fn remote_status_two_is_declared_failed_verdict() {
    let harness = Harness::new("remote-two");
    harness.set_ssh_result(b"remote usage\n", 2);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_final_report(&normalize_wall(&output.stdout), &report("worktree", 2));
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:undeclared-remote-status-maps-to-runtime-failure´
#[test]
fn undeclared_remote_status_maps_to_runtime_failure() {
    let harness = Harness::new("remote-undeclared");
    harness.set_ssh_result(b"remote evidence\n", 7);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    let normalized = normalize_wall(&output.stdout);
    assert!(normalized.starts_with(b"remote evidence\n"));
    assert!(
        normalized
            .windows(REMOTE_DIAGNOSTIC.len())
            .any(|window| window == REMOTE_DIAGNOSTIC)
    );
    assert_final_report(&normalized, &report("worktree", 1));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(fixture_status("remote-undeclared"), 7);
    assert!(
        fixture("remote-undeclared", "stdout")
            .ends_with(b"exit=7 wall=Ns verdict=FAILED ref=refs/lanes/verify-worktree\n")
    );
}

/// ´test:integration:spawn-failures-are-classed-and-never-reach-a-real-tool´
#[test]
fn spawn_failures_are_classed_and_never_reach_a_real_tool() {
    for tool in ["git", "ssh"] {
        let harness = Harness::new(tool);
        harness.set_ssh_result(b"", 0);
        harness.remove_tool(tool);
        let output = run(
            &mut harness.command(),
            &[
                OsStr::new("-p"),
                OsStr::new("alpha"),
                argument(harness.worktree()),
            ],
        );
        let diagnostic = if tool == "git" {
            SNAPSHOT_DIAGNOSTIC
        } else {
            REMOTE_DIAGNOSTIC
        };
        assert_eq!(output.status.code(), Some(1));
        assert!(
            normalize_wall(&output.stdout)
                .windows(diagnostic.len())
                .any(|window| window == diagnostic)
        );
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert!(harness.temporary_index_is_clean());
    }
}

/// ´test:integration:a-snapshot-failure-without-a-tool-carries-the-error-text´
#[test]
fn a_snapshot_failure_without_a_tool_carries_the_error_text() {
    let harness = Harness::new("missing-git");
    harness.remove_tool("git");
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );

    let mut expected =
        b"superloop-gate-submit: git rev-parse HEAD failed\nNo such file or directory (os error 2)\n"
            .to_vec();
    expected.extend(SNAPSHOT_DIAGNOSTIC);
    expected.extend(report("worktree", 1));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(normalize_wall(&output.stdout), expected);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(harness.temporary_index_is_clean());
}

/// ´test:integration:unterminated-remote-evidence-is-separated-from-final-report´
#[test]
fn unterminated_remote_evidence_is_separated_from_final_report() {
    let harness = Harness::new("unterminated");
    harness.set_ssh_result(b"partial evidence", 0);
    let output = run(
        &mut harness.command(),
        &[
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ],
    );
    let normalized = normalize_wall(&output.stdout);
    assert!(normalized.starts_with(b"partial evidence\nRUN-REPORT"));
    assert_final_report(&normalized, &report("worktree", 0));
    assert!(fixture("unterminated-evidence", "stdout").starts_with(b"partial evidenceRUN-REPORT"));
}

/// ´test:integration:panic-hook-is-installed-before-argument-handling-and-hides-payload´
#[test]
fn panic_hook_is_installed_before_argument_handling_and_hides_payload() {
    let harness = Harness::new("panic-before-args");
    let output = harness
        .command()
        .env("LANE_VERIFY_TEST_PANIC", "secret-panic-payload")
        .arg("secret-argument")
        .output_serialized()
        .expect("panic subprocess runs");
    let mut expected = INTERNAL_DIAGNOSTIC.to_vec();
    expected.extend(report("unknown", 1));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(normalize_wall(&output.stdout), expected);
    assert_eq!(output.stderr, [] as [u8; 0]);
    for forbidden in [
        "secret-panic-payload",
        "secret-argument",
        "panicked at",
        "backtrace",
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(forbidden));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(forbidden));
    }
}

/// ´test:integration:panic-after-parsing-still-ends-in-one-failed-report´
#[test]
fn panic_after_parsing_still_ends_in_one_failed_report() {
    let harness = Harness::new("panic-after-parse");
    let output = harness
        .command()
        .env("LANE_VERIFY_TEST_PANIC_AFTER_PARSE", "secret-after-parse")
        .args([
            OsStr::new("-p"),
            OsStr::new("alpha"),
            argument(harness.worktree()),
        ])
        .output_serialized()
        .expect("post-parse panic subprocess runs");
    let normalized = normalize_wall(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(normalized.starts_with(INTERNAL_DIAGNOSTIC));
    assert_final_report(&normalized, &report("unknown", 1));
    assert!(!String::from_utf8_lossy(&normalized).contains("secret-after-parse"));
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:failed-generated-battery-keeps-samples-and-exit-proof´
#[test]
fn failed_generated_battery_keeps_samples_and_exit_proof() {
    for committed in [false, true] {
        let harness = Harness::new("sample-failure");
        let mut command = harness.remote_execution_command();
        command.env("SAMPLE_FAIL_TEST", "1");
        let mut args = vec![OsStr::new("-p"), OsStr::new("alpha")];
        if committed {
            args.extend([
                OsStr::new("--committed-head"),
                OsStr::new("refs/heads/lane/R"),
            ]);
        }
        args.push(argument(harness.worktree()));
        let output = run(&mut command, &args);
        assert_eq!(output.status.code(), Some(1));
        let evidence = String::from_utf8(output.stdout).expect("failure evidence");
        for battery in ["gate", "fmt", "clippy", "test"] {
            assert_eq!(
                evidence
                    .matches(&format!("SAMPLE {battery} start "))
                    .count(),
                1
            );
            assert_eq!(
                evidence.matches(&format!("SAMPLE {battery} end ")).count(),
                1
            );
            assert_eq!(
                evidence.matches(&format!("DELTA {battery} wall=")).count(),
                1
            );
        }
        assert!(evidence.contains("own_user_s="));
        assert!(evidence.contains("own_system_s="));
        assert!(evidence.contains("scope=shared-or-unisolated"));
        assert!(
            evidence
                .lines()
                .last()
                .expect("report")
                .contains("verdict=FAILED")
        );
        if committed {
            assert!(evidence.contains("CHECKED-OUT object="));
        }
    }
}
