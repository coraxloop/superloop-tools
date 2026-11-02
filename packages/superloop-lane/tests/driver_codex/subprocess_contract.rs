//! End-to-end contract tests use only an injected Codex executable and
//! synthetic clock values. No test can contact a provider.

mod support;

use support::SerializedCommand as _;

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{Harness, argument};

const USAGE_DIAGNOSTIC: &[u8] = b"codex-lane: usage_error: invalid command-line arguments\n";
const RUNTIME_DIAGNOSTIC: &[u8] = b"codex-lane: runtime_failure: lane execution failed\n";
const INTERNAL_DIAGNOSTIC: &[u8] = b"codex-lane: internal_failure: unexpected internal failure\n";

/// Missing executable settings refuse before any run directory is allocated.
/// ´test:integration:codex-configured-selectors-refuse-before-allocation´
#[test]
fn codex_configured_selectors_refuse_before_allocation() {
    for (variable, setting) in [
        ("LANE_DRIVER_ARGV", "driver_argv"),
        ("LANE_BACKEND_ARGV", "backend_argv"),
    ] {
        let harness = Harness::new(variable);
        let mut command = harness.command();
        command.env_remove(variable);
        let result = output(
            &mut command,
            &[
                OsStr::new("-t60"),
                OsStr::new("-nmissing"),
                OsStr::new("hello"),
            ],
        );
        assert_eq!(result.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(setting),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!harness.run_dir("missing").exists());
        assert_eq!(harness.read("argv"), b"");
    }
}

/// Configured fixed arguments and their source remain visible in execution evidence.
///
/// # Panics
/// Panics only if fixture setup or the asserted execution-evidence contract fails.
///
/// ´test:integration:configured-backend-preserves-arguments-and-report-evidence´
#[test]
fn configured_backend_preserves_arguments_and_report_evidence() {
    let harness = Harness::new("configured-backend");
    let mut command = harness.command();
    let evidence = command
        .get_envs()
        .find(|(key, _)| *key == "LANE_SETTINGS_EVIDENCE")
        .and_then(|(_, value)| value)
        .expect("fixture evidence");
    let mut evidence: serde_json::Value =
        serde_json::from_str(evidence.to_str().expect("UTF-8 evidence")).expect("JSON evidence");
    evidence["backend_argv"]["codex"]
        .as_array_mut()
        .expect("vector")
        .push(serde_json::json!("fixed argument"));
    command
        .env("LANE_BACKEND_ARGV", evidence["backend_argv"].to_string())
        .env("LANE_SETTINGS_EVIDENCE", evidence.to_string())
        .env("ORACLE_EXIT", "0");
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nconfigured"),
            OsStr::new("hello"),
        ],
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(harness.read("argv").starts_with(b"fixed argument\nexec\n"));
    let directory = harness.run_dir("configured");
    let saved: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("backend-settings.json")).expect("saved evidence"),
    )
    .expect("JSON evidence");
    assert_eq!(saved["settings"], evidence);
    assert_eq!(saved["program"], evidence["backend_argv"]["codex"][0]);
    let report = String::from_utf8_lossy(&result.stdout);
    assert!(report.contains(" backend_program="));
    assert!(report.contains(" settings="));
    assert!(report.contains(" settings_sha256="));
}

/// # Panics
/// Panics only if fixture setup or absolute root recording fails.
/// ´test:integration:bound-roots-relative-workdir-is-absolute´
#[test]
fn bound_roots_relative_workdir_is_absolute() {
    let harness = Harness::new("relative-bound-roots");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-nroots"),
        OsStr::new("-Cworktree"),
        OsStr::new("hello"),
    ]);
    assert!(result.status.success(), "{result:?}");
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(harness.run_dir("roots").join("bound-roots.json")).expect("root record"),
    )
    .expect("root JSON");
    assert_eq!(
        record,
        serde_json::json!({"schema":1,"roots":[harness.worktree()]})
    );
}

/// # Panics
/// Panics only if fixture setup or the prior-record refusal contract fails.
/// ´test:integration:bound-roots-prior-shape-refuses-before-child´
#[test]
fn bound_roots_prior_shape_refuses_before_child() {
    for prior in [
        serde_json::json!({"schema":2,"roots":[]}),
        serde_json::json!({"schema":1,"roots":[],"extra":true}),
        serde_json::json!({"roots":[]}),
        serde_json::json!({"schema":1,"roots":["relative"]}),
    ] {
        let harness = Harness::new("prior-bound-roots");
        let run = harness.seed_resume("prior", b"0\n");
        fs::write(run.join("bound-roots.json"), prior.to_string()).expect("prior roots");
        let result = harness.run(&[
            OsStr::new("-t60"),
            OsStr::new("-nnext"),
            OsStr::new("-r"),
            OsStr::new("session-1"),
            OsStr::new("-d"),
            argument(&run),
            OsStr::new("continue"),
        ]);
        assert!(!result.status.success(), "{prior}: {result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("bound-roots-shape"));
        assert_eq!(harness.read("argv"), [] as [u8; 0]);
        assert_eq!(
            fs::read_to_string(run.join("bound-roots.json")).expect("unchanged record"),
            prior.to_string()
        );
    }
}

/// # Panics
/// Panics only if fixture setup or the retained-root contract fails.
/// ´test:integration:bound-roots-survive-config-removal-and-resume´
#[test]
fn bound_roots_survive_config_removal_and_resume() {
    let harness = Harness::new("bound-roots");
    let settings = harness.home().join(".codex/config.toml");
    let sibling = harness.root().join("sibling/.git");
    fs::write(
        &settings,
        format!(
            "[sandbox_workspace_write]\nwritable_roots = ['{}']\n",
            sibling.display()
        ),
    )
    .expect("root configuration");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-nroots"),
        OsStr::new("-C"),
        argument(harness.worktree()),
        OsStr::new("hello"),
    ]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let run = harness.run_dir("roots");
    let read = || -> serde_json::Value {
        serde_json::from_slice(&fs::read(run.join("bound-roots.json")).expect("root record"))
            .expect("root JSON")
    };
    let expected = serde_json::json!({"schema":1,"roots":[harness.worktree(), sibling]});
    assert_eq!(read(), expected);
    fs::write(
        &settings,
        "[sandbox_workspace_write]\nwritable_roots = []\n",
    )
    .expect("remove root from later configuration");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-nnext"),
        OsStr::new("-C"),
        argument(harness.worktree()),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run),
        OsStr::new("continue"),
    ]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(read(), expected);
}

/// # Panics
/// Panics only if fixture setup or the named refusal contract fails.
/// ´test:integration:bound-roots-invalid-config-refuses-before-child´
#[test]
fn bound_roots_invalid_config_refuses_before_child() {
    let harness = Harness::new("invalid-bound-roots");
    fs::write(
        harness.home().join(".codex/config.toml"),
        "[sandbox_workspace_write]\nwritable_roots = ['relative']\n",
    )
    .expect("invalid root configuration");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-nroots"),
        OsStr::new("hello"),
    ]);
    assert!(!result.status.success());
    assert!(result.stdout.starts_with(RUNTIME_DIAGNOSTIC));
    assert!(String::from_utf8_lossy(&result.stdout).contains("bound-roots-config-relative"));
    assert!(
        fs::read_to_string(harness.run_dir("roots").join("stderr.txt"))
            .expect("retained refusal")
            .contains("bound-roots-config-relative")
    );
    assert_eq!(harness.read("argv"), [] as [u8; 0]);
}

/// # Panics
/// Panics only if fixture setup or the asserted attempt-wall contract fails.
///
/// ´test:integration:attempt-wall-reaches-the-driver-report-as-a-failure´
#[test]
fn attempt_wall_reaches_the_driver_report_as_a_failure() {
    let harness = Harness::new("attempt-wall");
    let client = harness.root().join("wall-client");
    support::write_executable(&client, b"#!/bin/sh\ncat >/dev/null\nprintf 'attempt-wall wall_seconds=9 bound_seconds=8\\n' > \"$LANE_ATTEMPT_END\"\nexit 1\n", 0o755).expect("helper client stand-in");
    let mut command = harness.command();
    let runtime = harness.repo().join("runs/box/launch");
    fs::create_dir_all(&runtime).expect("runtime directory");
    let argv = runtime.join("runtime.argv");
    fs::write(&argv, format!("{}\0", client.display())).expect("runtime argv");
    fs::write(
        runtime.join("runtime.env"),
        format!("HOME={}\0PATH=/usr/bin:/bin\0", harness.home().display()),
    )
    .expect("runtime environment");
    Harness::configure_boxed(&mut command);
    command.env("LANE_RUN_DIR", runtime.parent().expect("box directory"));
    let result = output(
        &mut command,
        &[OsStr::new("-t2"), OsStr::new("-nwall"), OsStr::new("hello")],
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let directory = runtime
        .parent()
        .expect("box directory")
        .join("20260828T120000Z-wall");
    let expected = format!(
        "RUN-REPORT lane=wall exit=1 wall=0s budget=2s verdict=FAILED dir={} cause=attempt-wall attempt_elapsed_seconds=9 attempt_bound_seconds=8\n",
        directory.display()
    );
    assert_eq!(without_settings(&result.stdout), expected.as_bytes());
    assert_eq!(
        fs::read(directory.join("run-report.txt")).expect("saved report"),
        result.stdout
    );
}

/// # Panics
/// Panics only if fixture setup or the asserted attempt-wall contract fails.
///
/// ´test:integration:host-child-neither-receives-nor-publishes-an-attempt-end´
#[test]
fn host_child_neither_receives_nor_publishes_an_attempt_end() {
    let harness = Harness::new("host-attempt-end");
    let directory = harness.run_dir("host");
    let client = harness.root().join("host-client");
    support::write_executable(&client, b"#!/bin/sh\ncat >/dev/null\nprintf '%s' \"${LANE_ATTEMPT_END-unset}\" > \"$HOST_ENV_OBSERVED\"\nprintf 'attempt-wall wall_seconds=9 bound_seconds=8\\n' > \"$HOST_ATTEMPT_END\"\nexit 1\n", 0o755).expect("host child");
    let observed = harness.root().join("observed-env");
    let mut command = harness.command();
    harness.configure_backend(&mut command, &client);
    command
        .env("LANE_ATTEMPT_END", "must-not-be-inherited")
        .env("HOST_ENV_OBSERVED", &observed)
        .env("HOST_ATTEMPT_END", directory.join(".attempt-end"));
    let result = output(
        &mut command,
        &[OsStr::new("-t2"), OsStr::new("-nhost"), OsStr::new("hello")],
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(fs::read(observed).expect("observed environment"), b"unset");
    assert_eq!(
        fs::read(directory.join(".attempt-end")).expect("host sidecar"),
        b"attempt-wall wall_seconds=9 bound_seconds=8\n"
    );
    let expected = format!(
        "RUN-REPORT lane=host exit=1 wall=0s budget=2s verdict=FAILED dir={}\n",
        directory.display()
    );
    assert_eq!(without_settings(&result.stdout), expected.as_bytes());
    assert_eq!(
        fs::read(directory.join("run-report.txt")).expect("saved report"),
        result.stdout
    );
}

fn fixture(case: &str, suffix: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/driver_codex/fixtures/expected")
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

fn replace_all(mut bytes: Vec<u8>, from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return bytes;
    }
    let mut offset = 0;
    while let Some(relative) = bytes[offset..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let start = offset + relative;
        bytes.splice(start..start + from.len(), to.iter().copied());
        offset = start + to.len();
    }
    bytes
}

fn without_settings(bytes: &[u8]) -> Vec<u8> {
    let marker = b" backend_program=";
    let mut result = bytes.to_vec();
    if let Some(start) = result
        .windows(marker.len())
        .rposition(|part| part == marker)
    {
        let end = result[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(result.len(), |end| start + end);
        let fields = std::str::from_utf8(&result[start..end]).expect("settings evidence fields");
        assert!(fields.contains(" settings="));
        let digest = fields
            .split(" settings_sha256=")
            .nth(1)
            .expect("settings digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        result.drain(start..end);
    }
    result
}

fn normalize(harness: &Harness, run_dir: &Path, bytes: &[u8]) -> Vec<u8> {
    let run = run_dir.to_string_lossy();
    let repo = harness.repo().to_string_lossy();
    let normalized = replace_all(without_settings(bytes), run.as_bytes(), b"$RUN_DIR");
    let mut normalized = replace_all(normalized, repo.as_bytes(), b"$REPO");
    let prefix = b" wall=";
    let suffix = b"s budget=";
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

fn assert_final_report(stdout: &[u8], expected: &[u8]) {
    assert!(stdout.ends_with(expected), "owned report is not final");
    assert_eq!(
        stdout
            .windows(b"RUN-REPORT ".len())
            .filter(|window| *window == b"RUN-REPORT ")
            .count(),
        1,
        "owned report must occur exactly once"
    );
}

fn assert_oracle_roles(harness: &Harness, run_dir: &Path, case: &str) {
    assert_eq!(
        harness.read("codex-home"),
        format!("{}\n", harness.home().join(".codex").display()).as_bytes()
    );
    for role in ["argv", "stdin", "cwd"] {
        assert_eq!(
            normalize(harness, run_dir, &harness.read(role)),
            fixture(case, role),
            "case {case} role {role}"
        );
    }
}

fn output(command: &mut Command, arguments: &[&OsStr]) -> Output {
    command
        .args(arguments)
        .output_serialized()
        .expect("codex-lane subprocess runs")
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn read_started_at(path: &Path, earliest: u64, latest: u64) -> String {
    let stamp = fs::read_to_string(path).expect("read step start");
    let bytes = stamp.as_bytes();
    assert_eq!(bytes.len(), 21, "one UTC second and LF");
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            4 | 7 => assert_eq!(*byte, b'-'),
            10 => assert_eq!(*byte, b'T'),
            13 | 16 => assert_eq!(*byte, b':'),
            19 => assert_eq!(*byte, b'Z'),
            20 => assert_eq!(*byte, b'\n'),
            _ => assert!(byte.is_ascii_digit()),
        }
    }
    let field = |start, end| {
        std::str::from_utf8(&bytes[start..end])
            .expect("ASCII digits")
            .parse::<u64>()
            .expect("decimal UTC field")
    };
    let (year, month, day) = (field(0, 4), field(5, 7), field(8, 10));
    let (hour, minute, second) = (field(11, 13), field(14, 16), field(17, 19));
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    assert!(year >= 1970 && (1..=12).contains(&month));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_index = usize::try_from(month - 1).expect("valid month index");
    assert!((1..=months[month_index]).contains(&day));
    assert!(hour < 24 && minute < 60 && second < 60);
    let days: u64 = (1970..year).map(|year| 365 + u64::from(leap(year))).sum();
    let days = days + months.iter().take(month_index).sum::<u64>() + day - 1;
    let epoch = ((days * 24 + hour) * 60 + minute) * 60 + second;
    assert!(
        (earliest..=latest).contains(&epoch),
        "start lies within the launch"
    );
    stamp
}

/// A fresh Codex step records its UTC start.
/// ´test:integration:codex-fresh-step-records-utc-start´
#[test]
fn codex_fresh_step_records_utc_start() {
    let harness = Harness::new("fresh-start");
    let before = now_epoch();
    let result = harness.run(&[OsStr::new("-t"), OsStr::new("60"), OsStr::new("hello")]);
    let after = now_epoch();

    assert_eq!(result.status.code(), Some(0));
    read_started_at(&harness.run_dir("lane").join(".started-at"), before, after);
}

/// A fresh Codex run records the thread id carried by its event stream.
/// ´test:integration:a-fresh-codex-run-records-its-thread-id´
#[test]
fn a_fresh_codex_run_records_its_thread_id() {
    let harness = Harness::new("fresh-thread-id");
    let result = harness.run(&[OsStr::new("-t"), OsStr::new("60"), OsStr::new("hello")]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(harness.run_dir("lane").join("thread-id.txt")).expect("read run thread id"),
        b"session-1\n"
    );
}

/// ´test:integration:codex-fresh-launch-uses-lane-runs-root-and-reports-its-directory´
#[test]
fn codex_fresh_launch_uses_lane_runs_root_and_reports_its_directory() {
    let harness = Harness::new("runs-root");
    let root = harness.root().join("selected-runs");
    let run_dir = root.join("20260828T120000Z-selected");
    let mut command = harness.command();
    command.env("LANE_RUNS_ROOT", &root);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nselected"),
            OsStr::new("hello"),
        ],
    );
    assert_eq!(result.status.code(), Some(0));
    assert!(run_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .contains(&format!(" dir={} backend_program=", run_dir.display()))
    );
}

/// ´test:integration:copied-codex-driver-keeps-configured-root-and-selected-run-separate´
#[test]
fn copied_codex_driver_keeps_configured_root_and_selected_run_separate() {
    let harness = Harness::new("copied-runs-root");
    let installed = harness.root().join("relocated/bin");
    fs::create_dir_all(&installed).expect("relocated directory");
    let driver = installed.join("codex-lane");
    support::write_executable(
        &driver,
        &fs::read(env!("CARGO_BIN_EXE_superloop-lane")).expect("driver bytes"),
        0o755,
    )
    .expect("copied driver");
    let root = harness.root().join("configured-runs");
    let selected = root.join("R");
    fs::create_dir_all(&selected).expect("selected run");
    let mut command = harness.command_at(&driver);
    command
        .env("LANE_RUNS_ROOT", &root)
        .env("LANE_RUN_DIR", &selected);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-nselected"),
            OsStr::new("hello"),
        ],
    );
    let step = selected.join("20260828T120000Z-selected");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        fs::read(step.join("run-report.txt")).expect("report"),
        result.stdout
    );
    assert!(!installed.join("runs").exists());
    assert!(
        !installed
            .parent()
            .expect("relocated parent")
            .join("runs")
            .exists()
    );
    assert!(!harness.repo().join("runs").exists());
    let refused = selected.join("must-not-exist");
    let mut command = harness.command_at(&driver);
    command
        .env_remove("LANE_RUNS_ROOT")
        .env("LANE_RUN_DIR", &selected);
    let result = output(
        &mut command,
        &[
            OsStr::new("-t60"),
            OsStr::new("-d"),
            refused.as_os_str(),
            OsStr::new("hello"),
        ],
    );
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("runs_root_required"));
    assert!(!refused.exists());
}

/// ´test:integration:codex-fresh-launch-refuses-missing-or-relative-runs-root-before-allocation´
#[test]
fn codex_fresh_launch_refuses_missing_or_relative_runs_root_before_allocation() {
    for (index, invalid) in [None, Some(""), Some("relative")].into_iter().enumerate() {
        let harness = Harness::new(&format!("runs-root-refusal-{index}"));
        let mut command = harness.command();
        if let Some(invalid) = invalid {
            command.env("LANE_RUNS_ROOT", invalid);
        } else {
            command.env_remove("LANE_RUNS_ROOT");
        }
        let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("hello")]);
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(
            result.stderr,
            b"codex-lane: runs_root_required: LANE_RUNS_ROOT must be an absolute path\n"
        );
        assert_eq!(
            result.stdout,
            b"RUN-REPORT lane=unknown exit=2 wall=0s budget=60s verdict=FAILED dir=unknown\n",
        );
        assert!(!harness.repo().join("runs").exists());
        assert!(!harness.repo().join("relative").exists());
        assert!(!harness.root().join("argv").exists());
    }
}

/// Normal completion matches the shell oracle.
/// ´test:integration:normal-completion-matches-shell-oracle´
#[test]
fn normal_completion_matches_shell_oracle() {
    let harness = Harness::new("normal");
    let run_dir = harness.run_dir("lane");
    let result = harness.run(&[OsStr::new("-t"), OsStr::new("60"), OsStr::new("hello")]);

    assert_eq!(
        result.status.code(),
        Some(fixture_status("normal-completion"))
    );
    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("normal-completion", "stdout")
    );
    assert_eq!(result.stderr, fixture("normal-completion", "stderr"));
    assert_oracle_roles(&harness, &run_dir, "normal-completion");
    assert_eq!(
        fs::read(run_dir.join("brief.txt")).expect("read brief"),
        fixture("normal-completion", "input")
    );
    assert_eq!(
        fs::read(run_dir.join("events.jsonl")).expect("read events"),
        fixture("normal-completion", "events")
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read last message"),
        fixture("normal-completion", "last-message")
    );
    assert_eq!(
        normalize(
            &harness,
            &run_dir,
            &fs::read(run_dir.join("run-report.txt")).expect("read report")
        ),
        fixture("normal-completion", "report")
    );
}

/// The stdin prompt matches the shell oracle without an invented line feed.
/// ´test:integration:stdin-prompt-matches-shell-oracle-without-inventing-lf´
#[test]
fn stdin_prompt_matches_shell_oracle_without_inventing_lf() {
    let harness = Harness::new("stdin");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .args(["-t", "60", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn_serialized().expect("spawn stdin case");
    {
        use std::io::Write as _;
        // A child is entitled to exit without draining its stdin: an injected panic
        // and a rejected argument list both leave the lane before the prompt read.
        // A read end the child has closed therefore says nothing about this case —
        // its exit status, its streams, and the run directory are the verdict. Any
        // other write failure is a fault of the harness itself and must be seen.
        let write = child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(b"stdin prompt");
        if let Err(error) = write {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "write prompt: {error}"
            );
        }
    }
    let result = child.wait_with_output().expect("wait stdin case");

    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("stdin-prompt", "stdout")
    );
    assert_oracle_roles(&harness, &run_dir, "stdin-prompt");
    assert_eq!(
        fs::read(run_dir.join("brief.txt")).expect("read stdin brief"),
        b"stdin prompt"
    );
}

/// Resume matches the shell invocation and preserves the prior step history.
/// ´test:integration:resume-matches-shell-invocation-and-preserves-step-history´
#[test]
fn resume_matches_shell_invocation_and_preserves_step_history() {
    let harness = Harness::new("resume-history");
    let run_dir = harness.seed_resume("run", b"51\n");
    fs::write(run_dir.join("kill-evidence.txt"), b"reason=STALLED\n")
        .expect("seed pre-upgrade evidence");
    fs::write(run_dir.join(".started-at"), b"2026-09-24T21:35:27Z\n").expect("seed prior start");
    let prior_start = fs::read_to_string(run_dir.join(".started-at")).expect("read prior start");
    let before = now_epoch();
    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("PROCEED"),
    ]);
    let after = now_epoch();

    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("resume-step", "stdout")
    );
    assert_oracle_roles(&harness, &run_dir, "resume-step");
    assert_eq!(
        fs::read(run_dir.join("events.jsonl")).expect("read appended events"),
        fixture("resume-step", "events")
    );
    assert_eq!(
        fs::read(run_dir.join("step-work.txt")).expect("read resume input"),
        b"PROCEED\n"
    );
    let history = run_dir.join("steps/gate");
    assert_eq!(
        fs::read(history.join("run-report.txt")).expect("read archived report"),
        format!(
            "RUN-REPORT lane=gate exit=0 wall=0s budget=60s verdict=ok dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_eq!(
        fs::read(history.join("feed-offset.txt")).expect("read archived offset"),
        b"51\n"
    );
    assert_eq!(
        fs::read(history.join("kill-evidence.txt")).expect("read historical evidence"),
        b"reason=STALLED\n"
    );
    assert_eq!(
        fs::read(history.join("last-message.txt")).expect("read archived message"),
        b"first"
    );
    assert_eq!(
        fs::read_to_string(history.join("started-at.txt")).expect("read archived start"),
        prior_start
    );
    let new_start = read_started_at(&run_dir.join(".started-at"), before, after);
    assert!(new_start >= prior_start);
    assert!(!run_dir.join(".feed-offset").exists());
    assert!(!run_dir.join("kill-evidence.txt").exists());
}

/// A resumed child's first turn is separate from an earlier child's partial line.
/// ´test:integration:resumed-first-turn-after-prior-partial-line-has-context-record´
#[test]
fn resumed_first_turn_after_prior_partial_line_has_context_record() {
    let harness = Harness::new("resume-partial-context");
    let run_dir = harness.seed_resume("run", b"0\n");
    let events_path = run_dir.join("events.jsonl");
    fs::OpenOptions::new()
        .append(true)
        .open(&events_path)
        .expect("prior events")
        .write_all(b"{\"type\":\"item.completed\"")
        .expect("prior child partial line");
    let boundary = fs::read(&events_path).expect("prior events").len();
    let result = harness
        .command()
        .env("ORACLE_MODE", "resume-turn-first")
        .args([
            OsStr::new("-t"),
            OsStr::new("60"),
            OsStr::new("-r"),
            OsStr::new("session-1"),
            OsStr::new("-d"),
            argument(&run_dir),
            OsStr::new("-n"),
            OsStr::new("work"),
            OsStr::new("PROCEED"),
        ])
        .output_serialized()
        .expect("resumed child runs");
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(run_dir.join(".event-start")).expect("step start"),
        format!("{boundary}\n")
    );
    let events = fs::read(&events_path).expect("resumed events");
    assert!(events[boundary..].starts_with(b"{\"type\":\"turn.completed\""));
    let record = fs::read_to_string(run_dir.join("context.jsonl")).expect("context record");
    assert_eq!(record.lines().count(), 1);
    assert!(record.contains("\"turn\":1"));
    assert!(record.contains(&format!("\"event_end\":{}", events.len())));
}

/// A Codex resume records the matched event id when the run has no id file.
/// ´test:integration:a-codex-resume-fills-a-missing-thread-id´
#[test]
fn a_codex_resume_fills_a_missing_thread_id() {
    let harness = Harness::new("resume-missing-thread-id");
    let run_dir = harness.seed_resume("run", b"0\n");
    assert!(!run_dir.join("thread-id.txt").exists());

    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("thread-id.txt")).expect("read run thread id"),
        b"session-1\n"
    );
    assert!(!run_dir.join("steps/gate/thread-id.txt").exists());
}

/// A Codex resume proceeds when the thread-id path cannot be written, rather than refusing as a mismatch.
/// ´test:integration:a-codex-resume-tolerates-an-unwritable-thread-id-path´
#[test]
fn a_codex_resume_tolerates_an_unwritable_thread_id_path() {
    let harness = Harness::new("resume-unwritable-thread-id");
    let run_dir = harness.seed_resume("run", b"0\n");
    let thread_path = run_dir.join("thread-id.txt");
    fs::create_dir(&thread_path).expect("occupy thread-id path with a directory");

    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("resume-step", "stdout")
    );
    assert_eq!(
        fs::read(run_dir.join("run-report.txt")).expect("read settled report"),
        result.stdout
    );
    assert!(thread_path.is_dir());
}

/// A Codex rollback removes a flipped start when the prior archive has none.
/// ´test:integration:a-codex-rollback-removes-a-start-with-no-archived-marker´
#[test]
fn a_codex_rollback_removes_a_start_with_no_archived_marker() {
    let harness = Harness::new("preparation-no-prior-start");
    let run_dir = harness.seed_resume("run", b"0\n");
    fs::write(run_dir.join("thread-id.txt"), b"session-1\n").expect("seed run thread id");
    let report = fs::read(run_dir.join("run-report.txt")).expect("read the surviving report");
    let transcript = fs::metadata(run_dir.join("events.jsonl"))
        .expect("measure the transcript")
        .len();
    let history = run_dir.join("steps/gate");
    fs::create_dir_all(&history).expect("create prior history");
    for file in ["run-report.txt", "last-message.txt"] {
        fs::copy(run_dir.join(file), history.join(file)).expect("archive prior file");
    }
    fs::copy(
        run_dir.join(".feed-offset"),
        history.join("feed-offset.txt"),
    )
    .expect("archive follower offset");
    fs::write(history.join("event-start.txt"), b"0\n").expect("archive prior event start");
    fs::write(history.join("event-end.txt"), format!("{transcript}\n"))
        .expect("archive prior event end");
    fs::write(run_dir.join("step-work.txt"), b"PROCEED\n").expect("seed unfinished input");
    fs::write(run_dir.join(".step-name"), b"work\n").expect("flip step name");
    fs::write(run_dir.join(".event-start"), format!("{transcript}\n")).expect("flip event start");
    fs::write(run_dir.join(".started-at"), b"2026-09-24T21:35:28Z\n").expect("flip step start");

    let before = now_epoch();
    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("PROCEED"),
    ]);
    let after = now_epoch();

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "codex-lane: resume_preparation_rolled_back: step work never started, so gate was restored: {}\n",
            run_dir.display()
        )
        .as_bytes()
    );
    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("resume-step", "stdout")
    );
    assert_eq!(
        fs::read(history.join("run-report.txt")).expect("read archived report"),
        report
    );
    assert_eq!(
        fs::read(history.join("last-message.txt")).expect("read archived message"),
        b"first"
    );
    assert_eq!(
        fs::read(history.join("feed-offset.txt")).expect("read archived offset"),
        b"0\n"
    );
    assert_eq!(
        fs::read(history.join("event-start.txt")).expect("read archived event start"),
        b"0\n"
    );
    assert_eq!(
        fs::read(history.join("event-end.txt")).expect("read archived event end"),
        format!("{transcript}\n").as_bytes()
    );
    assert!(!history.join("started-at.txt").exists());
    assert!(!run_dir.join("steps/work").exists());
    assert_eq!(
        fs::read(run_dir.join(".event-start")).expect("read new event start"),
        format!("{transcript}\n").as_bytes()
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read new message"),
        b"final answer"
    );
    read_started_at(&run_dir.join(".started-at"), before, after);
    assert!(!run_dir.join(".feed-offset").exists());
    assert_eq!(
        fs::read(run_dir.join("thread-id.txt")).expect("read retained run thread id"),
        b"session-1\n"
    );
    assert!(!history.join("thread-id.txt").exists());
}

/// A fresh follower replays from zero at the resume boundary.
/// ´test:integration:fresh-follower-replays-from-zero-at-resume-boundary´
#[test]
fn fresh_follower_replays_from_zero_at_resume_boundary() {
    let harness = Harness::new("resume-replay");
    let run_dir = harness.seed_resume("run", b"9\n");
    let prior_size = fs::metadata(run_dir.join("events.jsonl"))
        .expect("inspect prior events")
        .len();
    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("again"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("steps/gate/feed-offset.txt")).expect("history offset"),
        b"9\n"
    );
    assert!(!run_dir.join(".feed-offset").exists());
    assert!(
        fs::metadata(run_dir.join("events.jsonl"))
            .expect("inspect resumed events")
            .len()
            > prior_size
    );
}

/// Empty output uses the last nonempty agent message.
/// ´test:integration:empty-output-uses-last-nonempty-agent-message´
#[test]
fn empty_output_uses_last_nonempty_agent_message() {
    let harness = Harness::new("fallback");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "fallback");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("fallback")],
    );

    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("empty-output-fallback", "stdout")
    );
    assert_eq!(
        fs::read(run_dir.join("events.jsonl")).expect("read fallback events"),
        fixture("empty-output-fallback", "events")
    );
    assert_eq!(
        fixture("empty-output-fallback", "last-message"),
        Vec::<u8>::new()
    );
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read recovered message"),
        b"kept answer"
    );
}

/// Growing events can finish successfully over budget.
/// ´test:integration:growing-events-can-finish-over-budget-successfully´
#[test]
fn growing_events_can_finish_over_budget_successfully() {
    let harness = Harness::new("over-budget");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "late")
        .env("CODEX_LANE_TEST_CLOCK", "0,3");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("2"), OsStr::new("late")],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        normalize(&harness, &run_dir, &result.stdout),
        fixture("over-budget-growing", "stdout")
    );
    assert_eq!(
        fs::read(run_dir.join("events.jsonl")).expect("read late events"),
        fixture("over-budget-growing", "events")
    );
}

/// The awake clock drives the step budget.
/// ´test:integration:the-awake-clock-not-the-boot-clock-drives-step-budget´
#[test]
fn the_awake_clock_not_the_boot_clock_drives_step_budget() {
    let harness = Harness::new("awake-budget");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command.env("CODEX_LANE_TEST_CLOCK", "0:0,0:2");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("1"), OsStr::new("boottime")],
    );

    assert_eq!(result.status.code(), Some(0));
    let expected = b"RUN-REPORT lane=lane exit=0 wall=Ns budget=1s verdict=ok dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
}

/// # Panics
/// Panics only if fixtures fail or production recovery violates its bounds.
/// ´test:integration:suspend-recovery-reuses-the-saved-step-and-enforces-both-bounds´
#[test]
fn suspend_recovery_reuses_the_saved_step_and_enforces_both_bounds() {
    for (mode, gap, awake, budget, calls, resumes, success) in [
        ("suspend-once", 900, 1, 60, 2, 1, true),
        ("suspend-always", 900, 0, 60, 4, 3, false),
        ("suspend-always", 900, 1, 1, 1, 0, false),
        ("suspend-always", 900, 1, 2, 2, 1, false),
        ("suspend-always", 0, 1, 60, 1, 0, false),
        ("suspend-always", 2, 1, 60, 1, 0, false),
        ("suspend-complete", 900, 1, 60, 1, 0, true),
        ("suspend-trailing", 900, 1, 60, 1, 0, true),
        ("suspend-no-thread", 900, 1, 60, 1, 0, false),
        ("suspend-first-gap", 900, 1, 60, 2, 1, false),
        ("suspend-terminated", 900, 1, 60, 1, 0, false),
        ("suspend-attempt-wall", 900, 1, 60, 1, 0, false),
        ("suspend-killed", 900, 1, 60, 1, 0, false),
    ] {
        let harness = Harness::new(mode);
        let clock = harness.repo().join("clock");
        fs::write(&clock, "0:0").expect("initial paired clock");
        let mut command = harness.command();
        command
            .env("CODEX_LANE_TEST_CLOCK", format!("@{}", clock.display()))
            .env("ORACLE_MODE", mode)
            .env("ORACLE_GAP", gap.to_string())
            .env("ORACLE_AWAKE", awake.to_string());
        if mode == "suspend-attempt-wall" {
            suspend_helper_runtime(&harness, &mut command);
        }
        let result = output(
            &mut command,
            &[
                OsStr::new("-t"),
                OsStr::new(&budget.to_string()),
                OsStr::new("saved duty"),
            ],
        );
        assert_eq!(result.status.success(), success, "{mode}: {result:?}");
        let run_dir = if mode == "suspend-attempt-wall" {
            harness.repo().join("runs/box/20260828T120000Z-lane")
        } else {
            harness.run_dir("lane")
        };
        let report = String::from_utf8(result.stdout).expect("report text");
        if matches!(
            mode,
            "suspend-terminated" | "suspend-attempt-wall" | "suspend-killed"
        ) {
            assert!(report.contains("suspend_gap=900s"), "{mode}: {report}");
        }
        if mode == "suspend-attempt-wall" {
            assert!(report.contains("cause=attempt-wall"), "{report}");
        }
        assert_eq!(
            fs::read_to_string(harness.root().join("ack"))
                .expect("invocation count")
                .trim(),
            calls.to_string()
        );
        assert_eq!(
            harness.read("stdin"),
            fs::read(run_dir.join("brief.txt")).expect("saved brief")
        );
        assert_eq!(
            fs::read_to_string(run_dir.join(".step-name"))
                .expect("step identity")
                .trim(),
            "lane"
        );
        assert!(!run_dir.join("steps/lane").exists());
        let record = run_dir.join("suspend-resumes-lane.txt");
        if resumes == 0 {
            assert!(!record.exists());
            assert!(!report.contains("suspend_resumes="));
        } else {
            assert!(
                report.contains(&format!("suspend_resumes={resumes}")),
                "{report}"
            );
            assert_eq!(
                fs::read_to_string(record)
                    .expect("recovery evidence")
                    .lines()
                    .count(),
                resumes
            );
            let argv = String::from_utf8(harness.read("argv")).expect("resume argv");
            assert!(argv.contains("resume\nsession-1\n"), "{argv}");
        }
    }
}

/// Configure the production boxed-runtime entry with the same vendor fixture.
/// # Panics
/// Panics only if fixture setup fails or its declared vendor program is absent.
fn suspend_helper_runtime(harness: &Harness, command: &mut Command) {
    let mut environment = Vec::new();
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            environment.extend_from_slice(key.as_encoded_bytes());
            environment.push(b'=');
            environment.extend_from_slice(value.as_encoded_bytes());
            environment.push(0);
        }
    }
    let backend = command
        .get_envs()
        .find_map(|(key, value)| (key == "LANE_BACKEND_ARGV").then_some(value).flatten())
        .expect("fixture backend selector");
    let backend: serde_json::Value =
        serde_json::from_str(backend.to_str().expect("UTF-8 selector")).expect("backend vector");
    let program = backend["codex"][0].as_str().expect("fixture vendor");
    let runtime = harness.repo().join("runs/box/launch");
    fs::create_dir_all(&runtime).expect("runtime directory");
    let argv = runtime.join("runtime.argv");
    fs::write(
        &argv,
        format!(
            "{}\0-o\0{}\0",
            program,
            runtime
                .parent()
                .expect("box directory")
                .join("20260828T120000Z-lane/last-message.txt")
                .display()
        ),
    )
    .expect("runtime argv");
    fs::write(runtime.join("runtime.env"), environment).expect("runtime environment");
    Harness::configure_boxed(command);
    command.env("LANE_RUN_DIR", runtime.parent().expect("runs directory"));
}

/// Suspend divergence is recorded beside the earned verdict.
/// ´test:integration:suspend-divergence-is-data-beside-the-earned-verdict´
#[test]
fn suspend_divergence_is_data_beside_the_earned_verdict() {
    let harness = Harness::new("suspend-continues");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("CODEX_LANE_TEST_CLOCK", "0:0,1:901")
        .env("ORACLE_MODE", "terminal");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("suspend")],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(result.stderr, Vec::<u8>::new());
    let expected =
        b"RUN-REPORT lane=lane exit=0 wall=Ns budget=60s verdict=ok suspend_gap=900s dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
    assert_eq!(
        normalize(
            &harness,
            &run_dir,
            &fs::read(run_dir.join("run-report.txt")).expect("read the published report")
        ),
        expected
    );
    assert!(
        !run_dir.join("kill-evidence.txt").exists(),
        "a host sleep is not a kill"
    );
}

/// The monitor publishes awake accounting in the run directory.
/// ´test:integration:the-monitor-publishes-its-awake-accounting-in-the-run-directory´
#[test]
fn the_monitor_publishes_its_awake_accounting_in_the_run_directory() {
    let harness = Harness::new("monitor-sidecar");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "budget-wait")
        .env("CODEX_LANE_TEST_CLOCK", "0:0,131:1031")
        .args([OsStr::new("-t"), OsStr::new("10"), OsStr::new("sidecar")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command.spawn_serialized().expect("spawn driver");
    // The poll read 131 awake seconds and 1,031 boot seconds: a reader holding
    // this line and its own boot reading recovers the awake interval, which the
    // event file's timestamp cannot express.
    let sidecar = await_monitor(&run_dir, "expired_wall=131s");
    assert_monitor_line(
        &sidecar,
        "quiet=131s wall=131s event_size=0 boot=1031s awake=131s",
        " budget=10s last_growth=0s state=stalled expired_wall=131s expired_event_size=0 expired_last_growth=0s expired_quiet=131s expired_state=stalled",
    );
    fs::write(harness.root().join("release"), b"").expect("release child");
    assert_eq!(
        driver
            .wait_with_output()
            .expect("natural completion")
            .status
            .code(),
        Some(0)
    );
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:capacity-measured-wait-is-published-before-the-next-attempt´
#[test]
fn capacity_measured_wait_is_published_before_the_next_attempt() {
    let harness = Harness::new("capacity-wait-publication");
    let run_dir = harness.run_dir("lane");
    let listener = capacity_boundary(&harness);
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "capacity-then-ok")
        .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker"))
        .env("CODEX_LANE_TEST_BOUNDARY", "capacity-wait-recorded")
        .env(
            "CODEX_LANE_TEST_BOUNDARY_SOCKET",
            harness.root().file_name().expect("fixture name"),
        )
        .args(["-t600", "saved duty"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command.spawn_serialized().expect("driver");
    let mut channel = await_capacity_boundary(&listener);
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("published wait"),
        "attempt=1 result=model-at-capacity retry_in=60s\nattempt=1 waited=60s\n"
    );
    assert!(!String::from_utf8_lossy(&harness.read("argv")).contains("resume\n"));
    channel.write_all(b"r").expect("release retry");
    assert!(
        driver
            .wait_with_output()
            .expect("completion")
            .status
            .success()
    );
}

/// # Panics
/// Panics only if fixture setup fails or an early exit misidentifies its cause.
/// ´test:integration:capacity-early-exits-name-the-signal-or-runtime-failure´
#[test]
fn capacity_early_exits_name_the_signal_or_runtime_failure() {
    for (fault, boundary, reason) in [
        (
            "signal",
            "capacity-before-retry",
            "model-at-capacity; retry-stopped",
        ),
        ("clock", "capacity-before-retry", "clock sample failed"),
        ("clock", "capacity-wait-recorded", "clock sample failed"),
        ("brief", "capacity-before-retry", "capacity resume brief:"),
        ("input", "capacity-before-retry", "capacity resume input:"),
    ] {
        let harness = Harness::new("capacity-early-exit");
        let run_dir = harness.run_dir("lane");
        let listener = capacity_boundary(&harness);
        let clock = harness.root().join("clock");
        fs::write(&clock, "0:0").expect("controlled clock");
        let mut command = harness.command();
        command
            .env("ORACLE_MODE", "capacity-then-ok")
            .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker"))
            .env("CODEX_LANE_TEST_CLOCK", format!("@{}", clock.display()))
            .env("CODEX_LANE_TEST_BOUNDARY", boundary)
            .env(
                "CODEX_LANE_TEST_BOUNDARY_SOCKET",
                harness.root().file_name().expect("fixture name"),
            )
            .args(["-t600", "saved duty"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let driver = command.spawn_serialized().expect("driver");
        let mut channel = await_capacity_boundary(&listener);
        match fault {
            "signal" => {
                assert!(
                    Command::new("kill")
                        .args(["-TERM", &driver.id().to_string()])
                        .status_serialized()
                        .expect("signal driver")
                        .success()
                );
            }
            "clock" => fs::remove_file(&clock).expect("break clock sample"),
            "brief" => fs::remove_file(run_dir.join("brief.txt")).expect("remove brief"),
            "input" => fs::create_dir(run_dir.join("step-lane.txt")).expect("obstruct input"),
            _ => unreachable!(),
        }
        channel
            .write_all(if fault == "signal" { b"s" } else { b"r" })
            .expect("release retry");
        let result = driver.wait_with_output().expect("completion");
        assert_eq!(result.status.code(), Some(1), "{fault}: {result:?}");
        let record =
            fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("capacity evidence");
        assert!(
            record.contains(&format!("attempt=1 result={reason}")),
            "{fault}: {record}"
        );
        assert!(!record.contains("bound-reached"), "{record}");
        assert!(!String::from_utf8_lossy(&harness.read("argv")).contains("resume\n"));
        assert!(String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=1"));
        if fault != "signal" {
            assert!(String::from_utf8_lossy(&result.stdout).contains("runtime_failure"));
        }
    }
}

/// # Panics
/// Panics only if fixture setup fails or a recovery loses its failure prefix.
/// ´test:integration:automatic-resume-preparation-errors-name-the-recovery´
#[test]
fn automatic_resume_preparation_errors_name_the_recovery() {
    for recovery in ["suspend", "capacity"] {
        for fault in ["brief", "input"] {
            let harness = Harness::new("recovery-error");
            let run_dir = harness.run_dir("lane");
            let listener = capacity_boundary(&harness);
            let clock = harness.root().join("clock");
            fs::write(&clock, "0:0").expect("controlled clock");
            let mut command = harness.command();
            command
                .env(
                    "ORACLE_MODE",
                    if recovery == "suspend" {
                        "suspend-always"
                    } else {
                        "capacity-always"
                    },
                )
                .env("CODEX_LANE_TEST_CLOCK", format!("@{}", clock.display()))
                .env(
                    "CODEX_LANE_TEST_BOUNDARY",
                    format!(
                        "{recovery}-before-{}",
                        if recovery == "suspend" {
                            "resume"
                        } else {
                            "retry"
                        }
                    ),
                )
                .env(
                    "CODEX_LANE_TEST_BOUNDARY_SOCKET",
                    harness.root().file_name().expect("fixture name"),
                )
                .args(["-t600", "saved duty"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let driver = command.spawn_serialized().expect("driver");
            let mut channel = await_capacity_boundary(&listener);
            if fault == "brief" {
                fs::remove_file(run_dir.join("brief.txt")).expect("remove brief");
            } else {
                fs::create_dir(run_dir.join("step-lane.txt")).expect("obstruct input");
            }
            channel.write_all(b"r").expect("release recovery");
            let result = driver.wait_with_output().expect("completion");
            assert_eq!(
                result.status.code(),
                Some(1),
                "{recovery} {fault}: {result:?}"
            );
            let expected = format!("codex-lane: runtime_failure: {recovery} resume {fault}: ");
            assert!(
                String::from_utf8_lossy(&result.stdout).contains(&expected),
                "{result:?}"
            );
            assert!(
                fs::read_to_string(run_dir.join("stderr.txt"))
                    .expect("diagnostic")
                    .contains(&expected)
            );
            assert!(!String::from_utf8_lossy(&harness.read("argv")).contains("resume\n"));
        }
    }
}

/// # Panics
/// Panics only if fixture setup fails or termination starts another attempt.
/// ´test:integration:termination-during-a-controlled-capacity-wait-stops-retry´
#[test]
fn termination_during_a_controlled_capacity_wait_stops_retry() {
    let harness = Harness::new("capacity-wait-stop");
    let run_dir = harness.run_dir("lane");
    let listener = capacity_boundary(&harness);
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "capacity-then-ok")
        .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker"))
        .env("CODEX_LANE_TEST_BOUNDARY", "capacity-waiting")
        .env(
            "CODEX_LANE_TEST_BOUNDARY_SOCKET",
            harness.root().file_name().expect("fixture name"),
        )
        .args(["-t600", "saved duty"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command.spawn_serialized().expect("driver");
    let mut channel = await_capacity_boundary(&listener);
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("planned wait"),
        "attempt=1 result=model-at-capacity retry_in=60s\n"
    );
    assert!(
        Command::new("kill")
            .args(["-TERM", &driver.id().to_string()])
            .status_serialized()
            .expect("signal driver")
            .success()
    );
    channel.write_all(b"s").expect("release signalled wait");
    let result = driver.wait_with_output().expect("completion");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("stopped wait"),
        "attempt=1 result=model-at-capacity retry_in=60s\nattempt=1 waited=0s\nattempt=1 result=model-at-capacity; retry-stopped\ncapacity_attempts=1 capacity_waits=0s\n"
    );
    assert!(!String::from_utf8_lossy(&harness.read("argv")).contains("resume\n"));
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=1 capacity_waits=0s")
    );
}

fn capacity_boundary(harness: &Harness) -> std::os::unix::net::UnixListener {
    use std::os::linux::net::SocketAddrExt as _;
    let address = std::os::unix::net::SocketAddr::from_abstract_name(
        harness
            .root()
            .file_name()
            .expect("fixture name")
            .as_encoded_bytes(),
    )
    .expect("abstract address");
    let listener =
        std::os::unix::net::UnixListener::bind_addr(&address).expect("boundary listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    listener
}

fn await_capacity_boundary(
    listener: &std::os::unix::net::UnixListener,
) -> std::os::unix::net::UnixStream {
    use std::io::Read as _;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((mut channel, _)) => {
                channel
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read bound");
                let mut ready = [0; 5];
                channel.read_exact(&mut ready).expect("boundary reached");
                assert_eq!(&ready, b"ready");
                return channel;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "capacity boundary did not arrive"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("capacity boundary: {error}"),
        }
    }
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:model-capacity-retries-and-records-each-attempt-before-success´
#[test]
fn model_capacity_retries_and_records_each_attempt_before_success() {
    let harness = Harness::new("capacity-retry");
    let run_dir = harness.run_dir("lane");
    let letter = harness.root().join("letter.md");
    fs::write(&letter, b"The complete letter body.\n").expect("step letter");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "capacity-then-ok")
        .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker"));
    let result = output(
        &mut command,
        &[
            OsStr::new("--step-letter"),
            letter.as_os_str(),
            OsStr::new("-t"),
            OsStr::new("600"),
            OsStr::new("read back"),
        ],
    );
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("attempt record"),
        "attempt=1 result=model-at-capacity retry_in=60s\nattempt=1 waited=60s\nattempt=2 result=completed\ncapacity_attempts=2 capacity_waits=60s\n"
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("thread-id.txt")).expect("latest thread"),
        "session-1\n"
    );
    assert!(harness.read("argv").ends_with(b"resume\nsession-1\n-\n"));
    assert_eq!(harness.read("stdin"), b"read back\n");
    assert_eq!(
        fs::read(run_dir.join("step-lane.txt")).expect("saved duty"),
        b"The complete letter body.\n"
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=2 capacity_waits=60s")
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("wall=60s"));
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:model-capacity-stops-at-the-fourth-attempt´
#[test]
fn model_capacity_stops_at_the_fourth_attempt() {
    let harness = Harness::new("capacity-bound");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "capacity-always");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("600"), OsStr::new("read back")],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("attempt record"),
        "attempt=1 result=model-at-capacity retry_in=60s\nattempt=1 waited=60s\nattempt=2 result=model-at-capacity retry_in=120s\nattempt=2 waited=120s\nattempt=3 result=model-at-capacity retry_in=240s\nattempt=3 waited=240s\nattempt=4 result=model-at-capacity; bound-reached\ncapacity_attempts=4 capacity_waits=60,120,240s\n"
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("wall=420s"));
}

/// # Panics
/// Panics only if a fourth-attempt signal invents a stopped retry or another resume.
/// ´test:integration:fourth-capacity-attempt-signal-keeps-bound-reached´
#[test]
fn fourth_capacity_attempt_signal_keeps_bound_reached() {
    let harness = Harness::new("capacity-bound-signal");
    let run_dir = harness.run_dir("lane");
    let listener = capacity_boundary(&harness);
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "capacity-always")
        .env("CODEX_LANE_TEST_CLOCK", "0")
        .env("CODEX_LANE_TEST_BOUNDARY", "capacity-before-retry")
        .env(
            "CODEX_LANE_TEST_BOUNDARY_SOCKET",
            harness.root().file_name().expect("fixture name"),
        )
        .args(["-t600", "saved duty"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command.spawn_serialized().expect("driver");
    for _ in 0..3 {
        await_capacity_boundary(&listener)
            .write_all(b"r")
            .expect("release earlier retry");
    }
    let mut channel = await_capacity_boundary(&listener);
    let events = fs::read(run_dir.join("events.jsonl")).expect("fourth attempt events");
    assert_eq!(
        String::from_utf8_lossy(&events)
            .matches("thread.started")
            .count(),
        4
    );
    let argv = harness.read("argv");
    assert!(
        Command::new("kill")
            .args(["-TERM", &driver.id().to_string()])
            .status_serialized()
            .expect("signal driver")
            .success()
    );
    channel
        .write_all(b"s")
        .expect("await signal before releasing boundary");
    let result = driver.wait_with_output().expect("completion");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        fs::read_to_string(run_dir.join("capacity-attempts.txt")).expect("capacity evidence"),
        "attempt=1 result=model-at-capacity retry_in=60s\nattempt=1 waited=60s\nattempt=2 result=model-at-capacity retry_in=120s\nattempt=2 waited=120s\nattempt=3 result=model-at-capacity retry_in=240s\nattempt=3 waited=240s\nattempt=4 result=model-at-capacity; bound-reached\ncapacity_attempts=4 capacity_waits=60,120,240s\n"
    );
    assert_eq!(
        fs::read(run_dir.join("events.jsonl")).expect("final events"),
        events
    );
    assert_eq!(harness.read("argv"), argv);
    assert!(String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=4"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("attempt 4/4; retry"));
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:capacity-resume-keeps-the-current-step-and-archives-prior-attempts´
#[test]
fn capacity_resume_keeps_the_current_step_and_archives_prior_attempts() {
    let harness = Harness::new("capacity-resume");
    let run_dir = harness.seed_resume("resume", b"0\n");
    fs::write(run_dir.join("capacity-attempts.txt"), b"prior attempts\n")
        .expect("old capacity evidence");
    let result = output(
        harness
            .command()
            .env("ORACLE_MODE", "capacity-then-ok")
            .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker")),
        &[
            OsStr::new("-t"),
            OsStr::new("600"),
            OsStr::new("-r"),
            OsStr::new("session-1"),
            OsStr::new("-d"),
            run_dir.as_os_str(),
            OsStr::new("-n"),
            OsStr::new("work"),
            OsStr::new("current duty"),
        ],
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(harness.read("stdin"), b"current duty\n");
    assert!(harness.read("argv").ends_with(b"resume\nsession-1\n-\n"));
    assert_eq!(
        fs::read(run_dir.join(".step-name")).expect("step"),
        b"work\n"
    );
    assert_eq!(
        fs::read(run_dir.join("steps/gate/capacity-attempts.txt")).expect("prior attempts"),
        b"prior attempts\n"
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("lane=work"));
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:capacity-tail-survives-an-attempt-larger-than-one-mib´
#[test]
fn capacity_tail_survives_an_attempt_larger_than_one_mib() {
    let harness = Harness::new("capacity-large");
    let run_dir = harness.run_dir("lane");
    let result = output(
        harness
            .command()
            .env("ORACLE_MODE", "capacity-large-then-ok")
            .env("ORACLE_CAPACITY_MARKER", run_dir.join("capacity-marker")),
        &[
            OsStr::new("-t"),
            OsStr::new("600"),
            OsStr::new("saved message"),
        ],
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(
        fs::metadata(run_dir.join("events.jsonl"))
            .expect("events")
            .len()
            > 2_000_000
    );
    assert!(harness.read("argv").ends_with(b"resume\nsession-1\n-\n"));
    assert_eq!(harness.read("stdin"), b"saved message\n");
    assert!(String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=2"));
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:capacity-waits-never-spend-the-remaining-step-budget´
#[test]
fn capacity_waits_never_spend_the_remaining_step_budget() {
    for (budget, attempts, wall) in [("60", 1, 0), ("180", 2, 60), ("420", 3, 180)] {
        let harness = Harness::new("capacity-budget");
        let result = output(
            harness.command().env("ORACLE_MODE", "capacity-always"),
            &[
                OsStr::new("-t"),
                OsStr::new(budget),
                OsStr::new("saved message"),
            ],
        );
        assert_eq!(result.status.code(), Some(1));
        let report = String::from_utf8_lossy(&result.stdout);
        assert!(
            report.contains(&format!("capacity_attempts={attempts}")),
            "{report}"
        );
        assert!(report.contains(&format!("wall={wall}s")), "{report}");
        let record = fs::read_to_string(harness.run_dir("lane").join("capacity-attempts.txt"))
            .expect("capacity record");
        assert!(
            record.contains("model-at-capacity; budget-exhausted"),
            "{record}"
        );
    }
}

/// # Panics
/// Panics only if fixture setup fails or the asserted retry contract is violated.
/// ´test:integration:capacity-without-a-thread-never-starts-a-fresh-retry´
#[test]
fn capacity_without_a_thread_never_starts_a_fresh_retry() {
    let harness = Harness::new("capacity-no-thread");
    let result = output(
        harness.command().env("ORACLE_MODE", "capacity-no-thread"),
        &[
            OsStr::new("-t"),
            OsStr::new("600"),
            OsStr::new("saved message"),
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    let record = fs::read_to_string(harness.run_dir("lane").join("capacity-attempts.txt"))
        .expect("capacity record");
    assert!(record.contains("attempt=1 result=model-at-capacity; thread-unavailable"));
    assert!(String::from_utf8_lossy(&result.stdout).contains("capacity_attempts=1"));
}

/// ´test:integration:budget-expiry-leaves-codex-running-until-natural-completion´
#[test]
fn budget_expiry_leaves_codex_running_until_natural_completion() {
    let harness = Harness::new("budget-expiry");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "budget-wait")
        .env("CODEX_LANE_TEST_CLOCK", "0,131")
        .args([OsStr::new("-t"), OsStr::new("10"), OsStr::new("stall")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " state=stalled ");
    assert_monitor_line(
        &sidecar,
        "quiet=131s wall=131s event_size=0 boot=131s awake=131s",
        " budget=10s last_growth=0s state=stalled expired_wall=131s expired_event_size=0 expired_last_growth=0s expired_quiet=131s expired_state=stalled",
    );
    assert!(driver.try_wait().expect("live driver").is_none());
    assert!(!run_dir.join("kill-evidence.txt").exists());
    fs::write(harness.root().join("release"), b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");
    assert_eq!(result.status.code(), Some(0));
    let expected =
        b"RUN-REPORT lane=lane exit=0 wall=Ns budget=10s verdict=OVER-BUDGET dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
    assert_eq!(
        normalize(
            &harness,
            &run_dir,
            &fs::read(run_dir.join("run-report.txt")).expect("read natural report")
        ),
        expected
    );
    assert!(run_dir.join("thread-id.txt").exists());
}

/// ´test:integration:budget-expiry-latch-keeps-first-reading-after-state-changes´
#[test]
fn budget_expiry_latch_keeps_first_reading_after_state_changes() {
    let harness = Harness::new("budget-latch");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "budget-wait")
        .env("CODEX_LANE_TEST_CLOCK", "0,11,131")
        .args(["-t", "10", "-n", "lane", "stall"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " state=stalled ");
    assert_monitor_line(
        &sidecar,
        "quiet=131s wall=131s event_size=0 boot=131s awake=131s",
        " budget=10s last_growth=0s state=stalled expired_wall=11s expired_event_size=0 expired_last_growth=0s expired_quiet=11s expired_state=growing",
    );
    assert!(driver.try_wait().expect("live driver").is_none());
    fs::write(harness.root().join("release"), b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("verdict=OVER-BUDGET"));
}

/// ´test:integration:an-approved-run-is-runaway-state-without-a-signal´
#[test]
fn an_approved_run_is_runaway_state_without_a_signal() {
    let harness = Harness::new("gateway-in-flight");
    let gateway = harness.seed_gateway(false);
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("LANE_GATEWAY_STATE", &gateway)
        .env("ORACLE_MODE", "budget-wait")
        .env("CODEX_LANE_TEST_CLOCK", "0,131")
        .args([
            OsStr::new("-C"),
            harness.worktree().as_os_str(),
            OsStr::new("--gateway-lane"),
            OsStr::new("gw"),
            OsStr::new("-t"),
            OsStr::new("10"),
            OsStr::new("stall"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn gateway driver");
    let sidecar = await_monitor(&run_dir, " state=runaway ");
    assert_monitor_line(
        &sidecar,
        "quiet=0s wall=131s event_size=0 boot=131s awake=131s awaiting=gw:7",
        " budget=10s last_growth=0s state=runaway expired_wall=131s expired_event_size=0 expired_last_growth=0s expired_quiet=0s expired_state=runaway",
    );
    assert!(driver.try_wait().expect("live driver").is_none());
    fs::write(harness.root().join("release"), b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("verdict=OVER-BUDGET"));
}

/// ´test:integration:an-audited-result-or-an-open-proposal-is-stalled-state´
#[test]
fn an_audited_result_or_an_open_proposal_is_stalled_state() {
    for (label, audited, open) in [("audited", true, false), ("open", false, true)] {
        let harness = Harness::new(label);
        let gateway = harness.seed_gateway(audited);
        if open {
            fs::remove_file(gateway.join("proposal-verdicts/gw/7.json"))
                .expect("leave proposal open");
        }
        let run_dir = harness.run_dir("lane");
        let mut command = harness.command();
        command
            .env("LANE_GATEWAY_STATE", &gateway)
            .env("ORACLE_MODE", "budget-wait")
            .env("CODEX_LANE_TEST_CLOCK", "0,131")
            .args([
                OsStr::new("-C"),
                harness.worktree().as_os_str(),
                OsStr::new("--gateway-lane"),
                OsStr::new("gw"),
                OsStr::new("-t"),
                OsStr::new("10"),
                OsStr::new("stall"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut driver = command.spawn_serialized().expect("spawn gateway driver");
        let sidecar = await_monitor(&run_dir, " state=stalled ");
        assert_monitor_line(
            &sidecar,
            "quiet=131s wall=131s event_size=0 boot=131s awake=131s",
            " budget=10s last_growth=0s state=stalled expired_wall=131s expired_event_size=0 expired_last_growth=0s expired_quiet=131s expired_state=stalled",
        );
        assert!(driver.try_wait().expect("live driver").is_none(), "{label}");
        fs::write(harness.root().join("release"), b"").expect("release child");
        let result = driver.wait_with_output().expect("natural completion");
        assert_eq!(result.status.code(), Some(0), "{label}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("verdict=OVER-BUDGET"));
    }
}

/// ´test:integration:runaway-is-a-live-state-without-a-signal´
#[test]
fn runaway_is_a_live_state_without_a_signal() {
    let harness = Harness::new("runaway");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "budget-wait")
        .env("CODEX_LANE_TEST_CLOCK", "0,5")
        .args([OsStr::new("-t"), OsStr::new("1"), OsStr::new("runaway")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " state=runaway ");
    assert!(sidecar.contains("expired_wall=5s"));
    assert!(driver.try_wait().expect("live driver").is_none());
    fs::write(harness.root().join("release"), b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("verdict=OVER-BUDGET"));
}

/// ´test:integration:codex-a-finished-turn-can-idle-past-budget-and-exit-naturally´
#[test]
fn codex_a_finished_turn_can_idle_past_budget_and_exit_naturally() {
    let harness = Harness::new("result-seen");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "completed-then-idle")
        .env("CODEX_LANE_TEST_CLOCK", "")
        .args([OsStr::new("-t"), OsStr::new("1"), OsStr::new("idle")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " expired_wall=");
    assert!(sidecar.contains("expired_state="));
    assert!(driver.try_wait().expect("live driver").is_none());
    fs::write(harness.root().join("release"), b"").expect("release child");
    let result = driver.wait_with_output().expect("natural completion");

    assert_eq!(result.status.code(), Some(0));
    let expected =
        b"RUN-REPORT lane=lane exit=0 wall=Ns budget=1s verdict=OVER-BUDGET dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
    assert_eq!(
        normalize(
            &harness,
            &run_dir,
            &fs::read(run_dir.join("run-report.txt")).expect("read the published report")
        ),
        expected
    );
    assert!(!run_dir.join("kill-evidence.txt").exists());
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("read the finished message"),
        b"final answer"
    );
}

/// ´test:integration:a-finished-codex-child-stopped-after-budget-keeps-its-result-and-message´
#[test]
fn a_finished_codex_child_stopped_after_budget_keeps_its_result_and_message() {
    let harness = Harness::new("result-idle-signal");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "completed-then-idle")
        .env("CODEX_LANE_TEST_CLOCK", "0,131")
        .args(["-t", "10", "-n", "lane", "idle"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut driver = command.spawn_serialized().expect("spawn driver");
    let sidecar = await_monitor(&run_dir, " expired_wall=");
    assert!(sidecar.contains("wall=131s"));
    let started = Instant::now();
    while !fs::read_to_string(run_dir.join("events.jsonl"))
        .is_ok_and(|events| events.contains("\"type\":\"turn.completed\""))
    {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "terminal result absent"
        );
        std::thread::yield_now();
    }
    assert!(driver.try_wait().expect("live driver").is_none());
    signal_process(driver.id(), "TERM");
    let result = driver.wait_with_output().expect("stopped driver");
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("verdict=OVER-BUDGET"));
    assert_eq!(
        fs::read(run_dir.join("last-message.txt")).expect("settled message"),
        b"final answer"
    );
}

/// A driver asked to stop takes its child with it.
/// ´test:integration:codex-a-driver-asked-to-stop-takes-its-child-with-it´
#[test]
fn codex_a_driver_asked_to_stop_takes_its_child_with_it() {
    let harness = Harness::new("forwarded-signal");
    let run_dir = harness.run_dir("lane");
    let child_record = harness.root().join("child-pid");
    let mut command = harness.command();
    command
        .env("ORACLE_MODE", "hang")
        .env("ORACLE_PID", &child_record)
        .env("CODEX_LANE_TEST_CLOCK", "0")
        .args([OsStr::new("-t"), OsStr::new("10"), OsStr::new("signal")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let driver = command
        .spawn_serialized()
        .expect("codex-lane subprocess runs");
    let child = await_pid(&child_record);
    signal_process(driver.id(), "TERM");
    let result = driver
        .wait_with_output()
        .expect("codex-lane subprocess ends");

    assert_eq!(result.status.code(), Some(1));
    let expected = b"RUN-REPORT lane=lane exit=1 wall=Ns budget=10s verdict=FAILED dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
    assert!(
        !Path::new("/proc").join(child.to_string()).exists(),
        "child pid {child} outlived the driver it was spawned by"
    );
    assert!(!run_dir.join("kill-evidence.txt").exists());
}

/// A lock whose child is alive refuses recovery.
/// ´test:integration:codex-a-lock-whose-child-is-alive-refuses-recovery´
#[test]
fn codex_a_lock_whose_child_is_alive_refuses_recovery() {
    let harness = Harness::new("live-child-lock");
    let run_dir = harness.seed_resume("run", b"0\n");
    let lock = run_dir.join(".codex-lane.lock");
    let dead_driver = u32::MAX;
    let live_child = std::process::id();
    assert!(!Path::new("/proc").join(dead_driver.to_string()).exists());
    fs::remove_file(run_dir.join("run-report.txt")).expect("remove interrupted report");
    fs::write(&lock, format!("{dead_driver}\n{live_child}\n")).expect("seed live-child lock");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_live_lock: holder pid {live_child} is still live: {}\n",
            lock.display()
        )
        .as_bytes(),
    );
    assert!(lock.exists(), "a live lock is never cleared");
    assert!(
        !run_dir.join("run-report.txt").exists(),
        "a live child was given a CRASHED report"
    );
}

/// The identity of the child the driver is supervising, as the child states it.
fn await_pid(path: &Path) -> u32 {
    let started = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(path)
            && let Some(pid) = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the injected child never recorded its identity"
        );
        std::thread::yield_now();
    }
}

fn await_monitor(run_dir: &Path, expected: &str) -> String {
    let started = Instant::now();
    loop {
        if let Ok(entries) = fs::read_dir(run_dir) {
            for entry in entries.filter_map(Result::ok) {
                if entry.file_name().to_string_lossy().starts_with(".monitor-")
                    && let Ok(sidecar) = fs::read_to_string(entry.path())
                    && sidecar.contains(expected)
                {
                    return sidecar;
                }
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "monitor never published {expected}"
        );
        std::thread::yield_now();
    }
}

fn assert_monitor_line(line: &str, accounting: &str, suffix: &str) {
    let head = format!(
        "{accounting} context_state=unknown context_used=unknown context_window=unknown context_fraction=unknown context_source=none context_reason=no-turn context_turn=0 context_at="
    );
    let at = line
        .strip_prefix(&head)
        .and_then(|rest| rest.strip_suffix(&format!("{suffix}\n")))
        .expect("whole monitor line");
    assert_eq!(at.len(), 20);
    for (index, byte) in at.bytes().enumerate() {
        if [4, 7].contains(&index) {
            assert_eq!(byte, b'-');
        } else if index == 10 {
            assert_eq!(byte, b'T');
        } else if [13, 16].contains(&index) {
            assert_eq!(byte, b':');
        } else if index == 19 {
            assert_eq!(byte, b'Z');
        } else {
            assert!(byte.is_ascii_digit());
        }
    }
    assert_eq!(line, format!("{head}{at}{suffix}\n"));
}

/// Ask a process to stop, through the shell's own signal command.
fn signal_process(pid: u32, signal: &str) {
    let status = Command::new("/bin/sh")
        .args(["-c", &format!("kill -{signal} {pid}")])
        .status_serialized()
        .expect("signal the driver");
    assert!(status.success(), "signal delivery failed");
}

fn assert_usage(harness: &Harness, arguments: &[&OsStr], budget: u64) {
    let result = harness.run(arguments);
    let report = format!(
        "RUN-REPORT lane=unknown exit=2 wall=0s budget={budget}s verdict=FAILED dir=unknown\n"
    );
    let mut expected = USAGE_DIAGNOSTIC.to_vec();
    expected.extend_from_slice(report.as_bytes());
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert_eq!(result.stdout, expected);
    assert_final_report(&result.stdout, report.as_bytes());
}

fn assert_resume_refusal(
    harness: &Harness,
    run_dir: &Path,
    session: &str,
    expected_diagnostic: &[u8],
) {
    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new(session),
        OsStr::new("-d"),
        argument(run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("prompt"),
    ]);
    let report = b"RUN-REPORT lane=unknown exit=2 wall=0s budget=60s verdict=FAILED dir=unknown\n";
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(result.stderr, expected_diagnostic);
    assert_eq!(result.stdout, report);
    assert_final_report(&result.stdout, report);
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
}

/// Usage errors return status two and a final report.
/// ´test:integration:usage-error-matrix-returns-two-and-a-final-report´
#[test]
fn usage_error_matrix_returns_two_and_a_final_report() {
    for (label, arguments, budget) in [
        ("missing-budget", vec![OsStr::new("prompt")], 0),
        (
            "zero-budget",
            vec![OsStr::new("-t"), OsStr::new("0"), OsStr::new("prompt")],
            0,
        ),
        (
            "missing-prompt",
            vec![OsStr::new("-t"), OsStr::new("60")],
            60,
        ),
        (
            "extra-prompt",
            vec![
                OsStr::new("-t"),
                OsStr::new("60"),
                OsStr::new("one"),
                OsStr::new("two"),
            ],
            60,
        ),
        (
            "bad-sandbox",
            vec![
                OsStr::new("-t"),
                OsStr::new("60"),
                OsStr::new("-s"),
                OsStr::new("unsafe"),
                OsStr::new("prompt"),
            ],
            60,
        ),
        (
            "bad-name",
            vec![
                OsStr::new("-t"),
                OsStr::new("60"),
                OsStr::new("-n"),
                OsStr::new("bad name"),
                OsStr::new("prompt"),
            ],
            60,
        ),
        (
            "resume-without-dir",
            vec![
                OsStr::new("-t"),
                OsStr::new("60"),
                OsStr::new("-r"),
                OsStr::new("session-1"),
                OsStr::new("prompt"),
            ],
            60,
        ),
        (
            "unknown-option",
            vec![
                OsStr::new("-t"),
                OsStr::new("60"),
                OsStr::new("-Z"),
                OsStr::new("prompt"),
            ],
            60,
        ),
    ] {
        let harness = Harness::new(label);
        assert_usage(&harness, &arguments, budget);
    }
}

/// Retired pure mode refuses resumed steps without creating a home or starting a child.
/// # Panics
/// Panics only if fixture setup or the refusal contract fails.
/// ´test:integration:retired-pure-resume-refuses-without-creating-home-or-starting-child´
#[test]
fn retired_pure_resume_refuses_without_creating_home_or_starting_child() {
    let harness = Harness::new("pure-resume");
    let run_dir = harness.seed_resume("run", b"0\n");
    let result = harness
        .resume_command()
        .args(["-Pt60", "-r", "session-1", "-d"])
        .arg(&run_dir)
        .args(["-n", "work", "prompt"])
        .output()
        .expect("pure resume");
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(result.stdout.starts_with(USAGE_DIAGNOSTIC));
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
    assert!(!harness.home().join(".codex-pure").exists());
    let report = fs::read(run_dir.join("run-report.txt")).expect("pure refusal report");
    assert_eq!(report, result.stdout[USAGE_DIAGNOSTIC.len()..]);
}

/// # Panics
/// Panics only if a fresh or resumed driver starts without an explicit Codex home.
/// ´test:integration:codex-start-and-resume-refuse-missing-home´
#[test]
fn codex_start_and_resume_refuse_missing_home() {
    for resume in [false, true] {
        for empty in [false, true] {
            let harness = Harness::new("missing-codex-home");
            let mut command = if resume {
                harness.resume_command()
            } else {
                harness.command()
            };
            command.args(["-t60"]);
            if resume {
                let run = harness.seed_resume("run", b"0\n");
                command
                    .args(["-r", "session-1", "-d"])
                    .arg(run)
                    .args(["-n", "work"]);
            }
            command.arg("prompt").env_remove("CODEX_HOME");
            if empty {
                command.env("CODEX_HOME", "");
            }
            let result = command.output().expect("missing home refusal");
            assert!(!result.status.success());
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("CODEX_HOME is required"),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
            assert_eq!(harness.read("argv"), Vec::<u8>::new());
            assert!(!harness.home().join(".codex-pure").exists());
        }
    }
}

/// Retired pure mode refuses without creating a home or starting a child.
/// ´test:integration:retired-pure-mode-refuses-without-creating-home-or-starting-child´
#[test]
fn retired_pure_mode_refuses_without_creating_home_or_starting_child() {
    let harness = Harness::new("pure-retired");
    let result = harness.run(&[
        OsStr::new("-t60"),
        OsStr::new("-P"),
        OsStr::new("-npure"),
        OsStr::new("prompt"),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.starts_with(USAGE_DIAGNOSTIC));
    assert_eq!(harness.read("argv"), Vec::<u8>::new());
    assert!(!harness.home().join(".codex-pure").exists());
}

/// Marker publication is atomic.
/// ´test:integration:marker-publication-is-atomic´
#[test]
fn marker_publication_is_atomic() {
    let harness = Harness::new("atomic");
    let run_dir = harness.run_dir("lane");
    let barrier = harness.root().join("publish-release");
    let ready = harness.root().join("publish-release.ready");
    let mut command = harness.command();
    command
        .env("CODEX_LANE_TEST_REPORT_BARRIER", &barrier)
        .args(["-t", "60", "prompt"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn_serialized()
        .expect("spawn atomic publication case");
    let started = Instant::now();
    while !ready.exists() {
        assert!(
            started.elapsed().as_secs() < 10,
            "publication barrier was not reached"
        );
        std::thread::yield_now();
    }
    assert!(run_dir.exists());
    assert!(!run_dir.join("run-report.txt").exists());
    fs::write(&barrier, b"release\n").expect("release report publication");
    let result = child.wait_with_output().expect("wait atomic case");
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        fs::read(run_dir.join("run-report.txt")).expect("read atomic report"),
        result.stdout
    );
}

/// Every allocated run is live until its finished marker exists.
/// ´test:integration:every-allocated-run-is-live-until-a-finished-marker-exists´
#[test]
fn every_allocated_run_is_live_until_a_finished_marker_exists() {
    let harness = Harness::new("spawn-failure");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    harness.configure_backend(&mut command, &harness.root().join("missing-codex"));
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("prompt")],
    );

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(result.stdout.starts_with(RUNTIME_DIAGNOSTIC));
    let cause = format!(
        "spawn {}: No such file or directory",
        harness.root().join("missing-codex").display()
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains(&cause));
    assert!(
        String::from_utf8_lossy(&fs::read(run_dir.join("stderr.txt")).expect("step diagnostic"))
            .contains(&cause)
    );
    let report_start = result
        .stdout
        .windows(b"RUN-REPORT".len())
        .position(|part| part == b"RUN-REPORT")
        .expect("report start");
    assert_eq!(
        fs::read(run_dir.join("run-report.txt")).expect("read failure marker"),
        result.stdout[report_start..]
    );
    assert!(
        result
            .stdout
            .windows(b"verdict=FAILED".len())
            .any(|window| { window == b"verdict=FAILED" })
    );
}

/// # Panics
/// Panics only if fixture setup or the asserted boxed home and pool contract fails.
///
/// ´test:integration:boxed-codex-starts-without-host-home-and-retains-pool-record´
#[test]
fn boxed_codex_starts_without_host_home_and_retains_pool_record() {
    let harness = Harness::new("boxed-no-host-home");
    let mut command = harness.command();
    suspend_helper_runtime(&harness, &mut command);
    command.env_remove("CODEX_HOME");
    let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("prompt")]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        harness.read("codex-home"),
        format!("{}\n", harness.home().join(".codex").display()).as_bytes()
    );
    assert_ne!(harness.read("argv"), Vec::<u8>::new());
    fs::remove_file(harness.root().join("argv")).expect("clear child evidence");
    fs::write(
        harness.home().join(".codex/lane-pool.json"),
        br#"{"status":"rejected","observed_at":1,"resets_at":4102444800}"#,
    )
    .expect("boxed pool record");
    let mut command = harness.command();
    suspend_helper_runtime(&harness, &mut command);
    command.env_remove("CODEX_HOME");
    let result = output(&mut command, &[OsStr::new("-t60"), OsStr::new("prompt")]);
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("dispatch_rate_limited"),
        "{result:?}"
    );
    assert!(!harness.root().join("argv").exists());
}

/// ´test:integration:unreadable-boxed-runtime-file-names-the-file´
#[test]
fn unreadable_boxed_runtime_file_names_the_file() {
    let harness = Harness::new("unreadable-runtime");
    let runtime = harness.repo().join("runs/box/launch");
    fs::create_dir_all(&runtime).expect("runtime directory");
    let path = runtime.join("runtime.argv");
    fs::write(&path, b"/usr/bin/podman\0").expect("runtime file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("restrict runtime file");
    let mut command = harness.command();
    Harness::configure_boxed(&mut command);
    command.env("LANE_RUN_DIR", runtime.parent().expect("box directory"));
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("prompt")],
    );
    assert_eq!(result.status.code(), Some(1));
    let diagnostic = String::from_utf8_lossy(&result.stdout);
    assert!(
        diagnostic.contains(&format!("runtime argv {}", path.display())),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("Permission denied"), "{diagnostic}");
}

/// An undeclared child status maps to the shared failure.
/// ´test:integration:undeclared-child-status-is-mapped-to-shared-failure´
#[test]
fn undeclared_child_status_is_mapped_to_shared_failure() {
    let harness = Harness::new("child-seven");
    let run_dir = harness.run_dir("lane");
    let mut command = harness.command();
    command.env("ORACLE_MODE", "fail").env("ORACLE_EXIT", "7");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("prompt")],
    );

    assert_eq!(result.status.code(), Some(1));
    let expected = b"RUN-REPORT lane=lane exit=1 wall=Ns budget=60s verdict=FAILED dir=$RUN_DIR\n";
    assert_eq!(normalize(&harness, &run_dir, &result.stdout), expected);
}

/// Two fresh launches under the pinned UTC stamp own separate evidence.
/// ´test:integration:two-codex-fresh-launches-in-one-second-own-separate-runs´
#[test]
fn two_codex_fresh_launches_in_one_second_own_separate_runs() {
    let harness = Harness::new("collision");
    let first_dir = harness.run_dir("lane");
    let second_dir = first_dir.with_file_name("20260828T120000Z-lane-2");
    let first = harness.run(&[OsStr::new("-t"), OsStr::new("60"), OsStr::new("first")]);
    assert_eq!(first.status.code(), Some(0));
    assert!(first_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&first.stdout)
            .contains(&format!(" dir={} backend_program=", first_dir.display()))
    );
    let prior = fs::read(first_dir.join("brief.txt")).expect("read first brief");
    assert_eq!(prior, b"first\n");
    let second = harness.run(&[OsStr::new("-t"), OsStr::new("60"), OsStr::new("second")]);
    assert_eq!(second.status.code(), Some(0));
    assert!(second_dir.is_dir());
    assert!(
        String::from_utf8_lossy(&second.stdout)
            .contains(&format!(" dir={} backend_program=", second_dir.display()))
    );
    assert_eq!(
        fs::read(first_dir.join("brief.txt")).expect("reread first brief"),
        prior
    );
    assert_eq!(
        fs::read(second_dir.join("brief.txt")).expect("read second brief"),
        b"second\n"
    );
}

/// A resume refusal names the missing prior report.
/// ´test:integration:resume-refusal-names-missing-prior-report´
#[test]
fn resume_refusal_names_missing_prior_report() {
    let harness = Harness::new("missing-report");
    let run_dir = harness.seed_resume("run", b"0\n");
    let report = run_dir.join("run-report.txt");
    fs::remove_file(&report).expect("remove prior report");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_missing_report: prior step report is missing: {}\n",
            report.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names existing step input.
/// ´test:integration:resume-refusal-names-existing-step-input´
#[test]
fn resume_refusal_names_existing_step_input() {
    let harness = Harness::new("step-input-collision");
    let run_dir = harness.seed_resume("run", b"0\n");
    let collision = run_dir.join("step-work.txt");
    fs::write(&collision, b"prior\n").expect("seed duplicate input");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_step_collision: step name is already used: {}\n",
            collision.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names existing step history.
/// ´test:integration:resume-refusal-names-existing-step-history´
#[test]
fn resume_refusal_names_existing_step_history() {
    let harness = Harness::new("step-history-collision");
    let run_dir = harness.seed_resume("run", b"0\n");
    let collision = run_dir.join("steps/work");
    fs::create_dir_all(&collision).expect("seed duplicate history");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_step_collision: step name is already used: {}\n",
            collision.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names a live lock.
/// ´test:integration:resume-refusal-names-live-lock´
#[test]
fn resume_refusal_names_live_lock() {
    let harness = Harness::new("live-lock");
    let run_dir = harness.seed_resume("run", b"0\n");
    let lock = run_dir.join(".codex-lane.lock");
    let mut holder = Command::new("sleep")
        .arg("30")
        .spawn_serialized()
        .expect("spawn live lock holder");
    let pid = holder.id();
    fs::write(&lock, format!("{pid}\n")).expect("seed live lock");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_live_lock: holder pid {pid} is still live: {}\n",
            lock.display()
        )
        .as_bytes(),
    );
    holder.kill().expect("kill live lock holder");
    holder.wait().expect("reap live lock holder");
}

/// Resume recovers a dead pid lock and archives the crash.
/// ´test:integration:resume-recovers-dead-pid-lock-and-archives-crash´
#[test]
fn resume_recovers_dead_pid_lock_and_archives_crash() {
    let harness = Harness::new("dead-lock");
    let run_dir = harness.seed_resume("run", b"0\n");
    let lock = run_dir.join(".codex-lane.lock");
    let dead_pid = u32::MAX;
    assert!(!Path::new("/proc").join(dead_pid.to_string()).exists());
    fs::remove_file(run_dir.join("run-report.txt")).expect("remove interrupted report");
    fs::write(&lock, format!("{dead_pid}\n")).expect("seed dead lock");

    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("work"),
        OsStr::new("PROCEED"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(
        result.stderr,
        format!(
            "codex-lane: resume_crash_recovered: wrote a CRASHED report for dead holder pid {dead_pid} and cleared lock: {}\n",
            lock.display()
        )
        .as_bytes()
    );
    assert!(!lock.exists());
    assert_eq!(
        fs::read(run_dir.join("steps/gate/run-report.txt")).expect("read archived crash report"),
        format!(
            "RUN-REPORT lane=gate exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid={dead_pid} dir={}\n",
            run_dir.display()
        )
        .as_bytes()
    );
}

/// Resume treats a recycled pid as live.
/// ´test:integration:resume-treats-recycled-pid-as-live´
#[test]
fn resume_treats_recycled_pid_as_live() {
    let harness = Harness::new("recycled-lock");
    let run_dir = harness.seed_resume("run", b"0\n");
    let lock = run_dir.join(".codex-lane.lock");
    let recycled_pid = std::process::id();
    fs::write(&lock, format!("{recycled_pid}\n")).expect("seed recycled pid lock");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_live_lock: holder pid {recycled_pid} is still live: {}\n",
            lock.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names the missing event stream.
/// ´test:integration:resume-refusal-names-missing-event-stream´
#[test]
fn resume_refusal_names_missing_event_stream() {
    let harness = Harness::new("missing-events");
    let run_dir = harness.seed_resume("run", b"0\n");
    let events = run_dir.join("events.jsonl");
    fs::remove_file(&events).expect("remove event stream");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_thread_mismatch: event stream is missing: {}\n",
            events.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names the unreadable event stream.
/// ´test:integration:resume-refusal-names-unreadable-event-stream´
#[test]
fn resume_refusal_names_unreadable_event_stream() {
    let harness = Harness::new("unreadable-events");
    let run_dir = harness.seed_resume("run", b"0\n");
    let events = run_dir.join("events.jsonl");
    fs::remove_file(&events).expect("remove readable event stream");
    fs::create_dir(&events).expect("replace event stream with unreadable directory");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_thread_mismatch: event stream is unreadable: {}\n",
            events.display()
        )
        .as_bytes(),
    );
}

/// A resume refusal names a thread mismatch.
/// ´test:integration:resume-refusal-names-thread-mismatch´
#[test]
fn resume_refusal_names_thread_mismatch() {
    let harness = Harness::new("thread-mismatch");
    let run_dir = harness.seed_resume("run", b"0\n");
    let events = run_dir.join("events.jsonl");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "wrong-session",
        format!(
            "codex-lane: resume_thread_mismatch: first thread id does not match resume session: {}\n",
            events.display()
        )
        .as_bytes(),
    );
}

/// A Codex resume refuses an id file that disagrees with its matched events.
/// ´test:integration:a-codex-resume-refuses-a-conflicting-thread-id-file´
#[test]
fn a_codex_resume_refuses_a_conflicting_thread_id_file() {
    let harness = Harness::new("conflicting-thread-id");
    let run_dir = harness.seed_resume("run", b"0\n");
    let thread_path = run_dir.join("thread-id.txt");
    fs::write(&thread_path, b"other-session\n").expect("seed conflicting thread id");

    assert_resume_refusal(
        &harness,
        &run_dir,
        "session-1",
        format!(
            "codex-lane: resume_thread_mismatch: first thread id does not match resume session: {}\n",
            thread_path.display()
        )
        .as_bytes(),
    );
    assert_eq!(
        fs::read(&thread_path).expect("read unchanged thread id"),
        b"other-session\n"
    );
}

/// Custom exec flags precede the resume subcommand.
/// ´test:integration:custom-exec-flags-precede-resume-subcommand´
#[test]
fn custom_exec_flags_precede_resume_subcommand() {
    let harness = Harness::new("resume-order");
    let run_dir = harness.seed_resume("run", b"0\n");
    let result = harness.run(&[
        OsStr::new("-t"),
        OsStr::new("60"),
        OsStr::new("-C"),
        argument(harness.worktree()),
        OsStr::new("-s"),
        OsStr::new("read-only"),
        OsStr::new("-m"),
        OsStr::new("model-x"),
        OsStr::new("-e"),
        OsStr::new("high"),
        OsStr::new("-r"),
        OsStr::new("session-1"),
        OsStr::new("-d"),
        argument(&run_dir),
        OsStr::new("-n"),
        OsStr::new("verify"),
        OsStr::new("message"),
    ]);

    assert_eq!(result.status.code(), Some(0));
    let argv = String::from_utf8(harness.read("argv")).expect("UTF-8 argv");
    let lines = argv.lines().collect::<Vec<_>>();
    let resume = lines
        .iter()
        .position(|line| *line == "resume")
        .expect("resume argument");
    let model = lines
        .iter()
        .position(|line| *line == "-m")
        .expect("model argument");
    let effort = lines
        .iter()
        .position(|line| *line == "model_reasoning_effort=high")
        .expect("effort argument");
    assert!(model < resume);
    assert!(effort < resume);
    assert_eq!(lines[resume + 1], "session-1");
    assert_eq!(lines.last(), Some(&"-"));
}

/// A panic before argument handling is suppressed and reported.
/// ´test:integration:panic-before-argument-handling-is-suppressed-and-reported´
#[test]
fn panic_before_argument_handling_is_suppressed_and_reported() {
    let harness = Harness::new("panic-before-parse");
    let mut command = harness.command();
    command.env("CODEX_LANE_TEST_PANIC", "seeded-secret");
    let result = output(&mut command, &[]);

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(result.stdout.starts_with(INTERNAL_DIAGNOSTIC));
    assert!(
        !result
            .stdout
            .windows(b"seeded-secret".len())
            .any(|window| window == b"seeded-secret")
    );
    let report = b"RUN-REPORT lane=unknown exit=1 wall=0s budget=0s verdict=FAILED dir=unknown\n";
    assert_final_report(&result.stdout, report);
}

/// A panic after argument handling is suppressed and reported.
/// ´test:integration:panic-after-argument-handling-is-suppressed-and-reported´
#[test]
fn panic_after_argument_handling_is_suppressed_and_reported() {
    let harness = Harness::new("panic-after-parse");
    let mut command = harness.command();
    command.env("CODEX_LANE_TEST_PANIC_AFTER_PARSE", "seeded-secret");
    let result = output(
        &mut command,
        &[OsStr::new("-t"), OsStr::new("60"), OsStr::new("prompt")],
    );

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stderr, Vec::<u8>::new());
    assert!(result.stdout.starts_with(INTERNAL_DIAGNOSTIC));
    let report = b"RUN-REPORT lane=unknown exit=1 wall=0s budget=0s verdict=FAILED dir=unknown\n";
    assert_final_report(&result.stdout, report);
}
///
/// # Panics
/// Panics only if the binary cannot run or omits the required usage evidence.
/// ´test:integration:relative-resume-directory-refusal-names-option-value-and-form´
#[test]
fn relative_resume_directory_refusal_names_option_value_and_form() {
    for options in [
        vec!["-d", "run-name"],
        vec!["-drun-name"],
        vec!["-Pd", "run-name"],
        vec!["-d"],
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command.args([
            "driver",
            "resume",
            "--backend",
            "codex",
            "-t",
            "1",
            "-r",
            "session",
        ]);
        command.args(&options);
        if options != ["-d"] {
            command.arg("prompt");
        }
        let output = command.output().expect("usage refusal");
        assert_eq!(output.status.code(), Some(2));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("usage_error: -d received"), "{error}");
        assert!(
            error.contains("expected an absolute existing run directory"),
            "{error}"
        );
        assert!(error.contains(if options == ["-d"] {
            "no value"
        } else {
            "run-name"
        }));
    }
}
