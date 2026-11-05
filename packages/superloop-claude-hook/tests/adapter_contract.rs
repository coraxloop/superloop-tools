use std::fmt::Write as _;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Value, json};

const ALLOW: &str = "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}\n";
const DENY: &str = "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"fixture denial\"}}\n";
const LETTERS: &str = "You've got mail.";
const RULEBOOK: &str = "ORCHESTRATION_SCOPE_MARKER v1 sha256=6ac9f156a3b4475ed2731f61db1381590b153ce9897d108506c62dd5aa7707a5 mtime=1700000000123456789\n# Fixture rules\n\nKeep evidence exact.\nORCHESTRATION_SCOPE_MARKER_END v1 sha256=6ac9f156a3b4475ed2731f61db1381590b153ce9897d108506c62dd5aa7707a5";

struct Fixture {
    root: PathBuf,
    project: PathBuf,
    state: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("claude-adapter-{}-{label}", std::process::id()));
        fs::create_dir(&root).expect("unique fixture");
        let project = root.join("project");
        fs::create_dir_all(project.join(".git")).expect("project");
        fs::create_dir_all(root.join(".claude")).expect("instance directory");
        fs::write(root.join(".claude/permission-triage.env"), "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/state\nPERMISSION_TRIAGE_CLI=/fixture/cli\n").expect("instance");
        let helper = root.join(".local/libexec/superloop/hooks/permission-triage-hook");
        fs::create_dir_all(helper.parent().expect("helper parent")).expect("private hooks");
        fs::copy(
            std::env::current_exe().expect("fixture executable"),
            &helper,
        )
        .expect("ELF fixture");
        let state = root.join(".local/state/superloop-tools/hook");
        Self {
            root,
            project,
            state,
            helper,
        }
    }

    fn enabled(&self) {
        fs::create_dir_all(&self.state).expect("state");
        fs::write(
            self.state.join(format!(
                "heartbeat{}",
                self.project.to_string_lossy().replace('/', "-")
            )),
            "",
        )
        .expect("toggle");
    }

    fn payload(&self, event: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"hook_event_name":event,"cwd":self.project,"session_id":"fixture","source":"startup","tool_name":"ScheduleWakeup","transcript_path":self.root.join("transcript")})).expect("payload")
    }

    fn run(&self, command: &str, payload: &[u8], response: &str, code: &str) -> Output {
        self.run_fault(command, payload, response, code, "none")
    }

    fn run_fault(
        &self,
        command: &str,
        payload: &[u8],
        response: &str,
        code: &str,
        fault: &str,
    ) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_superloop-claude-hook"));
        process
            .arg(command)
            .env_clear()
            .env("HOME", &self.root)
            .env("PWD", &self.project)
            .env(
                "PERMISSION_TRIAGE_HOOK_BIN",
                self.root.join("redirected-helper"),
            )
            .env(
                "PERMISSION_TRIAGE_INSTANCE",
                self.root.join("redirected-instance"),
            )
            .env("FIXTURE_RESPONSE", response)
            .env("FIXTURE_CODE", code)
            .env("FIXTURE_CAPTURE", self.root.join("capture"))
            .env("ENTER_LOOP_REGISTRY", self.root.join("registry.toml"))
            .env("ORCHESTRATION_FILE", self.root.join("rulebook"))
            .env("PERMISSION_TRIAGE_ISOLATION", "inherited-must-be-cleared")
            .env("PERMISSION_TRIAGE_MODE", "enforce")
            .current_dir(&self.project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if fault == "panic" {
            process.env("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC", "1");
        }
        if fault == "unreadable" {
            process.stdin(fs::File::open(&self.root).expect("directory stdin"));
        }
        let mut child = process.spawn().expect("adapter");
        if let Some(mut stdin) = child.stdin.take()
            && let Err(error) = stdin.write_all(payload)
        {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().expect("adapter output")
    }

    fn contexts(&self, rulebook: bool, letters: bool) {
        if rulebook {
            fs::write(
                self.root.join("rulebook"),
                "# Fixture rules\n\nKeep evidence exact.\n",
            )
            .expect("rulebook");
            fs::File::open(self.root.join("rulebook"))
                .expect("rulebook file")
                .set_modified(UNIX_EPOCH + Duration::from_nanos(1_700_000_000_123_456_789))
                .expect("mtime");
        }
        if letters {
            fs::write(self.root.join("registry.toml"), "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\n[[loops]]\nname = \"alpha\"\nuid = 41001\nlaunch = \"project\"\n").expect("registry");
            fs::create_dir_all(self.root.join(".local/bin")).expect("entry directory");
            fs::copy(&self.helper, self.root.join(".local/bin/superloop")).expect("entry fixture");
        }
    }
}

fn input_faults_and_panics() {
    for (command, event) in [
        ("stop", "Stop"),
        ("pre-tool-use", "PreToolUse"),
        ("session-start", "SessionStart"),
        ("user-prompt-submit", "UserPromptSubmit"),
    ] {
        for fault in ["unreadable", "oversized", "panic"] {
            if fault == "panic" && !cfg!(debug_assertions) {
                continue;
            }
            let fixture = Fixture::new(&format!("fault-{command}-{fault}"));
            let payload = if fault == "oversized" {
                vec![b' '; 1_048_577]
            } else {
                fixture.payload(event)
            };
            let output = fixture.run_fault(command, &payload, ALLOW, "0", fault);
            assert_eq!(
                output.status.code(),
                Some(if event == "PreToolUse" { 2 } else { 0 }),
                "{command} {fault}"
            );
            assert!(!fixture.root.join("capture").exists());
            if event != "PreToolUse" {
                assert_eq!(output.stdout, b"");
                assert_eq!(output.stderr, b"");
                let log = fs::read_to_string(fixture.state.join("orchestrator.log"))
                    .expect("redacted fault record");
                assert!(
                    log.contains(if fault == "panic" { "Panic" } else { "Payload" }),
                    "{log}"
                );
                assert!(!log.contains("injected adapter panic"));
            }
        }
    }
}

fn runtime_environment_cannot_redirect_permission() {
    let fixture = Fixture::new("runtime-redirection");
    fs::write(fixture.root.join("redirected-instance"), "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/other\nPERMISSION_TRIAGE_CLI=/fixture/cli\n").expect("alternate instance");
    fs::copy(&fixture.helper, fixture.root.join("redirected-helper")).expect("alternate ELF");
    fs::remove_file(&fixture.helper).expect("remove configured helper");
    let output = fixture.run("pre-tool-use", &fixture.payload("PreToolUse"), ALLOW, "0");
    assert_eq!(output.status.code(), Some(2));
    assert!(!fixture.root.join("capture").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("hook binary missing"));
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fixture");
    }
}

fn helper() -> i32 {
    assert_eq!(
        std::env::var("PERMISSION_TRIAGE_MODE").expect("instance mode"),
        "audit"
    );
    assert!(std::env::var_os("PERMISSION_TRIAGE_ISOLATION").is_none());
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .expect("helper input");
    fs::write(std::env::var_os("FIXTURE_CAPTURE").expect("capture"), input).expect("capture input");
    std::io::stdout()
        .write_all(
            std::env::var("FIXTURE_RESPONSE")
                .expect("response")
                .as_bytes(),
        )
        .expect("helper response");
    std::env::var("FIXTURE_CODE")
        .expect("code")
        .parse()
        .expect("numeric code")
}

fn mismatch_has_no_effects() {
    for (command, event) in [
        ("stop", "Stop"),
        ("pre-tool-use", "PreToolUse"),
        ("session-start", "SessionStart"),
        ("user-prompt-submit", "UserPromptSubmit"),
    ] {
        let fixture = Fixture::new(command);
        let mut inputs = vec![
            b"{".to_vec(),
            b"{\"hook_event_name\":\"Other\"}".to_vec(),
            b"{}".to_vec(),
            b"{\"hook_event_name\":7}".to_vec(),
        ];
        for other in ["Stop", "PreToolUse", "SessionStart", "UserPromptSubmit"] {
            if event != other {
                inputs.push(fixture.payload(other));
            }
        }
        for input in inputs {
            let output = fixture.run(command, &input, ALLOW, "0");
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("hook-event-mismatch"));
            assert!(!fixture.state.exists());
            assert!(!fixture.root.join("capture").exists());
        }
    }
}

fn refusal_matrix() {
    for mode in ["off", "on", "prompted", "fail-open"] {
        for (name, response, code) in [
            ("allow", ALLOW, "0"),
            ("deny", DENY, "0"),
            ("audit", "", "0"),
            ("infrastructure", DENY, "2"),
            ("crash", "", "9"),
        ] {
            let fixture = Fixture::new(&format!("matrix-{mode}-{name}"));
            if matches!(mode, "on" | "prompted") {
                fixture.enabled();
            }
            if mode == "prompted" {
                fs::write(fixture.root.join("transcript"), "").expect("transcript");
                assert_eq!(
                    fixture
                        .run("stop", &fixture.payload("Stop"), "", "0")
                        .status
                        .code(),
                    Some(2)
                );
            }
            if mode == "fail-open" {
                fs::create_dir_all(fixture.state.parent().expect("state parent")).expect("parent");
                fs::write(&fixture.state, "unreadable state directory").expect("failed state");
            }
            let payload = fixture.payload("PreToolUse");
            let output = fixture.run("pre-tool-use", &payload, response, code);
            assert_eq!(
                fs::read(fixture.root.join("capture")).expect("both logic paths ran"),
                payload
            );
            if code != "0" || mode == "on" {
                assert_eq!(output.status.code(), Some(2), "{mode} {name}");
            } else if name == "deny" {
                assert_eq!(output.status.code(), Some(0));
                assert_eq!(output.stdout, DENY.as_bytes());
            } else if name == "allow" && mode == "off" {
                assert_eq!(output.status.code(), Some(0));
                let expected = json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"systemMessage":String::from_utf8_lossy(superloop_claude_hook::heartbeat::pre_tool::OFF_WARNING)});
                assert_eq!(
                    output.stdout,
                    format!(
                        "{}\n",
                        serde_json::to_string(&expected).expect("warning reply")
                    )
                    .as_bytes()
                );
            } else {
                assert_eq!(output.status.code(), Some(i32::from(mode == "off")));
                assert_eq!(output.stdout, response.as_bytes());
            }
            if mode == "on" && code == "0" {
                assert_eq!(
                    output.stderr,
                    superloop_claude_hook::heartbeat::pre_tool::REFUSAL_REASON
                );
                assert_eq!(output.stdout, [] as [u8; 0]);
            }
        }
    }
}

fn isolated_and_combined_contexts() {
    for (command, event) in [
        ("session-start", "SessionStart"),
        ("user-prompt-submit", "UserPromptSubmit"),
    ] {
        for (rulebook, letters) in [(true, false), (false, true), (true, true)] {
            let fixture = Fixture::new(&format!("context-{command}-{rulebook}-{letters}"));
            fixture.contexts(rulebook, letters);
            let output = fixture.run(command, &fixture.payload(event), "", "0");
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(output.stderr, [] as [u8; 0]);
            let expected = if rulebook {
                let text = if letters {
                    format!("{RULEBOOK}\n\n{LETTERS}")
                } else {
                    RULEBOOK.to_owned()
                };
                format!(
                    "{{\"hookSpecificOutput\":{{\"hookEventName\":\"{event}\",\"additionalContext\":{}}}}}",
                    serde_json::to_string(&text).expect("quoted context")
                )
            } else {
                format!(
                    "{{\"hookSpecificOutput\":{{\"additionalContext\":\"{LETTERS}\",\"hookEventName\":\"{event}\"}}}}"
                )
            };
            assert_eq!(
                output.stdout,
                expected.as_bytes(),
                "{command} {rulebook} {letters}"
            );
        }
    }
}

fn isolated_stop_and_permission() {
    let fixture = Fixture::new("stop");
    let silent = fixture.run("stop", &fixture.payload("Stop"), "", "0");
    assert_eq!(silent.status.code(), Some(0));
    assert_eq!(silent.stdout, [] as [u8; 0]);
    assert_eq!(silent.stderr, [] as [u8; 0]);
    fixture.enabled();
    fs::write(fixture.root.join("transcript"), "").expect("transcript");
    let stop = fixture.run("stop", &fixture.payload("Stop"), "", "0");
    assert_eq!(stop.status.code(), Some(2));
    assert_eq!(stop.stdout, [] as [u8; 0]);
    assert_eq!(stop.stderr, b"HEARTBEAT GUARD: no wakeup is currently armed and the heartbeat toggle is ON. did you use ListAgents, are all your watchers happy? Please set the ScheduleWakeup now (the turn then ends naturally on its result), or - if this turn genuinely ends blocked on the user with nothing in flight - run `superloop heartbeat off` first, then end the turn.");
    let mut payload: Value =
        serde_json::from_slice(&fixture.payload("PreToolUse")).expect("payload");
    payload["tool_name"] = json!("Read");
    for response in [ALLOW, DENY, ""] {
        let result = fixture.run(
            "pre-tool-use",
            &serde_json::to_vec(&payload).expect("payload"),
            response,
            "0",
        );
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(result.stdout, response.as_bytes());
        assert_eq!(result.stderr, [] as [u8; 0]);
    }
}

fn heartbeat_oracle_fixtures() {
    use std::os::unix::fs::PermissionsExt as _;
    let oracle_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/heartbeat/fixtures/expected");
    for name in [
        "spec-block-stderr",
        "spec-invalid-field-fail-open",
        "spec-unreadable-state-fail-open",
        "spec-state-write-fail-open",
        "spec-nonnumeric-delay",
        "spec-list-feedback-turn-marker",
    ] {
        let oracle: Value = serde_json::from_slice(
            &fs::read(oracle_root.join(format!("{name}.json"))).expect("existing heartbeat oracle"),
        )
        .expect("oracle JSON");
        let fixture = Fixture::new(name);
        fixture.enabled();
        let mut payload: Value =
            serde_json::from_slice(&fixture.payload("Stop")).expect("Stop payload");
        let mut entries = vec![json!({"type":"user","message":{"content":"question"}})];
        match name {
            "spec-invalid-field-fail-open" => payload["session_id"] = json!(7),
            "spec-unreadable-state-fail-open" => fs::create_dir(fixture.state.join("guard-count-fixture")).expect("unreadable counter"),
            "spec-state-write-fail-open" => fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o500)).expect("unwritable state"),
            "spec-nonnumeric-delay" => entries.extend([
                json!({"type":"assistant","timestamp":"2099-01-01T00:00:00Z","message":{"content":[{"type":"tool_use","name":"ScheduleWakeup","id":"timer","input":{"delaySeconds":"1800"}}]}}),
                json!({"type":"user","timestamp":"2099-01-01T00:00:01Z","message":{"content":[{"type":"tool_result","tool_use_id":"timer","is_error":false}]}}),
            ]),
            "spec-list-feedback-turn-marker" => entries.push(json!({"type":"user","message":{"content":[{"type":"text","text":"Stop hook feedback: retry"}]}})),
            _ => {}
        }
        let mut transcript = String::new();
        for entry in &entries {
            writeln!(transcript, "{entry}").expect("transcript string");
        }
        fs::write(fixture.root.join("transcript"), transcript).expect("oracle transcript");
        let output = fixture.run(
            "stop",
            &serde_json::to_vec(&payload).expect("oracle payload"),
            "",
            "0",
        );
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700))
            .expect("restore state");
        if let Some(status) = oracle["specified"]["status"].as_i64() {
            assert_eq!(output.status.code().map(i64::from), Some(status), "{name}");
            assert_eq!(
                output.stdout,
                oracle["specified"]["stdout"]
                    .as_str()
                    .expect("oracle stdout")
                    .as_bytes(),
                "{name}"
            );
            if let Some(stderr) = oracle["specified"]["stderr"].as_str() {
                assert_eq!(output.stderr, stderr.as_bytes(), "{name}");
            } else {
                assert!(output.stderr.starts_with(b"HEARTBEAT GUARD:"));
            }
        } else {
            assert_eq!(output.status.code(), Some(2), "{name}");
            assert_eq!(output.stdout, b"");
            if name == "spec-list-feedback-turn-marker" {
                assert_eq!(
                    fs::read(fixture.state.join("guard-count-fixture")).expect("turn marker"),
                    b"0 1"
                );
            }
        }
    }
}

fn instance_and_elf_refusals() {
    for (label, instance) in [
        (
            "duplicate",
            "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_MODE=enforce\n",
        ),
        ("shell", "PERMISSION_TRIAGE_MODE=$(echo audit)\n"),
        ("missing", ""),
    ] {
        let fixture = Fixture::new(label);
        fs::write(fixture.root.join(".claude/permission-triage.env"), instance)
            .expect("bad instance");
        let result = fixture.run("pre-tool-use", &fixture.payload("PreToolUse"), ALLOW, "0");
        assert_eq!(result.status.code(), Some(2));
        assert!(!fixture.root.join("capture").exists());
    }
    let fixture = Fixture::new("non-elf");
    fs::write(&fixture.helper, "#!/bin/sh\nexit 0\n").expect("script");
    let result = fixture.run("pre-tool-use", &fixture.payload("PreToolUse"), ALLOW, "0");
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("hook binary missing"));

    for (index, extra, accepted) in [
        (
            0,
            "PERMISSION_TRIAGE_HOOK_CEILING_MS=60000\nPERMISSION_TRIAGE_MODEL_DEADLINE_MS=55000\n",
            true,
        ),
        (1, "PERMISSION_TRIAGE_HOOK_CEILING_MS=60001\n", false),
        (2, "PERMISSION_TRIAGE_MODEL_DEADLINE_MS=55001\n", false),
        (3, "PERMISSION_TRIAGE_HOOK_CEILING_MS=0\n", false),
        (4, "PERMISSION_TRIAGE_MODEL_DEADLINE_MS=+1\n", false),
        (5, "PERMISSION_TRIAGE_MODEL=\"quoted\"\n", false),
        (6, "PERMISSION_TRIAGE_ISOLATION=classifier\n", false),
        (7, "\n", false),
    ] {
        let fixture = Fixture::new(&format!("instance-bound-{index}"));
        fs::write(fixture.root.join(".claude/permission-triage.env"), format!("PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/state\nPERMISSION_TRIAGE_CLI=/fixture/cli\n{extra}"))
            .expect("instance grammar fixture");
        let result = fixture.run("pre-tool-use", &fixture.payload("PreToolUse"), ALLOW, "0");
        assert_eq!(
            result.status.code(),
            Some(if accepted { 0 } else { 2 }),
            "{index}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fixture.root.join("capture").exists(), accepted);
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["hook"] {
        std::process::exit(helper());
    }
    if args.len() == 8 && args[..5] == ["enter", "alpha", "--", "/bin/sh", "-c"] {
        std::io::stdout().write_all(b"1\n").expect("listing");
        return;
    }
    mismatch_has_no_effects();
    input_faults_and_panics();
    runtime_environment_cannot_redirect_permission();
    refusal_matrix();
    isolated_and_combined_contexts();
    isolated_stop_and_permission();
    heartbeat_oracle_fixtures();
    instance_and_elf_refusals();
    std::io::stdout().write_all(b"adapter contract: event validation, reply bytes, combined contexts, refusal matrix and helper checks passed\n").expect("fixture result");
}
