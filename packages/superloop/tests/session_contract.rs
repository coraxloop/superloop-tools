use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PWD", home)
        .current_dir(home);
    command
}

/// Status reads both session toggles without creating their absent state.
/// ´claim:session:status-keeps-absent-state-absent´
/// ´test:integration:session-status-does-not-create-absent-state´
#[test]
fn session_status_does_not_create_absent_state() {
    let home = tempfile::tempdir().expect("fixture");
    for subject in ["heartbeat", "orchestrator"] {
        let output = command(home.path())
            .args([subject, "status"])
            .output()
            .expect("status");
        assert!(
            output.status.success(),
            "{subject}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!home.path().join(".local").exists());
    }
}

/// Equivalent neutral and harness observations reach the same heartbeat verdict.
/// ´claim:session:neutral-heartbeat-agrees-with-adapter´
/// ´test:integration:neutral-heartbeat-decisions-agree-with-adapter-verdicts´
#[test]
fn neutral_heartbeat_decisions_agree_with_adapter_verdicts() {
    let adapter = std::env::var_os("SUPERLOOP_TEST_CLAUDE_HOOK")
        .expect("SUPERLOOP_TEST_CLAUDE_HOOK must bind the built adapter");
    for enabled in [false, true] {
        let home = tempfile::tempdir().expect("fixture");
        let transcript = home.path().join("observations.jsonl");
        fs::write(&transcript, b"").expect("empty observations");
        if enabled {
            assert!(
                command(home.path())
                    .args(["heartbeat", "on"])
                    .output()
                    .expect("toggle")
                    .status
                    .success()
            );
        }
        let input = home.path().join("decision.json");
        fs::write(&input,serde_json::to_vec(&serde_json::json!({"schema":1,"cwd":home.path(),"session":"neutral","observations":transcript,"retry":false,"letters":{"kind":"empty"}})).expect("record")).expect("input");
        let output = command(home.path())
            .args(["heartbeat", "decide"])
            .arg(&input)
            .output()
            .expect("decision");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("neutral decision");
        let terminal = result["terminal"].as_str().expect("terminal");
        if !enabled {
            assert_eq!(terminal, "AllowSilent");
        }
        let mut hook = Command::new(&adapter)
            .arg("stop")
            .env_clear()
            .env("HOME", home.path())
            .env("PWD", home.path())
            .current_dir(home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("adapter");
        let payload=serde_json::to_vec(&serde_json::json!({"hook_event_name":"Stop","cwd":home.path(),"session_id":"adapter","transcript_path":transcript})).expect("harness input");
        hook.stdin
            .take()
            .expect("stdin")
            .write_all(&payload)
            .expect("payload");
        let reply = hook.wait_with_output().expect("reply");
        assert_eq!(
            terminal.starts_with("Block"),
            reply.status.code() == Some(2),
            "terminal={terminal} status={} stdout={} stderr={}",
            reply.status,
            String::from_utf8_lossy(&reply.stdout),
            String::from_utf8_lossy(&reply.stderr)
        );
    }
}

/// Equivalent neutral and harness observations publish the same rulebook injection.
/// ´claim:session:neutral-rulebook-agrees-with-adapter´
/// ´test:integration:neutral-orchestrator-and-adapter-publish-the-same-rulebook-decision´
#[test]
fn neutral_orchestrator_and_adapter_publish_the_same_rulebook_decision() {
    let home = tempfile::tempdir().expect("fixture");
    let rulebook = home.path().join("rules.md");
    fs::write(&rulebook, "# Rules\nKeep the measured evidence.\n").expect("rules");
    let input = home.path().join("decision.json");
    fs::write(&input, serde_json::to_vec(&serde_json::json!({"schema":1,"kind":"start","class":"fresh","session":"neutral","cwd":home.path(),"source":"startup"})).expect("record")).expect("input");
    let output = command(home.path())
        .args(["orchestrator", "decide"])
        .arg(&input)
        .env("ORCHESTRATION_FILE", &rulebook)
        .env("ORCHESTRATOR_STATE_DIR", home.path().join("neutral-state"))
        .output()
        .expect("neutral decision");
    assert!(output.status.success(), "{output:?}");
    let neutral: serde_json::Value = serde_json::from_slice(&output.stdout).expect("decision");
    let mut child = Command::new(
        std::env::var_os("SUPERLOOP_TEST_CLAUDE_HOOK").expect("SUPERLOOP_TEST_CLAUDE_HOOK"),
    )
    .arg("session-start")
    .env_clear()
    .env("HOME", home.path())
    .env("PWD", home.path())
    .env("ORCHESTRATION_FILE", &rulebook)
    .env("ORCHESTRATOR_STATE_DIR", home.path().join("adapter-state"))
    .env("ENTER_LOOP_REGISTRY", home.path().join("absent-registry"))
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("adapter");
    child.stdin.take().expect("stdin").write_all(&serde_json::to_vec(&serde_json::json!({"hook_event_name":"SessionStart","session_id":"adapter","cwd":home.path(),"source":"startup"})).expect("payload")).expect("write");
    let output = child.wait_with_output().expect("reply");
    assert!(output.status.success(), "{output:?}");
    let adapter: serde_json::Value = serde_json::from_slice(&output.stdout).expect("adapter reply");
    assert!(neutral["injection"].is_string(), "{neutral}");
    assert_eq!(
        neutral["injection"],
        adapter["hookSpecificOutput"]["additionalContext"]
    );
}

/// The public session interface rejects harness-shaped records and advertises its subjects.
/// ´claim:session:neutral-session-rejects-harness-shapes´
/// ´test:integration:neutral-session-rejects-harness-payload-and-help-lists-subjects´
#[test]
fn neutral_session_rejects_harness_payload_and_help_lists_subjects() {
    let home = tempfile::tempdir().expect("fixture");
    let input = home.path().join("harness.json");
    fs::write(&input, b"{\"hook_event_name\":\"Stop\"}").expect("input");
    for subject in ["heartbeat", "orchestrator"] {
        let output = command(home.path())
            .args([subject, "decide"])
            .arg(&input)
            .output()
            .expect("refusal");
        assert_eq!(output.status.code(), Some(2));
        assert!(!home.path().join(".local").exists());
    }
    let output = command(home.path()).arg("--help").output().expect("help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help text");
    for word in [
        "enter",
        "provision",
        "verify",
        "show",
        "run-bridge",
        "account",
        "heartbeat",
        "orchestrator",
    ] {
        assert!(help.contains(word), "missing {word}");
    }
}

/// Private bridges copy the root bytes, repeat unchanged and select bridge dispatch before version handling.
/// ´claim:session:bridges-copy-root-and-dispatch-by-name´
/// ´test:integration:bridge-install-copies-the-root-and-repeats-without-changes´
#[test]
fn bridge_install_copies_the_root_and_repeats_without_changes() {
    let home = tempfile::tempdir().expect("fixture");
    let registry = home.path().join("registry.toml");
    fs::write(&registry,"namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{name = \"alpha\", uid = 41001, launch = \"dev/alpha\"}]\n").expect("registry");
    let destination = home.path().join("libexec/superloop");
    for changed in [2, 0] {
        let output = command(home.path())
            .arg("_install-bridges")
            .arg(&registry)
            .arg(&destination)
            .output()
            .expect("install");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(result["changed"], changed);
        for kind in ["gpg", "ssh"] {
            assert_eq!(
                fs::read(destination.join(format!("alpha-{kind}"))).expect("bridge"),
                fs::read(env!("CARGO_BIN_EXE_superloop")).expect("binary")
            );
        }
    }
    let output = Command::new(destination.join("alpha-gpg"))
        .arg("--version")
        .env_clear()
        .env("HOME", home.path())
        .env("ENTER_LOOP_REGISTRY", &registry)
        .output()
        .expect("bridge dispatch");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("\"kind\":\"version\""),
        "bridge must dispatch before root version handling"
    );
}
