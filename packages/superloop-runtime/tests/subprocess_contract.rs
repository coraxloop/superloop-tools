use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

const ENGINE: &str = r"#!/usr/bin/python3
import json,os,pathlib,sys
root=pathlib.Path(os.environ['FIXTURE'])
args=sys.argv[1:]
with (root/'calls').open('a') as f: f.write(json.dumps(args)+'\n')
state=root/'state'
s=json.loads(state.read_text()) if state.exists() else {}
def save(): state.write_text(json.dumps(s,sort_keys=True))
if args[:2]==['container','exists']: sys.exit(0 if s else 1)
if args[0]=='inspect' and os.environ.get('FIXTURE_NEVER_CREATED')=='1':
 assert not state.exists()
 print('no such container: superloop-runtime',file=sys.stderr);sys.exit(1)
if args[:3]==['inspect','--format','{{json .Config.Labels}}']:
 print(json.dumps({'superloop.runtime.identity':s['identity']}));sys.exit(0)
if args[0]=='inspect': print('true' if s.get('running') else 'false');sys.exit(0)
if args[0]=='create':
 s={'identity':args[args.index('--label')+1].split('=',1)[1],'running':False};save();sys.exit(0)
if args[0]=='start':
 if os.environ.get('FIXTURE_START_REFUSE')=='1': print('engine refused',file=sys.stderr);sys.exit(1)
 s['running']=True;save();sys.exit(0)
if args[:5]==['exec','-u','root','superloop-runtime','cat']:
 if 'ready' not in s: sys.exit(1)
 print(s['ready']);sys.exit(0)
if args[:5]==['exec','-u','root','superloop-runtime','/bin/sh']:
 s['ready']=args[-1];save();sys.exit(0)
if args[0]=='exec':
 if os.environ.get('FIXTURE_LIVE')=='1':
  for index,word in enumerate(args):
   if word=='-e':
    name,value=args[index+1].split('=',1);os.environ[name]=value
  command=args[args.index('/bin/bash'):];os.execv(command[0],command)
 print('agent stdout');print('agent stderr',file=sys.stderr);sys.exit(23)
if args==['--host','true']:sys.exit(0)
print('portal stdout');print('portal stderr',file=sys.stderr);sys.exit(17)
";

struct Fixture(TempDir);
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        let script = directory.path().join("engine");
        fs::write(&script, ENGINE).expect("engine bytes");
        fs::set_permissions(script, fs::Permissions::from_mode(0o755)).expect("engine mode");
        Self(directory)
    }
    fn command(&self, verb: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-runtime"));
        command
            .arg(verb)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.0.path())
            .env("FIXTURE", self.0.path())
            .env(
                "SUPERLOOP_RUNTIME_ENGINE_ARGV",
                json!([self.0.path().join("engine")]).to_string(),
            )
            .env("SUPERLOOP_RUNTIME_PORTAL", self.0.path().join("engine"))
            .env(
                "SUPERLOOP_RUNTIME_CONTAINER_MARKER",
                self.0.path().join("container"),
            );
        command
    }
    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.0.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("recorded argv"))
            .collect()
    }
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:version-and-usage-do-not-open-runtime-state´
#[test]
fn version_and_usage_do_not_open_runtime_state() {
    let fixture = Fixture::new();
    let output = fixture.command("--version").output().expect("version");
    success(&output);
    assert_eq!(output.stdout, [] as [u8; 0]);
    let record: Value = serde_json::from_slice(&output.stderr).expect("JSON version");
    assert_eq!(record["fields"]["version"], "superloop-runtime 0.4.1");
    assert_eq!(record["command"], "superloop-runtime");
    assert_eq!(
        fixture
            .command("create")
            .arg("unexpected")
            .output()
            .expect("usage")
            .status
            .code(),
        Some(2)
    );
    assert_eq!(fixture.calls(), [] as [Value; 0]);
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:host-agent-keeps-arguments-streams-and-exit-status´
#[test]
fn host_agent_keeps_arguments_streams_and_exit_status() {
    let fixture = Fixture::new();
    let script = fixture.0.path().join("agent");
    fs::write(
        &script,
        b"#!/bin/sh\nprintf '%s\\n' \"$@\"\nprintf 'agent error\\n' >&2\nexit 19\n",
    )
    .expect("agent");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("mode");
    let output = fixture
        .command("run-host")
        .env("CODEX_REAL_BIN", script)
        .args(["--", "--version", "two words"])
        .output()
        .expect("host");
    assert_eq!(output.status.code(), Some(19));
    assert_eq!(output.stdout, b"--version\ntwo words\n");
    assert_eq!(output.stderr, b"agent error\n");
    assert_eq!(fixture.calls(), [] as [Value; 0]);
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:host-escape-and-toolbox-forward-only-declared-environment´
#[test]
fn host_escape_and_toolbox_forward_only_declared_environment() {
    let fixture = Fixture::new();
    fs::write(fixture.0.path().join("container"), b"").expect("marker");
    let output = fixture
        .command("run-host")
        .env("CODEX_REAL_BIN", "/agent path")
        .env("CODEX_HOME", "/home path")
        .arg("--version")
        .output()
        .expect("escape");
    assert_eq!(output.status.code(), Some(17));
    assert_eq!(output.stdout, b"portal stdout\n");
    assert_eq!(output.stderr, b"portal stderr\n");
    let calls = fixture.calls();
    assert_eq!(calls[0], json!(["--host", "true"]));
    let argv = calls[1].as_array().expect("argv");
    assert!(argv.contains(&json!("--env=CODEX_HOME=/home path")));
    assert_eq!(
        &argv[argv.len() - 2..],
        &[json!("/agent path"), json!("--version")]
    );
    let count = calls.len();
    let refused = fixture.command("run-toolbox").output().expect("refusal");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("CLAUDE_TOOLBOX"));
    assert_eq!(fixture.calls().len(), count);
    let output = fixture
        .command("run-toolbox")
        .env("CLAUDE_TOOLBOX", "fixture box")
        .env("CLAUDE_CONFIG_DIR", "/lane home")
        .env("TMPDIR", "/disk tmp")
        .args(["--version", "two words"])
        .output()
        .expect("toolbox");
    assert_eq!(output.status.code(), Some(17));
    assert_eq!(
        fixture.calls().last(),
        Some(&json!([
            "--host",
            "toolbox",
            "run",
            "-c",
            "fixture box",
            "env",
            "CLAUDE_CONFIG_DIR=/lane home",
            "TMPDIR=/disk tmp",
            "claude",
            "--version",
            "two words"
        ]))
    );
    assert!(
        !fixture.0.path().join(".config/loops").exists(),
        "runtime forwards the caller's explicit home without creating a registered home"
    );
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:container-exec-starts-once-and-preserves-agent-contract´
#[test]
fn container_exec_starts_once_and_preserves_agent_contract() {
    let fixture = Fixture::new();
    fs::write(fixture.0.path().join("state"), r#"{"running":false}"#).expect("stopped container");
    let output = fixture
        .command("exec")
        .env("CODEX_REAL_BIN", "/agent path")
        .env("CODEX_HOME", "/lane home")
        .args(["--", "--version", "two words"])
        .output()
        .expect("exec");
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"agent stdout\n");
    assert_eq!(output.stderr, b"agent stderr\n");
    let calls = fixture.calls();
    assert_eq!(calls[1], json!(["start", "superloop-runtime"]));
    let args = calls[2].as_array().expect("argv");
    assert!(args.contains(&json!("CODEX_HOME=/lane home")));
    assert!(args.iter().any(|arg| {
        arg.as_str()
            .is_some_and(|arg| arg.starts_with("CALLER_PID="))
    }));
    assert_eq!(
        &args[args.len() - 3..],
        &[json!("/agent path"), json!("--version"), json!("two words")]
    );
    assert!(args.iter().any(|arg| {
        arg.as_str()
            .is_some_and(|arg| arg.contains("kill -TERM \"$p\""))
    }));
    fixture
        .command("exec")
        .arg("--version")
        .output()
        .expect("second exec");
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|args| args[0] == "start")
            .count(),
        1
    );
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:create-repeats-without-mutation-and-refuses-foreign-shape´
#[test]
fn create_repeats_without_mutation_and_refuses_foreign_shape() {
    let fixture = Fixture::new();
    let output = fixture.command("create").output().expect("create");
    success(&output);
    assert_ready_report(&output, "prepared-ready-record");
    let state = fixture.0.path().join("state");
    let bytes = fs::read(&state).expect("state");
    let modified = fs::metadata(&state)
        .expect("stat")
        .modified()
        .expect("mtime");
    let first = fixture.calls();
    assert!(first.iter().any(|args| args[0] == "create"));
    let output = fixture.command("create").output().expect("repeat");
    success(&output);
    assert_ready_report(&output, "existing-ready-record");
    assert_eq!(fs::read(&state).expect("state"), bytes);
    assert_eq!(
        fs::metadata(&state)
            .expect("stat")
            .modified()
            .expect("mtime"),
        modified
    );
    let calls = fixture.calls();
    assert!(
        calls[first.len()..]
            .iter()
            .all(|args| args[0] == "inspect" || args[0] == "container" || args[4] == "cat")
    );
    let changed = fixture
        .command("create")
        .env("SUPERLOOP_RUNTIME_IMAGE", "different:image")
        .output()
        .expect("foreign shape");
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("differs"));
    assert_eq!(fs::read(state).expect("state"), bytes);
}

/// # Panics
/// Panics only if fixture setup or the asserted runtime contract fails.
/// ´test:integration:caller-death-terminates-the-container-agent-by-rendezvous´
#[test]
fn caller_death_terminates_the_container_agent_by_rendezvous() {
    use nix::sys::signal::{Signal, killpg};
    use nix::sys::stat::Mode;
    use nix::unistd::{Pid, mkfifo};
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;

    struct Group(std::process::Child);
    impl Drop for Group {
        fn drop(&mut self) {
            if let Ok(pid) = i32::try_from(self.0.id()) {
                let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
            }
            drop(self.0.wait());
        }
    }
    let fixture = Fixture::new();
    for name in ["sleep-ready", "sleep-release", "agent-ended"] {
        mkfifo(&fixture.0.path().join(name), Mode::S_IRUSR | Mode::S_IWUSR).expect("rendezvous");
    }
    let sleep = fixture.0.path().join("sleep");
    fs::write(&sleep, b"#!/bin/sh\nprintf '%s\\n' \"$1\" >\"$FIXTURE/sleep-ready\"\nread -r reply <\"$FIXTURE/sleep-release\"\n").expect("controlled sleep");
    fs::set_permissions(&sleep, fs::Permissions::from_mode(0o755)).expect("sleep mode");
    let agent = fixture.0.path().join("agent");
    fs::write(
        &agent,
        r"#!/usr/bin/python3
import os,pathlib,signal
root=pathlib.Path(os.environ['FIXTURE'])
def ended(sig,frame):
 (root/'agent-ended').write_text('terminated\n')
 raise SystemExit(0)
signal.signal(signal.SIGTERM,ended)
print('ready',flush=True)
signal.pause()
",
    )
    .expect("agent");
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).expect("agent mode");
    fs::write(fixture.0.path().join("state"), r#"{"running":true}"#).expect("container");
    let mut group = Group(
        fixture
            .command("exec")
            .env("FIXTURE_LIVE", "1")
            .env("CODEX_REAL_BIN", agent)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", fixture.0.path().display()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("runtime"),
    );
    let mut ready = String::new();
    std::io::BufReader::new(group.0.stdout.take().expect("stdout"))
        .read_line(&mut ready)
        .expect("agent ready");
    assert_eq!(ready, "ready\n");
    assert_eq!(
        fs::read_to_string(fixture.0.path().join("sleep-ready")).expect("watchdog ready"),
        "3\n"
    );
    group.0.kill().expect("caller death");
    group.0.wait().expect("reap caller");
    fs::OpenOptions::new()
        .write(true)
        .open(fixture.0.path().join("sleep-release"))
        .expect("release watcher")
        .write_all(b"continue\n")
        .expect("release");
    assert_eq!(
        fs::read_to_string(fixture.0.path().join("sleep-ready")).expect("termination sent"),
        "10\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.0.path().join("agent-ended")).expect("agent disposition"),
        "terminated\n"
    );
    fs::OpenOptions::new()
        .write(true)
        .open(fixture.0.path().join("sleep-release"))
        .expect("release cleanup")
        .write_all(b"continue\n")
        .expect("release");
}

fn assert_ready_report(output: &Output, evidence: &str) {
    let text = std::str::from_utf8(&output.stdout).expect("readiness text");
    assert!(text.starts_with("RUNTIME-READY container=superloop-runtime wall="));
    assert!(text.contains("readiness=/var/lib/superloop-runtime/ready identity="));
    assert!(text.contains(&format!("evidence={evidence}")));
    let wall = text
        .split("wall=")
        .nth(1)
        .expect("wall")
        .split('s')
        .next()
        .expect("seconds");
    assert!(wall.parse::<f64>().expect("numeric wall") >= 0.0);
}

/// # Panics
/// Panics only if fixture setup fails or a start refusal loses its identity or status.
/// ´test:integration:stopped-container-start-refusal-is-distinct-from-agent-failure´
#[test]
fn stopped_container_start_refusal_is_distinct_from_agent_failure() {
    let fixture = Fixture::new();
    fs::write(fixture.0.path().join("state"), r#"{"running":false}"#).expect("stopped container");
    let output = fixture
        .command("exec")
        .env("FIXTURE_START_REFUSE", "1")
        .output()
        .expect("refusal");
    assert_eq!(output.status.code(), Some(125));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("runtime-start-refused"));
    assert!(text.contains("superloop-runtime create"));
    assert!(text.contains("engine refused"));
    assert!(!fixture.calls().iter().any(|args| args[0] == "exec"));
}

/// # Panics
/// Panics only if fixture setup fails or an absent container loses its named refusal.
/// ´test:integration:never-created-container-has-the-runtime-start-refusal´
#[test]
fn never_created_container_has_the_runtime_start_refusal() {
    let fixture = Fixture::new();
    let output = fixture
        .command("exec")
        .env("FIXTURE_NEVER_CREATED", "1")
        .output()
        .expect("missing container refusal");
    assert_eq!(output.status.code(), Some(125));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("runtime-start-refused"));
    assert!(text.contains("superloop-runtime create"));
    assert!(text.contains("no such container: superloop-runtime"));
    assert!(fixture.calls().iter().all(|args| args[0] == "inspect"));
    assert!(!fixture.0.path().join("state").exists());
}
