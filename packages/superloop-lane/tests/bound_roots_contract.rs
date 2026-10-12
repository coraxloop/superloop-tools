#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs;
use std::io::Read as _;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn invoke(root: &std::path::Path, clone: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["bound-roots", "--runs-root"])
        .arg(root)
        .arg(clone)
        .output()
        .expect("bound-roots dispatch")
}

/// Dispatch publishes clearance evidence and finding statuses, with runtime and usage failures confined to stderr.
///
/// # Panics
/// Panics only if fixture setup, subprocess execution or the report contract fails.
///
/// ´test:integration:bound-roots-dispatch-report-and-status´
#[test]
fn bound_roots_dispatch_report_and_status() {
    let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let clone = fs::canonicalize(root.path()).expect("canonical fixture");
    let run = root.path().join("recorded");
    fs::create_dir(&run).expect("run");
    let record = run.join("bound-roots.json");
    let lock = run.join(".codex-lane.lock");
    let record_bytes = serde_json::to_vec(&json!({"schema":1,"roots":[clone.join(".git")]}))
        .expect("record bytes");
    fs::write(&record, &record_bytes).expect("record");
    fs::write(&lock, format!("{}\n", std::process::id())).expect("live lock");
    let output = invoke(root.path(), &clone);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        std::str::from_utf8(&output.stdout)
            .expect("UTF-8 report")
            .lines()
            .count(),
        1
    );
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).expect("report"),
        json!({
            "schema":1,
            "paths":[{"path":clone,"runs":[{"run":"recorded","lock":".codex-lane.lock","driver_pid":std::process::id(),"child_pid":null,"live":true}]}],
            "unrecorded_live_runs":[],
            "verdict":"refused",
            "refusal":{"kind":"bound-roots-live","runs":["recorded"]}
        })
    );
    assert_eq!(fs::read(&record).expect("unchanged record"), record_bytes);
    assert_eq!(fs::read_dir(&run).expect("run entries").count(), 2);

    let mut child = Command::new("/usr/bin/true").spawn().expect("child");
    let dead_pid = child.id();
    assert!(child.wait().expect("reap").success());
    fs::write(&lock, format!("{dead_pid}\n")).expect("dead lock");
    let output = invoke(root.path(), &clone);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(report["verdict"], "clear");
    assert_eq!(report["refusal"], Value::Null);
    assert_eq!(report["paths"][0]["runs"][0]["live"], false);
    fs::remove_file(&lock).expect("remove fixture lock");
    let output = invoke(root.path(), &clone);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(report["paths"][0]["runs"][0]["lock"], Value::Null);
    assert_eq!(report["paths"][0]["runs"][0]["driver_pid"], Value::Null);

    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&clone, &alias).expect("path alias");
    let output = invoke(root.path(), &alias);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("diagnostic")["kind"],
        "bound-roots-path"
    );

    fs::remove_file(&record).expect("remove fixture record");
    fs::write(&lock, format!("{}\n", std::process::id())).expect("live lock");
    let output = invoke(root.path(), &clone);
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(report["refusal"]["kind"], "bound-roots-unrecorded");
    assert_eq!(report["unrecorded_live_runs"][0]["run"], "recorded");

    fs::write(&record, b"{").expect("malformed record");
    let output = invoke(root.path(), &clone);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).expect("diagnostic");
    assert_eq!(diagnostic["kind"], "bound-roots-shape");
    assert_eq!(diagnostic["failures"][0]["run"], "recorded");
    let output = invoke(&root.path().join("missing"), &clone);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("diagnostic")["kind"],
        "bound-roots-read"
    );

    assert_usage_and_terminal_refusals();
}

fn assert_usage_and_terminal_refusals() {
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["bound-roots", "--secret-fixture"])
        .output()
        .expect("usage");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("diagnostic"),
        json!({"schema":1,"command":"superloop-lane bound-roots","class":"usage","kind":"bound-roots-usage"})
    );

    let terminal = nix::pty::openpty(None, None).expect("terminal");
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .arg("bound-roots")
        .stdout(std::process::Stdio::from(terminal.slave))
        .output()
        .expect("terminal refusal");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("diagnostic")["kind"],
        "bound-roots-terminal"
    );
    let mut bytes = Vec::new();
    let _closed = fs::File::from(terminal.master).read_to_end(&mut bytes);
    assert_eq!(bytes, [] as [u8; 0]);
}
