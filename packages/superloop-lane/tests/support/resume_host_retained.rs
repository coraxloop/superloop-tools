//! Retained attempts discriminate the order and identity guards in real host rollback.
use crate::{host, refusals};
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

pub(super) fn run(fixture: &host::Host, case: &str) {
    if case == "intent" && std::env::var_os("RESUME_FIXTURE_INTENT_HOME").is_none() {
        refusals::install(fixture, "intent");
        let error = Command::new(std::env::current_exe().expect("real entry image"))
            .args(std::env::args_os().skip(1))
            .env("LD_PRELOAD", fixture.home().join("resume-fault.so"))
            .env("RESUME_FIXTURE_INTENT_HOME", fixture.home())
            .env("RESUME_FIXTURE_HIT", fixture.home().join("fault-hit"))
            .exec();
        panic!("intent fault re-exec: {error}");
    }
    if case != "intent" {
        refusals::install(fixture, case);
    }
    let before = fixture.reservation();
    let error = fixture
        .launch(false)
        .expect_err("real public retained refusal");
    let after = fixture.reservation();
    let record: Value = serde_json::from_slice(&after).expect("preparing record");
    match case {
        "live-process" => alive(fixture, &before, &after),
        "changed-request" => changed_request(fixture, &record),
        "intent" => {
            assert_eq!(
                record["dispatch_intent"]["nonce"], record["round_rollback"]["nonce"],
                "persisted intent retained"
            );
            assert!(
                record["dispatch_intent"]["nonce"].is_string(),
                "persisted intent retained"
            );
            let marker =
                fs::read_to_string(fixture.home().join("fault-hit")).expect("intent marker");
            assert!(
                marker.lines().any(|line| line == "persisted intent fsync"),
                "{marker}"
            );
        }
        _ => panic!("retained case"),
    }
    assert_ne!(after, before, "retained attempt must not restore");
    assert_eq!(record["phase"], "preparing");
    assert_eq!(record["round_rollback"]["schema"], 1);
    assert_eq!(
        record["round_rollback"]["before"]
            .as_str()
            .expect("raw before")
            .as_bytes(),
        before
    );
    let line = error.line();
    assert!(line.contains("; retained:"), "{case}: {line}");
    let nonce = record["round_rollback"]["nonce"].as_str().expect("nonce");
    let path = fixture
        .home()
        .join(format!("runs/.round-refusal-R-{nonce}.json"));
    let evidence: Value =
        serde_json::from_slice(&fs::read(path).expect("durable refusal")).expect("evidence");
    assert_eq!(evidence["schema"], 1);
    assert_eq!(evidence["nonce"], nonce);
    assert_eq!(
        evidence["reason"],
        line.split_once("; retained:").expect("retained suffix").0
    );
    writeln!(std::io::stdout().lock(), "RETAINED-CONTROL {case} {line}").expect("result");
}
fn alive(fixture: &host::Host, before: &[u8], after: &[u8]) {
    let output = host::mapped(
        fixture.home(),
        r"
import os,sys,json
from pathlib import Path
home=Path(sys.argv[1]);saved=json.loads((home/'linger.json').read_text())
p=Path('/proc')/str(saved['pid']);fields=p.joinpath('stat').read_text().rsplit(')',1)[1].split()
assert fields[0]!='Z' and int(fields[19])==saved['start'],'real live work process'
assert p.joinpath('cgroup').read_text()==saved['cgroup']
assert saved['cgroup'].strip().endswith('/work')
print('LIVE-WORK-PROCESS '+json.dumps(saved))
",
    );
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("live identity");
    assert_ne!(
        after, before,
        "reservation not restored while real work process lives"
    );
}
fn changed_request(fixture: &host::Host, record: &Value) {
    let output = host::mapped(
        fixture.home(),
        r"
import sys,json
from pathlib import Path
home=Path(sys.argv[1]);p=home/'runs/R/round-launch-review.json'
assert p.is_file(),'changed request preserved'
record=json.loads((home/'runs/.reservation-R.json').read_text())
expected=record['round_rollback']['request'].encode()
assert expected.endswith(b'\n')
assert p.read_bytes()==expected[:-1]+b' ','changed request preserved'
print('CHANGED-REQUEST-PRESERVED')
",
    );
    assert!(record["round_rollback"]["request"].is_string());
    std::io::stdout()
        .lock()
        .write_all(&output.stdout)
        .expect("request evidence");
}
