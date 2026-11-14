//! Errors at the real private-entry boundary; the public host owns rollback and retry.
use crate::{fixture::bounded::CommandOutput as _, host};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::time::Duration;

pub(super) fn run(fixture: &host::Host, case: &str, failed: bool) {
    if failed {
        failed_history(fixture);
    }
    let home = fixture.home();
    host::write(home.join("runs/.prepare-R.lock"), b"", 0o600);
    let listener = (case == "stale-socket").then(|| {
        UnixListener::bind(home.join("runs/.container-R.sock")).expect("real stale socket")
    });
    let retained_socket = listener.as_ref().map(|_| socket_identity(fixture));
    if case != "stale-socket" {
        install(fixture, case);
    }
    let before = fixture.reservation();
    let inventory = fixture.inventory();
    choice_check(fixture, failed, &before);
    let error = fixture
        .launch_choice(false, failed)
        .expect_err("forced public refusal");
    let line = error.line();
    let expected = match case {
        "inspector" => "round-evidence:",
        "helper-pin" => "helper-pin:",
        "stale-socket" => "resumed helper socket already exists",
        "credential" => "credential-thread:",
        "readiness" => "helper-socket:",
        _ => panic!("case"),
    };
    assert!(
        line.contains(expected),
        "specific public refusal for {case}: {line}"
    );
    assert!(line.ends_with("; rollback: restored"), "{case}: {line}");
    assert_eq!(
        fixture.reservation(),
        before,
        "raw reservation restored for {case}: {line}"
    );
    let prior: Value = serde_json::from_slice(&before).expect("before");
    assert_eq!(
        prior["rounds"].as_array().expect("rounds").len(),
        1,
        "unused review name"
    );
    inventory_restored(fixture, &inventory, &line);
    crate::scope::assert_work_empty();
    remove_cause(fixture, case, listener, retained_socket);
    choice_check(fixture, failed, &before);
    let preview = fixture
        .launch_choice(true, failed)
        .expect("restored preview");
    assert_eq!(preview["helper_preflight"]["state"], "passed");
    assert_eq!(
        fixture.reservation(),
        before,
        "preview consumes no round or choice"
    );
    let retry = fixture
        .launch_choice(false, failed)
        .expect("identical public retry succeeds");
    assert_eq!(retry["thread_id"], "fixture-thread");
    let settled: Value = serde_json::from_slice(&fixture.reservation()).expect("settled retry");
    assert_eq!(settled["phase"], "settled");
    assert_eq!(settled["rounds"].as_array().expect("rounds").len(), 2);
    assert_eq!(settled["rounds"][1]["step"], "review");
    assert_eq!(settled["rounds"][1]["phase"], "settled");
    assert!(
        settled.get("round_rollback").is_none(),
        "retry consumed before-image"
    );
    assert!(
        settled.get("dispatch_intent").is_none(),
        "retry consumed intent"
    );

    writeln!(
        std::io::stdout().lock(),
        "RESTORED-AND-RETRIED {case} failed_history={failed} {line}"
    )
    .expect("case result");
}
fn remove_cause(
    fixture: &host::Host,
    case: &str,
    listener: Option<UnixListener>,
    retained_socket: Option<(u64, u64)>,
) {
    let home = fixture.home();
    if case == "stale-socket" {
        assert_eq!(
            Some(socket_identity(fixture)),
            retained_socket,
            "rollback preserves pre-existing socket identity"
        );
        drop(listener);
        fs::remove_file(home.join("runs/.container-R.sock")).expect("remove own stale listener");
    } else {
        hit(fixture, case);
        fs::remove_file(home.join("fixture-fault")).expect("remove own synthetic cause");
    }
}
fn socket_identity(fixture: &host::Host) -> (u64, u64) {
    let meta = fs::symlink_metadata(fixture.home().join("runs/.container-R.sock"))
        .expect("original socket retained");
    (meta.dev(), meta.ino())
}
fn choice_check(fixture: &host::Host, failed: bool, before: &[u8]) {
    let error = if failed {
        fixture
            .launch(true)
            .expect_err("failed history still owes its choice")
    } else {
        fixture
            .launch_choice(true, true)
            .expect_err("restored refusal creates no choice")
    };
    assert_eq!(error.kind, "round-choice", "{error}");
    let expected = if failed {
        "choose --fresh-thread or --resume-thread"
    } else {
        "no failed-round choice is owed"
    };
    assert!(error.detail.contains(expected), "{error}");
    assert_eq!(
        fixture.reservation(),
        before,
        "choice refusal writes nothing"
    );
}
fn failed_history(fixture: &host::Host) {
    // A finalized failure is the before-image, not an invented result of this attempt.
    let mut record: Value = serde_json::from_slice(&fixture.reservation()).expect("history");
    record["readback_end"] = json!("completed");
    record["driver_end"] = json!({"state":"completed","successful":false});
    record["helper_end"] = json!({"state":"completed"});
    let row = &mut record["rounds"][0];
    row["phase"] = json!("failed");
    row["reply"] = Value::Null;
    row["ended_by"] = json!("by-budget");
    row["thread"] = json!({"id":"fixture-thread","provenance":"observed"});
    row["settle_attempts"] = json!([{"phase":"complete"}]);
    host::write(
        fixture.home().join("runs/.reservation-R.json"),
        serde_json::to_vec(&record).expect("seeded completed failure"),
        0o600,
    );
}
fn hit(fixture: &host::Host, case: &str) {
    let hit =
        fs::read_to_string(fixture.home().join("fault-hit")).expect("actual injection reached");
    let expected = match case {
        "inspector" => "inspector read",
        "helper-pin" => "helper pin hash reader start",
        "credential" => "authority thread start after host pause",
        "readiness" => "helper client bind",
        _ => panic!("case"),
    };
    assert!(hit.lines().any(|s| s == expected), "{case}: {hit}");
}
fn install(fixture: &host::Host, case: &str) {
    let home = fixture.home();
    host::write(
        home.join("resume-fault.c"),
        include_str!("resume_host_fault.c"),
        0o600,
    );
    let output = Command::new("/usr/bin/cc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(home.join("resume-fault.so"))
        .arg(home.join("resume-fault.c"))
        .arg("-ldl")
        .fixture_output("fault injector build", Duration::from_secs(30))
        .expect("compiler");
    assert!(output.status.success(), "{output:?}");
    host::write(home.join("fixture-fault"), case, 0o600);
    host::write(home.join("unshare"), WRAPPER, 0o600);
}
fn inventory_restored(fixture: &host::Host, before: &[u8], reason: &str) {
    let home = fixture.home();
    let records = fs::read_dir(home.join("runs"))
        .expect("protected runs")
        .map(|r| r.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".round-refusal-R-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "exactly one durable refusal");
    let evidence: Value =
        serde_json::from_slice(&fs::read(&records[0]).expect("refusal")).expect("envelope");
    assert_eq!(evidence["schema"], 1);
    assert_eq!(evidence["state"], "live-refusal");
    assert_eq!(
        evidence["reason"],
        reason.strip_suffix("; rollback: restored").expect("suffix")
    );
    let nonce = evidence["nonce"].as_str().expect("attempt nonce");
    assert_eq!(
        records[0],
        home.join(format!("runs/.round-refusal-R-{nonce}.json"))
    );
    let mut after: Vec<Value> =
        serde_json::from_slice(&fixture.inventory()).expect("after inventory");
    let mut prior: Vec<Value> = serde_json::from_slice(before).expect("prior inventory");
    after.retain(|r| r[0] != format!("runs/.round-refusal-R-{nonce}.json"));
    for rows in [&mut prior, &mut after] {
        let env = rows
            .iter_mut()
            .find(|r| r[0] == "runs/R/launch/runtime.env")
            .expect("derived env");
        env[4] = Value::Null; // Custody and exact path still compare; derived bytes may refresh.
    }
    assert_eq!(
        after, prior,
        "attempt inventory restored (only derived env bytes and exact evidence excepted)"
    );
}

const WRAPPER: &str = r#"
# Actual private entry remains the command being executed.
export TMPDIR=${PWD%/*}
printf '%s\n' "$2" >> entry-calls
fault=
if test -f fixture-fault; then
  selection=$(cat fixture-fault)
  case " $* " in
    *' _inspect-round '*' --record '*) test "$selection" = inspector && fault=$selection ;;
    *' _container-helper '*)
      case " $* " in *' --preflight-round '*) ;; *)
        case "$selection" in helper-pin|credential|readiness) fault=$selection;; esac
      esac ;;
  esac
fi
if test -z "$fault"; then exec /usr/bin/podman unshare "$@"; fi
identity=$(/usr/bin/python3 -I -c 'import json;r=json.load(open("runs/.reservation-R.json"));print(r["launcher_pid"],r["launcher_start"])')
launcher=${identity% *}
launcher_start=${identity#* }
resume_launcher() {
 /usr/bin/python3 -I - "$launcher" "$launcher_start" <<'PYRESUME'
import os,signal,sys
try:
 data=open('/proc/'+sys.argv[1]+'/stat').read().rsplit(')',1)[1].split()
 if data[19]==sys.argv[2]:os.kill(int(sys.argv[1]),signal.SIGCONT)
except ProcessLookupError:pass
except FileNotFoundError:pass
PYRESUME
}
# Pause only the actual retained launcher identity; release it on every wrapper exit.
trap 'resume_launcher' EXIT HUP INT TERM
/usr/bin/podman unshare /usr/bin/env LD_PRELOAD="$PWD/resume-fault.so" RESUME_FIXTURE_FAULT="$fault" RESUME_FIXTURE_HIT="$PWD/fault-hit" RESUME_FIXTURE_LAUNCHER="$launcher" RESUME_FIXTURE_LAUNCHER_START="$launcher_start" "$@"
status=$?
resume_launcher
exit "$status"
"#;
