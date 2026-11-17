use super::tests::{FixtureClient, FixtureServer, fixture_request, route_for};
use super::transport::{Operation, Runner};
use super::{Registration, Scope, compute, serve_request};
use crate::requests::{
    RequestRecord,
    modes::Rubric,
    store::{Store, tests::Fixture},
};
use serde_json::{Value, json};
use std::io::{self, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

struct NodeRunner {
    store: Store,
    calls: Arc<AtomicUsize>,
    program: PathBuf,
    remaining: Option<Arc<std::sync::Mutex<f64>>>,
}

impl Runner for NodeRunner {
    fn spawn(&self, _: &Registration, _: Operation) -> io::Result<Child> {
        Err(io::Error::other("compute must use its bounded runner"))
    }

    fn spawn_compute(
        &self,
        registration: &Registration,
        words: &[String],
        seconds: f64,
    ) -> io::Result<Child> {
        assert!(seconds > 0.0 && seconds <= 86400.0);
        if let Some(remaining) = &self.remaining {
            *remaining.lock().expect("remaining") = seconds;
        }
        let records = self.store.list().expect("filed intent").0;
        let record = records
            .iter()
            .find(|r| r.value()["run"] == registration.run)
            .expect("own record");
        assert_eq!(record.value()["worker_uid"], registration.worker_uid);
        assert_eq!(record.value()["effect"]["state"], "pending");
        if record.value()["mode"] != "allow"
            && record.value()["would_do"]["decision"] == "undecided"
        {
            assert_eq!(record.value()["label"]["treatment"], "allow");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut detail = compute::pending(words);
        detail["checkout_path"] = json!(format!("/node/lanes/{}", registration.run));
        detail["checkout_ref"] = json!(registration.mirror_ref);
        detail["checkout_commit"] = json!("a".repeat(40));
        detail["preparation_wall_seconds"] = json!(0.125);
        detail["wrapper_exit_status"] = json!(3);
        detail["wrapper_wall_seconds"] = json!(0.2);
        detail["wrapper_user_cpu_seconds"] = json!(0.02);
        detail["wrapper_system_cpu_seconds"] = json!(0.01);
        detail["tree_clean"] = json!(true);
        detail["tree_change_count"] = json!(0);
        detail["discarded"] = json!({"tracked":0,"untracked":0});
        crate::fixture_exec::spawn(
            Command::new(&self.program)
                .arg(json!({"reason":"door-complete","detail":detail}).to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
    }
}

pub(super) fn compute_service(
    fixture: &Fixture,
    run: &str,
    worker: u32,
    peer: u32,
    scope: Scope,
    decision: Option<&str>,
) -> (
    FixtureClient,
    Arc<AtomicUsize>,
    thread::JoinHandle<io::Result<Value>>,
) {
    let (socket, calls, server) = compute_stub_service(fixture, run, worker, peer, scope, decision);
    (
        FixtureClient::connect(socket).expect("connected compute client"),
        calls,
        server,
    )
}

pub(super) fn compute_stub_service(
    fixture: &Fixture,
    run: &str,
    worker: u32,
    peer: u32,
    scope: Scope,
    decision: Option<&str>,
) -> (
    PathBuf,
    Arc<AtomicUsize>,
    thread::JoinHandle<io::Result<Value>>,
) {
    compute_stub_service_with_policy(fixture, run, worker, peer, scope, decision, &[], None, None)
}

#[allow(clippy::too_many_arguments)]
fn compute_stub_service_with_policy(
    fixture: &Fixture,
    run: &str,
    worker: u32,
    peer: u32,
    scope: Scope,
    decision: Option<&str>,
    forms: &[super::config::ComputeDeadline],
    remaining: Option<Arc<std::sync::Mutex<f64>>>,
    contended: Option<std::sync::mpsc::Sender<()>>,
) -> (
    PathBuf,
    Arc<AtomicUsize>,
    thread::JoinHandle<io::Result<Value>>,
) {
    let socket = crate::fixture_exec::fixture_socket_path(
        fixture.home.join(format!("compute-{run}-{peer}.sock")),
    );
    let listener = UnixListener::bind(&socket).expect("socket");
    let program = fixture.home.join(format!("node-{run}"));
    crate::fixture_exec::write_executable(&program, b"#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nprint('generator output', flush=True)\nprint('generator stderr', file=sys.stderr)\nprint('RUN-REPORT exit=3 wall=0.2s rootfs_tmp_left=1G workspace_left=1T', file=sys.stderr)\nprint('DOOR-COMPUTE ' + sys.argv[1], file=sys.stderr)\nsys.exit(3)\n").expect("closed executable");
    let calls = Arc::new(AtomicUsize::new(0));
    let runner = NodeRunner {
        store: fixture.store(),
        calls: Arc::clone(&calls),
        program,
        remaining,
    };
    let route = route_for(&fixture.home).with_compute_deadlines(forms);
    let home = fixture.home.clone();
    let store = fixture.store();
    let registration = Registration::from_row(
        &json!({"name":"alpha","uid":41001}),
        "alpha",
        run,
        worker,
        scope,
    )
    .expect("registration");
    let rules = decision.map_or_else(Vec::new, |decision| vec![json!({"operation":"compute","shape_key":"compute:cargo run","decision":decision,"reason":"fixture rule"})]);
    let rubric = Rubric::decode(
        &json!({"schema":1,"class":"compute","undecided_reason":"fixture undecided","rules":rules}),
    )
    .expect("rubric");
    let filed = super::REQUEST_FILED.with(|slot| slot.borrow_mut().take());
    let ready = super::REQUEST_READY.with(|slot| slot.borrow_mut().take());
    let credit = super::WAIT_CREDIT_CAP.with(std::cell::Cell::take);
    let server = thread::spawn(move || {
        super::WAIT_CREDIT_OBSERVED.with(|slot| *slot.borrow_mut() = contended);
        super::REQUEST_FILED.with(|slot| *slot.borrow_mut() = filed);
        super::REQUEST_READY.with(|slot| *slot.borrow_mut() = ready);
        super::WAIT_CREDIT_CAP.with(|slot| slot.set(credit));
        let mut stream = FixtureServer::accept(&listener)?;
        let started = Instant::now();
        let request = fixture_request(&mut stream)?;
        serve_request(
            &mut stream,
            &registration,
            peer,
            &request,
            Some(&route),
            Some(&runner),
            Some(&home),
            Some(&rubric),
            Some(&store),
            started,
        )
        .map(|r| r.0)
    });
    (socket, calls, server)
}

fn compute_call(socket: &std::path::Path, command: &str) -> (Value, Vec<u8>, Vec<u8>) {
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let reply = crate::door::stub_call_stream(
        socket,
        &["fixture".into(), command.into()],
        io::Cursor::new(Vec::new()),
        &mut output,
        &mut errors,
    )
    .expect("stub call");
    (reply, output, errors)
}

fn request_command(fixture: &Fixture, action: &str) -> Value {
    fixture
        .command(&[action, "alpha"], b"")
        .expect("request reader")
}

/// ´test:unit:door-compute-generator-forms-use-production-entry´
#[test]
fn door_compute_generator_forms_use_production_entry() {
    for tail in [
        "cargo run --locked --bin generator -- write --root packages/project-a",
        "cargo run --locked --features docs,render -- check",
        "cargo run --locked --all-features --bin project-a-doc-gen -p project-a -- write --root=packages/project-a",
        "cargo run --locked --all-features --bin project-a-doc-gen -p project-a -- write --root packages/project-a",
        "cargo run --locked -- a b c d e f g h i j k l m n o p",
        "cargo run --locked --",
        "cargo run --locked",
    ] {
        for (run, worker) in [("R", 3000), ("S", 3001)] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let (socket, calls, server) =
                compute_stub_service(&fixture, run, worker, worker, Scope::Work, None);
            let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
            server.join().expect("server").expect("service");
            assert_eq!(reply["reason"], "door-complete", "{tail}: {reply}");
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let rows = fixture.store().list_run(run).expect("records");
            assert_eq!(rows[0].value()["worker_uid"], worker);
            assert_eq!(
                rows[0].value()["effect"]["compute"]["words"],
                json!(tail.split(' ').collect::<Vec<_>>())
            );
        }
    }
}

/// # Panics
/// Panics if preflight upload evidence reaches a reader or a refused read changes custody.
/// ´test:unit:door-preflight-readers-refuse-upload-evidence´
#[test]
fn door_preflight_readers_refuse_upload_evidence() {
    let fixture = Fixture::new();
    let (socket, calls, server) =
        compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
    let (reply, _, _) = compute_call(&socket, "/opt/fixture/bin/report cargo run --bin generator");
    server.join().expect("server").expect("service");
    assert_eq!(reply["reason"], "door-compute-locked-refusal");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let path = fixture.home.join("runs/.launch-R/door-requests.json");
    let original_bytes = std::fs::read(&path).expect("production preflight record");
    let original: Value = serde_json::from_slice(&original_bytes).expect("run record");
    let record = &original["requests"][0];
    assert_eq!(record["state"], "preflight-refused");
    assert!(record["effect"].get("bound").is_none());
    assert!(record["effect"].get("output_bytes").is_none());
    RequestRecord::decode(record.clone()).expect("ordinary preflight accepted");
    for action in ["status", "list"] {
        fixture
            .command(&[action, "alpha"], b"")
            .expect("ordinary preflight reader");
    }
    for evidence in [
        json!({"bound":1,"output_bytes":0}),
        json!({"bound":crate::requests::MAX_UPLOAD_OUTPUT_LIMIT,"output_bytes":0}),
        json!({"bound":1}),
        json!({"output_bytes":0}),
        json!({"bound":null,"output_bytes":null}),
    ] {
        let mut changed = original.clone();
        changed["requests"][0]["effect"]
            .as_object_mut()
            .expect("effect")
            .extend(evidence.as_object().expect("evidence").clone());
        let error = RequestRecord::decode(changed["requests"][0].clone())
            .expect_err("preflight upload evidence refused");
        assert_eq!(error.kind, "requests-record-refusal");
        assert_eq!(
            error.detail,
            "preflight refusals cannot contain upload output evidence"
        );
        let bytes = serde_json::to_vec(&changed).expect("changed record");
        fixture
            .store()
            .fixture_replace_run_bytes("R", &bytes)
            .expect("inject evidence");
        for action in ["status", "list"] {
            let error = fixture
                .command(&[action, "alpha"], b"")
                .expect_err("shared reader refuses preflight upload evidence");
            assert_eq!(error.kind, "requests-record-refusal");
            assert_eq!(
                error.detail,
                "preflight refusals cannot contain upload output evidence"
            );
            assert_eq!(std::fs::read(&path).expect("unchanged custody"), bytes);
        }
    }
    fixture
        .store()
        .fixture_replace_run_bytes("R", &original_bytes)
        .expect("restore record");
}

/// ´test:unit:door-compute-preflight-refusals-survive-request-readers´
#[test]
fn door_compute_preflight_refusals_survive_request_readers() {
    for (tail, check) in [
        (
            "cargo run --locked -- a b c d e f g h i j k l m n o p q",
            "door-compute-command-refusal",
        ),
        (
            "cargo run --locked -- write;id",
            "door-compute-words-refusal",
        ),
        (
            "cargo run --locked --bin bad/name",
            "door-compute-command-refusal",
        ),
        ("cargo run --bin generator", "door-compute-locked-refusal"),
        (
            "cargo run --features --locked",
            "door-compute-locked-refusal",
        ),
        (
            "cargo run --locked --features",
            "door-compute-command-refusal",
        ),
        ("cargo run --locked --bin", "door-compute-command-refusal"),
    ] {
        let fixture = Fixture::new();
        for (run, worker) in [("R", 3000), ("S", 3001)] {
            let command = format!("/opt/fixture/bin/report {tail}");
            let (socket, calls, server) =
                compute_stub_service(&fixture, run, worker, worker, Scope::Work, None);
            let (reply, _, _) = compute_call(&socket, &command);
            server.join().expect("server").expect("service");
            assert_eq!(reply["reason"], check, "{reply}");
            assert!(reply.get("request_record_error").is_none(), "{reply}");
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            let listed = request_command(&fixture, "list");
            let source_id = reply["request_id"].as_str().expect("source id");
            let record = listed["preflight_refusals"]
                .as_array()
                .expect("preflight refusal evidence")
                .iter()
                .find(|row| row["id"] == source_id)
                .expect("own refusal");
            assert_eq!(record["worker_uid"], worker);
            assert_eq!(record["run"], run);
            assert_eq!(record["state"], "preflight-refused");
            assert_eq!(
                record["effect"]["preflight"],
                json!({"check":check,"words":[b"fixture".to_vec(),command.into_bytes()]})
            );
            assert_eq!(record["effect"]["compute_wall_seconds"], 0.0);
            assert!(record["label"].is_null());
            let status = request_command(&fixture, "status");
            assert_eq!(status["preflight_refusals"], listed["preflight_refusals"]);
            let count: u64 = status["counts"]
                .as_array()
                .expect("status counts")
                .iter()
                .map(|row| row["count"].as_u64().expect("count"))
                .sum();
            assert_eq!(
                count,
                u64::try_from(listed["requests"].as_array().expect("list rows").len())
                    .expect("bounded list")
            );
            assert!(
                fixture
                    .store()
                    .review(reply["request_id"].as_str().expect("id"), "1")
                    .is_err()
            );
            for (pointer, bad) in [
                ("/effect/preflight/check", json!("unknown-check")),
                ("/effect/state", json!("completed")),
                ("/effect/preflight/words", json!("not byte arrays")),
                ("/effect/preflight/words", json!("x".repeat(65_537))),
                ("/state", json!("waiting")),
            ] {
                let mut invalid = record.clone();
                *invalid.pointer_mut(pointer).expect("field") = bad;
                assert!(
                    crate::requests::RequestRecord::decode(invalid).is_err(),
                    "{pointer}"
                );
            }
        }
    }
}

fn preflight_request(site: &str, run: &str) -> (Value, &'static str) {
    let mut request = json!({"schema":2,"argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report git status --short".to_vec()],"deadline_ms":1000});
    let expected = match site {
        "route" | "runner" => "door-compute-unregistered",
        "authority" => {
            request["argv"][0] = json!(b"other".to_vec());
            "door-caller-authority-refusal"
        }
        "shape" => {
            request["argv"] = json!([b"door-shape-probe".to_vec(), run.as_bytes().to_vec()]);
            "door-transport-pending"
        }
        "request" => {
            request["schema"] = json!(1);
            "door-request-refusal"
        }
        "invalid-argv" => {
            request["argv"] = json!({"invalid":"argv"});
            "door-request-refusal"
        }
        "non-utf8" => {
            request["argv"][1] = json!([255]);
            "door-compute-words-refusal"
        }
        "mirror" => {
            request["mirror_ref"] = json!("other");
            "door-changed-ref-refusal"
        }
        "owner" => "door-requests-unregistered",
        _ => {
            request["argv"][1] = json!(b"/opt/fixture/bin/report cargo run".to_vec());
            "door-compute-locked-refusal"
        }
    };
    (request, expected)
}

/// ´test:unit:door-preflight-sites-file-or-report-persistence-failure´
#[test]
fn door_preflight_sites_file_or_report_persistence_failure() {
    for site in [
        "route",
        "runner",
        "authority",
        "shape",
        "request",
        "invalid-argv",
        "non-utf8",
        "mirror",
        "owner",
        "capacity",
        "store",
        "store-open",
    ] {
        for (run, worker) in [("R", 3000), ("S", 3001)] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                run,
                worker,
                Scope::Work,
            )
            .expect("registration");
            let route = route_for(&fixture.home);
            let calls = Arc::new(AtomicUsize::new(0));
            let runner = NodeRunner {
                store: fixture.store(),
                calls: Arc::clone(&calls),
                program: fixture.home.join("must-not-run"),
                remaining: None,
            };
            let (request, expected) = preflight_request(site, run);
            let (mut client, mut server) = FixtureClient::pair().expect("pair");
            let missing_home = fixture.home.join("absent");
            let home = if site == "store-open" {
                &missing_home
            } else {
                &fixture.home
            };
            if site == "capacity" {
                crate::requests::store::fixture_file_cap(Some(0));
            }
            let result = serve_request(
                &mut server,
                &registration,
                worker,
                &request,
                (site != "route").then_some(&route),
                (site != "runner").then_some(&runner as &dyn Runner),
                (!matches!(site, "owner" | "store")).then_some(home.as_path()),
                None,
                (!matches!(site, "store" | "store-open")).then_some(&store),
                Instant::now(),
            );
            crate::requests::store::fixture_file_cap(None);
            let reply = result.expect("service").0;
            let frame = client.answer();
            assert_eq!(frame, reply);
            assert_eq!(reply["reason"], expected, "{site}: {reply}");
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            if matches!(site, "capacity" | "store" | "store-open") {
                assert_eq!(reply["request_record_state"], "failed");
                assert!(
                    reply["request_record_error"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                );
                assert!(store.list_run(run).expect("no record").is_empty());
            } else {
                let records = store.list_run(run).expect("records");
                assert_eq!(records.len(), 1, "{site}: {reply}");
                assert_eq!(records[0].value()["effect"]["preflight"]["check"], expected);
                assert_eq!(records[0].value()["worker_uid"], worker);
            }
        }
    }
}

/// ´test:unit:door-compute-service-modes-streams-and-attribution´
#[test]
fn door_compute_service_modes_streams_and_attribution() {
    for (floor, decision) in [
        ("allow", None),
        ("audit", None),
        ("enforce", None),
        ("enforce", Some("allow")),
        ("enforce", Some("refuse")),
    ] {
        let fixture = Fixture::new();
        fixture.set_floor(floor);
        let store = fixture.store();
        for (run, worker) in [("R", 3000), ("S", 3001)] {
            let (socket, calls, server) =
                compute_stub_service(&fixture, run, worker, worker, Scope::Work, decision);
            let client = thread::spawn(move || {
                compute_call(
                    &socket,
                    "/opt/fixture/bin/report cargo run -p generator --locked -- check",
                )
            });
            if floor != "allow" && decision.is_none() {
                let id = (0..200)
                    .find_map(|_| {
                        let rows = store.list_run(run).expect("records");
                        rows.first().map_or_else(
                            || {
                                thread::sleep(Duration::from_millis(5));
                                None
                            },
                            |row| Some(row.id().to_owned()),
                        )
                    })
                    .expect("waiting request");
                assert_eq!(calls.load(Ordering::Relaxed), 0);
                store.triage(run, &[json!({"id":id,"action":"adjudicate","treatment":"allow","reason":"fixture"})], "fixture", "1").expect("answer");
            }
            let (reply, output, errors) = client.join().expect("client");
            server.join().expect("server").expect("service");
            let rows = store.list_run(run).expect("stored request");
            assert_eq!(rows.len(), 1);
            let record = rows[0].value();
            assert_eq!(record["class"], "compute");
            assert_eq!(record["shape_key"], "compute:cargo run");
            assert_eq!(record["mode"], floor);
            assert_eq!(record["worker_uid"], worker);
            if decision == Some("refuse") {
                assert_eq!(reply["reason"], "door-rubric-refusal");
                assert_eq!(calls.load(Ordering::Relaxed), 0);
                continue;
            }
            assert_eq!(reply["status"], 3);
            assert_eq!(reply["reason"], "door-complete");
            assert_eq!(output, b"generator output\n");
            assert!(String::from_utf8_lossy(&errors).contains("RUN-REPORT exit=3"));
            assert_eq!(
                record["effect"]["compute"]["checkout_commit"],
                "a".repeat(40)
            );
            assert_eq!(record["effect"]["compute"]["wrapper_wall_seconds"], 0.2);
            assert_eq!(
                record["effect"]["compute"]["wrapper_user_cpu_seconds"],
                0.02
            );
            assert_eq!(
                record["effect"]["compute"]["wrapper_system_cpu_seconds"],
                0.01
            );
            assert_eq!(record["effect"]["compute"]["wrapper_exit_status"], 3);
            assert_eq!(record["effect"]["compute"]["tree_clean"], true);
            assert_eq!(record["effect"]["compute"]["tree_change_count"], 0);
            for key in ["tree_clean", "tree_change_count", "discarded"] {
                let mut incomplete = record.clone();
                incomplete["effect"]["compute"][key] = Value::Null;
                assert!(crate::requests::RequestRecord::decode(incomplete).is_err());
            }
            assert_eq!(
                record["effect"]["compute"]["checkout_ref"],
                format!("refs/heads/lane/{run}")
            );
            let seen = crate::launch::exercise::door_attribution::watch_requests(
                &store,
                run,
                &std::collections::HashSet::new(),
                &AtomicBool::new(true),
            )
            .expect("attribution read");
            assert_eq!(seen.records["compute"][0]["effect"], record["effect"]);
            assert_eq!(seen.answered, Vec::<String>::new());
            let observed =
                crate::launch::exercise::door_attribution::compute_observation(&seen.records);
            assert_eq!(observed["status"], "recorded");
            assert_eq!(observed["requests"][0]["effect"], record["effect"]);
        }
    }
}

/// # Panics
/// Panics only if fixture setup fails or admitted Cargo forms bypass judgement or lose wrapper evidence.
/// ´test:unit:door-compute-check-and-no-default-features-keep-judgement-and-wall´
#[test]
fn door_compute_check_and_no_default_features_keep_judgement_and_wall() {
    for (verb, words) in [
        ("check", "cargo check --locked"),
        ("check", "cargo check --locked --no-default-features"),
        (
            "check",
            "cargo --locked check --no-default-features --package pkg",
        ),
        ("test", "cargo test --locked --no-default-features"),
        ("test", "cargo --locked test --no-default-features -p pkg"),
        ("check", "cargo check --locked --lib"),
        ("check", "cargo check --locked --bins"),
        ("check", "cargo check --locked --tests"),
        ("check", "cargo check --locked --bin fixture"),
        ("check", "cargo check --locked --test fixture"),
        ("clippy", "cargo clippy --locked --lib -- -D warnings"),
        ("clippy", "cargo clippy --locked --bins -- -D warnings"),
        ("clippy", "cargo clippy --locked --tests -- -D warnings"),
        (
            "clippy",
            "cargo clippy --locked --bin fixture -- -D warnings",
        ),
        (
            "clippy",
            "cargo clippy --locked --test fixture -- -D warnings",
        ),
        ("test", "cargo test --locked --lib"),
        ("test", "cargo test --locked --bins"),
        ("test", "cargo test --locked --tests"),
        ("test", "cargo test --locked --bin fixture"),
        ("test", "cargo test --locked --test fixture"),
        // Regression fixture: this command refused before target selectors.
        (
            "check",
            "cargo check -p project-a --lib --no-default-features --locked",
        ),
    ] {
        for floor in ["allow", "audit", "enforce"] {
            let fixture = Fixture::new();
            fixture.set_floor(floor);
            let store = fixture.store();
            let (socket, calls, server) =
                compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
            let command = format!("/opt/fixture/bin/report {words}");
            let client = thread::spawn(move || compute_call(&socket, &command));
            if floor != "allow" {
                let deadline = Instant::now() + Duration::from_secs(10);
                let id = loop {
                    let rows = store.list_run("R").expect("pending custody");
                    if let Some(row) = rows.first()
                        && row.value()["state"] == "waiting"
                    {
                        break row.id().to_owned();
                    }
                    assert!(
                        Instant::now() < deadline,
                        "{floor}: {words} did not await judgement"
                    );
                    thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(calls.load(Ordering::Relaxed), 0);
                store.triage("R", &[json!({"id":id,"action":"adjudicate","treatment":"allow","reason":"fixture"})], "fixture", "1").expect("supervisory answer");
            }
            let (reply, _, _) = client.join().expect("client");
            server.join().expect("server").expect("served");
            assert_eq!(
                reply["reason"], "door-complete",
                "{floor}: {words}: {reply}"
            );
            assert_eq!(reply["status"], 3);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let records = store.list_run("R").expect("complete custody");
            assert_eq!(records.len(), 1);
            let record = records[0].value();
            assert_eq!(record["class"], "compute");
            assert_eq!(record["mode"], floor);
            assert_eq!(record["shape_key"], format!("compute:cargo {verb}"));
            assert_eq!(record["effect"]["state"], "completed");
            assert_eq!(record["effect"]["compute"]["wrapper_wall_seconds"], 0.2);
            assert_eq!(
                record["effect"]["compute"]["wrapper_user_cpu_seconds"],
                0.02
            );
            assert_eq!(
                record["effect"]["compute"]["wrapper_system_cpu_seconds"],
                0.01
            );
            assert_eq!(record["effect"]["compute"]["wrapper_exit_status"], 3);
            assert_eq!(
                record["effect"]["compute"]["words"],
                json!(words.split(' ').collect::<Vec<_>>())
            );
            if floor != "allow" {
                assert_eq!(record["label"]["treatment"], "allow");
            }
        }
    }
}

/// ´test:unit:door-compute-service-refusals-have-no-effect´
#[test]
fn door_compute_service_refusals_have_no_effect() {
    for (command, peer, scope, reason) in [
        (
            "/opt/fixture/bin/report cargo test --locked;id",
            3000,
            Scope::Work,
            "door-compute-words-refusal",
        ),
        (
            "/other/run-report.sh cargo test --locked",
            3000,
            Scope::Work,
            "door-compute-wrapper-refusal",
        ),
        (
            "/opt/fixture/bin/report cargo test",
            3000,
            Scope::Work,
            "door-compute-locked-refusal",
        ),
        (
            "/opt/fixture/bin/report cargo update --locked",
            3000,
            Scope::Work,
            "door-compute-command-refusal",
        ),
        (
            "/opt/fixture/bin/report git diff",
            3001,
            Scope::Work,
            "door-peer-refusal",
        ),
        (
            "/opt/fixture/bin/report git diff",
            3000,
            Scope::Review,
            "door-review-compute-refusal",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) = compute_stub_service(&fixture, "R", 3000, peer, scope, None);
        let (reply, _, _) = compute_call(&socket, command);
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], reason);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let rows = fixture.store().list().expect("store").0;
        if peer == 3000 {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].value()["state"], "preflight-refused");
            assert_eq!(rows[0].value()["effect"]["preflight"]["check"], reason);
        } else {
            assert!(rows.is_empty());
        }
    }
}

/// ´test:unit:door-compute-grammar-covers-corpus-and-shell-refusals´
#[test]
fn door_compute_grammar_covers_corpus_and_shell_refusals() {
    for tail in [
        "cargo fmt --all -- --check",
        "cargo fmt --all --check",
        "cargo fmt --all",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo doc --workspace --no-deps --locked",
        "cargo test --doc --locked",
        "cargo test --workspace --locked",
        "cargo test -p pkg --locked",
        "cargo test -p pkg --release --locked",
        "cargo run -p pkg --locked -- data",
        "cargo run -p pkg --locked -- render",
        "cargo run -p pkg --locked -- check",
        "git diff",
        "git diff --stat",
        "git status --short",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
        server.join().expect("server").expect("service");
        assert_eq!(reply["status"], 3, "{tail}: {reply}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(
            compute::parse(
                &[
                    b"fixture".to_vec(),
                    format!("/opt/fixture/bin/report {tail}").into_bytes()
                ],
                "fixture",
                "/opt/fixture/bin/report"
            )
            .is_ok(),
            "{tail}"
        );
    }
    for tail in [
        "cargo doc --locked --lib",
        "cargo run --locked --lib",
        "cargo run --locked --tests",
        "cargo run --locked --test fixture",
        "cargo check --locked --bin -x",
        "cargo check --locked --bin --all-features",
        "cargo test --locked --test",
        "cargo clippy --locked --bin pkg/x -- -D warnings",
        "cargo check --no-default-features",
        "cargo test --no-default-features",
        "cargo check --locked --config=x",
        "cargo test --locked;id",
        "cargo test --locked|id",
        "cargo test --locked&id",
        "cargo test --locked>file",
        "cargo test $X --locked",
        "cargo test 'x' --locked",
        "cargo test \"x\" --locked",
        "cargo test \\x --locked",
        "cargo\ttest --locked",
        "cargo  test --locked",
        "",
        "RUSTDOCFLAGS=-D warnings cargo doc --locked",
        "cargo add pkg --locked",
        "cargo test --locked --config=x",
        "bash -c id",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
        server.join().expect("server").expect("service");
        assert_eq!(reply["status"], 125);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(
            compute::parse(
                &[
                    b"fixture".to_vec(),
                    format!("/opt/fixture/bin/report {tail}").into_bytes()
                ],
                "fixture",
                "/opt/fixture/bin/report"
            )
            .is_err(),
            "{tail}"
        );
    }
}

/// ´test:unit:door-compute-gates-preserve-lock-placement-and-shape´
#[test]
fn door_compute_gates_preserve_lock_placement_and_shape() {
    for tail in [
        "cargo clippy -p pkg --all-targets --all-features -- -D warnings",
        "cargo clippy --package pkg --all-targets --all-features -- -D warnings",
        "cargo test -p pkg --all-features",
        "cargo test --package pkg --all-features",
        "cargo test -p pkg",
        "cargo doc -p pkg --no-deps",
        "cargo test --doc",
        "cargo test --workspace",
        "cargo run --all-features --bin generator -p pkg -- write --root packages/project-a",
        "cargo run --release -p superloop-lint -- check --root .",
    ] {
        let words: Vec<_> = tail.split(' ').collect();
        let end = words
            .iter()
            .position(|word| *word == "--")
            .unwrap_or(words.len());
        for position in 1..=end {
            if matches!(words[position - 1], "-p" | "--package" | "--bin") {
                continue;
            }
            let mut locked = words.clone();
            locked.insert(position, "--locked");
            let command = format!("/opt/fixture/bin/report {}", locked.join(" "));
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let (socket, calls, server) =
                compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
            let (reply, _, _) = compute_call(&socket, &command);
            server.join().expect("server").expect("service");
            assert_eq!(reply["reason"], "door-complete", "{command}: {reply}");
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let records = fixture.store().list_run("R").expect("record reader");
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].value()["shape_key"],
                format!("compute:cargo {}", words[1])
            );
            assert_eq!(
                records[0].value()["effect"]["compute"]["words"],
                json!(locked)
            );
        }
    }
    for package in ["pkg_1-name".to_owned(), "a".repeat(256)] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let (reply, _, _) = compute_call(
            &socket,
            &format!(
                "/opt/fixture/bin/report cargo test --package {package} --all-features --locked"
            ),
        );
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], "door-complete", "{reply}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

/// ´test:unit:door-compute-test-no-run-retains-exact-argv´
#[test]
fn door_compute_test_no_run_retains_exact_argv() {
    for tail in [
        "cargo test -p fixture --locked --no-run",
        "cargo --locked test -p fixture --no-default-features --no-run",
        "cargo test -p fixture --locked --all-features --no-run",
        "cargo test --locked --test integration --no-run",
        "cargo test --locked --bin fixture --no-run",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], "door-complete", "{tail}: {reply}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let records = fixture.store().list_run("R").expect("record reader");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value()["effect"]["compute"]["words"],
            json!(tail.split(' ').collect::<Vec<_>>())
        );
    }
}

/// ´test:unit:door-compute-test-no-run-refuses-other-verbs-and-forwarding´
#[test]
fn door_compute_test_no_run_refuses_other_verbs_and_forwarding() {
    for tail in [
        "cargo check --locked --no-run",
        "cargo clippy --locked --no-run -- -D warnings",
        "cargo doc --locked --no-run",
        "cargo run --locked --no-run",
        "cargo test --locked --test integration -- --no-run",
        "cargo test --locked --test integration -- filter --no-run",
    ] {
        assert_compute_preflight(
            &format!("/opt/fixture/bin/report {tail}"),
            "door-compute-command-refusal",
        );
    }
}

/// ´test:unit:door-compute-test-filters-retain-exact-argv´
#[test]
fn door_compute_test_filters_retain_exact_argv() {
    for tail in [
        "cargo test -p fixture --all-features --locked --test integration module::case_2",
        "cargo --locked test --test integration module::case_2",
        "cargo test --locked --test integration -- module::case_2",
        "cargo test --locked --test integration -- module::case_2 --exact",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], "door-complete", "{tail}: {reply}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let records = fixture.store().list_run("R").expect("record reader");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value()["effect"]["compute"]["words"],
            json!(tail.split(' ').collect::<Vec<_>>())
        );
    }
}

/// ´test:unit:door-compute-test-filters-refuse-extra-or-unbound-words´
#[test]
fn door_compute_test_filters_refuse_extra_or_unbound_words() {
    for tail in [
        "cargo test --locked --test integration first second",
        "cargo test --locked --test integration filter --all-features",
        "cargo test --locked --test integration first -- second --exact",
        "cargo test --locked --test integration -- first second --exact",
        "cargo test --locked --test integration -- filter --nocapture",
        "cargo test --locked --test integration -- --exact",
        "cargo test --locked --test integration filter.name",
        "cargo test --locked --test integration filter-name",
        "cargo test --locked --test integration path/name",
        "cargo test --locked filter",
        "cargo test --locked --bin integration filter",
        "cargo check --locked --test integration filter",
        "cargo clippy --locked --test integration filter -- -D warnings",
    ] {
        assert_compute_preflight(
            &format!("/opt/fixture/bin/report {tail}"),
            "door-compute-command-refusal",
        );
    }
}

/// ´test:unit:door-compute-test-filters-refuse-empty-misplaced-and-late-lock-words´
#[test]
fn door_compute_test_filters_refuse_empty_misplaced_and_late_lock_words() {
    for (tail, check) in [
        ("cargo test --locked --test integration --", "command"),
        (
            "cargo test --locked --test integration --  --exact",
            "words",
        ),
        ("cargo test --locked filter --test integration", "command"),
        (
            "cargo test --locked --test integration filter --exact",
            "command",
        ),
        ("cargo test --test integration filter --locked", "locked"),
    ] {
        assert_compute_preflight(
            &format!("/opt/fixture/bin/report {tail}"),
            &format!("door-compute-{check}-refusal"),
        );
    }
}

/// ´test:unit:door-compute-target-selectors-refuse-dash-led-names´
#[test]
fn door_compute_target_selectors_refuse_dash_led_names() {
    for verb in ["check", "clippy", "test"] {
        for selector in ["--bin", "--test"] {
            for name in ["-x", "--all-features"] {
                let suffix = if verb == "clippy" {
                    " -- -D warnings"
                } else {
                    ""
                };
                assert_compute_preflight(
                    &format!(
                        "/opt/fixture/bin/report cargo {verb} --locked {selector} {name}{suffix}"
                    ),
                    "door-compute-command-refusal",
                );
            }
        }
    }
}

/// ´test:unit:door-compute-preserves-dash-led-package-records´
#[test]
fn door_compute_preserves_dash_led_package_records() {
    for tail in [
        "cargo test --locked -p --all-features",
        "cargo doc --locked -p --no-deps",
        "cargo run --locked -p --release -- check --root .",
        "cargo run --locked --bin -x",
        "cargo run --locked --bin --all-features",
        "cargo test --locked -p --locked",
        "cargo test --locked -p -pkg --all-features",
        "cargo clippy --locked -p -pkg --all-features -- -D warnings",
        "cargo clippy --locked -p --locked --all-features -- -D warnings",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
        let command = format!("/opt/fixture/bin/report {tail}");
        let (reply, _, _) = compute_call(&socket, &command);
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], "door-complete", "{command}: {reply}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let records = fixture
            .store()
            .list_run("R")
            .expect("stored compute record decodes");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value()["effect"]["compute"]["words"],
            json!(tail.split(' ').collect::<Vec<_>>())
        );
    }
}

/// ´test:unit:door-compute-run-bin-shares-the-dash-p-value-bound´
#[test]
fn door_compute_run_bin_shares_the_dash_p_value_bound() {
    for selector in ["-p", "--bin"] {
        for name in ["a".repeat(256), "-x".to_owned()] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let (socket, calls, server) =
                compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
            let (reply, _, _) = compute_call(
                &socket,
                &format!("/opt/fixture/bin/report cargo run --locked {selector} {name}"),
            );
            server.join().expect("server").expect("service");
            assert_eq!(
                reply["reason"], "door-complete",
                "{selector} {name}: {reply}"
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }
        for (name, check) in [
            ("a".repeat(257), "words"),
            ("pkg.name".to_owned(), "command"),
            ("--".to_owned(), "command"),
        ] {
            assert_compute_preflight(
                &format!("/opt/fixture/bin/report cargo run --locked {selector} {name}"),
                &format!("door-compute-{check}-refusal"),
            );
        }
    }
}

fn assert_compute_preflight(command: &str, check: &str) {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let (socket, calls, server) =
        compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
    let (reply, _, _) = compute_call(&socket, command);
    server.join().expect("server").expect("service");
    assert_eq!(reply["status"], 125, "{command}: {reply}");
    assert_eq!(reply["reason"], check, "{command}: {reply}");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(
        reply["mediation_wall_seconds"]
            .as_f64()
            .is_some_and(|wall| wall.is_finite() && wall >= 0.0)
    );
    assert_eq!(reply["compute_wall_seconds"], 0.0);
    let records = fixture.store().list_run("R").expect("record reader");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value()["effect"]["preflight"]["check"], check);
    assert_eq!(
        records[0].value()["effect"]["mediation_wall_seconds"],
        reply["mediation_wall_seconds"]
    );
}

/// ´test:unit:door-compute-gates-keep-package-and-refusal-bounds´
#[test]
fn door_compute_gates_keep_package_and_refusal_bounds() {
    for selector in ["-p", "--package"] {
        for verb in ["test", "clippy"] {
            let suffix = if verb == "clippy" {
                " -- -D warnings"
            } else {
                ""
            };
            for (package, check) in [
                (String::new(), "words"),
                ("a".repeat(257), "words"),
                ("pkg/name".to_owned(), "command"),
                ("pkg.name".to_owned(), "command"),
                ("pkg*".to_owned(), "words"),
                ("pkg;id".to_owned(), "words"),
                ("é".to_owned(), "words"),
            ] {
                assert_compute_preflight(
                    &format!(
                        "/opt/fixture/bin/report cargo {verb} --locked {selector} {package} --all-features{suffix}"
                    ),
                    &format!("door-compute-{check}-refusal"),
                );
            }
        }
    }
    for verb in ["test", "clippy"] {
        let suffix = if verb == "clippy" {
            " -- -D warnings"
        } else {
            ""
        };
        for package in ["-pkg", "--locked"] {
            assert_compute_preflight(
                &format!(
                    "/opt/fixture/bin/report cargo {verb} --locked --package {package}{suffix}"
                ),
                "door-compute-command-refusal",
            );
        }
    }
    for (tail, check) in [
        ("cargo test -p pkg --all-features", "locked"),
        (
            "cargo clippy --package pkg --all-features -- -D warnings",
            "locked",
        ),
        ("cargo test --package --locked", "locked"),
        ("cargo test -p --locked", "locked"),
        ("cargo test -p pkg -- --locked", "locked"),
        ("cargo clippy -p pkg -- -D warnings --locked", "locked"),
        ("cargo --locked test --package --locked", "command"),
        ("cargo test --locked -p pkg -- --locked", "command"),
        ("cargo clippy --locked -p pkg --all-features", "command"),
        (
            "cargo clippy --locked -p pkg -- -D warnings extra",
            "command",
        ),
        ("cargo test --locked --config=x", "command"),
        ("cargo update --locked", "command"),
        ("cargo --locked update", "command"),
        ("cargo --locked fmt --all -- --check", "command"),
        ("cargo fmt --all -- --check extra", "command"),
        ("cargo test --locked;id", "words"),
    ] {
        assert_compute_preflight(
            &format!("/opt/fixture/bin/report {tail}"),
            &format!("door-compute-{check}-refusal"),
        );
    }
}

/// ´test:unit:door-compute-floor-preserves-existing-mode-history´
#[test]
fn door_compute_floor_preserves_existing_mode_history() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.ensure_first_mode("ssh").expect("first audit");
    let old = store.modes().expect("history");
    fixture.set_floor("allow");
    let store = fixture.store();
    let setting = store.ensure_first_mode("compute").expect("new class");
    assert_eq!(setting["class"]["mode"], "allow");
    assert_eq!(setting["loop"]["mode"], "audit");
    assert_eq!(setting["mode"], "audit");
    assert_eq!(
        store.ensure_first_mode("ssh").expect("old class")["class"]["mode"],
        "audit"
    );
    let new = store.modes().expect("new history");
    assert!(
        old["loop_settings"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    );
    assert_eq!(old["loop_settings"], new["loop_settings"]);
    let old_ssh = old["classes"]
        .as_array()
        .expect("old classes")
        .iter()
        .find(|row| row["class"] == "ssh")
        .expect("old ssh");
    let new_ssh = new["classes"]
        .as_array()
        .expect("new classes")
        .iter()
        .find(|row| row["class"] == "ssh")
        .expect("new ssh");
    assert_eq!(old_ssh, new_ssh);
}

/// ´test:unit:door-compute-node-refresh-and-mechanical-diff´
#[test]
fn door_compute_node_refresh_and_mechanical_diff() {
    let fixture = tempfile::tempdir().expect("node fixture");
    let result = crate::fixture_exec::output(
        Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(include_str!("compute_node_tests.py"))
            .arg(compute::NODE_SCRIPT)
            .arg(fixture.path()),
    )
    .expect("node program fixture");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

/// ´test:unit:door-node-retirement-marker-lock-and-removal-evidence´
#[test]
fn door_node_retirement_marker_lock_and_removal_evidence() {
    let fixture = tempfile::tempdir().expect("retirement fixture");
    let result = crate::fixture_exec::output(
        Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(include_str!("retire_node_tests.py"))
            .arg(include_str!("retire_node.py"))
            .arg(compute::NODE_SCRIPT)
            .arg(fixture.path()),
    )
    .expect("retirement helper fixture");
    writeln!(io::stdout(), "{}", String::from_utf8_lossy(&result.stdout)).expect("fixture wall");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

/// ´test:unit:door-compute-retired-run-reason-reaches-service-output´
#[test]
fn door_compute_retired_run_reason_reaches_service_output() {
    for (run, worker) in [("R", 3000), ("S", 3001)] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) =
            compute_stub_service(&fixture, run, worker, worker, Scope::Work, None);
        crate::fixture_exec::write_executable(&fixture.home.join(format!("node-{run}")), b"#!/usr/bin/python3\nimport sys,json\nsys.stdin.buffer.read()\ne=json.loads(sys.argv[1])\ne['reason']='door-compute-retired-run'\nprint('DOOR-COMPUTE '+json.dumps(e),file=sys.stderr)\nsys.exit(125)\n").expect("retired node");
        let (reply, _, _) = compute_call(&socket, "/opt/fixture/bin/report git diff");
        server.join().expect("server").expect("service");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(reply["reason"], "door-compute-retired-run");
        assert_eq!(reply["status"], 125);
        let records = fixture.store().list_run(run).expect("effect");
        assert_eq!(
            records[0].value()["effect"]["reason"],
            "door-compute-retired-run"
        );
    }
}

/// ´test:unit:door-compute-root-refusal-preserves-node-path-and-evidence´
#[test]
fn door_compute_root_refusal_preserves_node_path_and_evidence() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let (socket, calls, server) =
        compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
    crate::fixture_exec::write_executable(&fixture.home.join("node-R"), b"#!/usr/bin/python3\nimport sys,json\nsys.stdin.buffer.read()\ne=json.loads(sys.argv[1])\ne['reason']='door-compute-root-refusal'\nprint('node_root is not an existing absolute directory: /node/missing',file=sys.stderr)\nprint('DOOR-COMPUTE '+json.dumps(e),file=sys.stderr)\nsys.exit(125)\n").expect("root refusal node");
    let (reply, _, stderr) = compute_call(&socket, "/opt/fixture/bin/report git diff");
    server.join().expect("server").expect("service");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(reply["reason"], "door-compute-root-refusal");
    assert_eq!(reply["status"], 125);
    assert!(String::from_utf8_lossy(&stderr).contains("/node/missing"));
    let rows = fixture.store().list_run("R").expect("effect");
    assert_eq!(
        rows[0].value()["effect"]["reason"],
        "door-compute-root-refusal"
    );
}

/// ´test:unit:door-compute-queue-deadline-and-disconnect-have-no-effect´
#[test]
fn door_compute_queue_deadline_and_disconnect_have_no_effect() {
    for (run, worker, disconnect) in [("R", 3000, false), ("S", 3001, true)] {
        let fixture = Fixture::new();
        let (ready, filed) = std::sync::mpsc::sync_channel(1);
        let (release, proceed) = std::sync::mpsc::sync_channel(1);
        super::WAIT_CREDIT_CAP.with(|slot| slot.set(Some(0)));
        super::REQUEST_READY.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |_| {
                ready.send(()).expect("filed request");
                proceed
                    .recv_timeout(super::tests::FIXTURE_HANG)
                    .expect("peer action");
                Ok(if disconnect {
                    Instant::now() + super::tests::FIXTURE_HANG
                } else {
                    Instant::now()
                })
            }));
        });
        let (socket, calls, server) =
            compute_service(&fixture, run, worker, worker, Scope::Work, None);
        let mut client = socket;
        client.send(&json!({"schema":2,"argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report git diff".to_vec()],"deadline_ms":120_000})).expect("request");
        filed
            .recv_timeout(super::tests::FIXTURE_HANG)
            .expect("request ready");
        assert_eq!(client.event("compute-deadline")["type"], "compute-deadline");
        let reason = if disconnect {
            drop(client);
            release.send(()).expect("observe closed peer");
            "door-disconnect-refusal"
        } else {
            release.send(()).expect("expire at readiness");
            let reply = client.answer();
            assert_eq!(reply["reason"], "door-request-deadline");
            "door-request-deadline"
        };
        let reply = server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], reason);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let rows = fixture.store().list_run(run).expect("records");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value()["effect"]["reason"], reason);
        assert_eq!(
            rows[0].value()["effect"]["compute"]["checkout_commit"],
            Value::Null
        );
    }
}

/// ´test:unit:door-compute-record-is-strict-and-evidence-is-required´
#[test]
fn door_compute_record_is_strict_and_evidence_is_required() {
    let words = vec!["git".to_owned(), "diff".to_owned()];
    let detail = compute::pending(&words);
    assert!(compute::valid_detail(&detail));
    let mut changed = detail.clone();
    changed["extra"] = json!(true);
    assert!(!compute::valid_detail(&changed));
    let mut changed = detail;
    changed["checkout_commit"] = json!("not-a-commit");
    assert!(!compute::valid_detail(&changed));
    let mut reply = json!({"reason":"door-complete","status":0,"compute_exit_status":0});
    compute::finish(&mut reply, &words, b"ordinary output without a report\n");
    assert_eq!(reply["reason"], "door-compute-evidence-refusal");
    assert_eq!(reply["status"], 125);
    for exit in [124, 137] {
        let mut detail = compute::pending(&words);
        detail["wrapper_exit_status"] = json!(exit);
        detail["wrapper_wall_seconds"] = json!(0.01);
        detail["wrapper_user_cpu_seconds"] = json!(0.0);
        detail["wrapper_system_cpu_seconds"] = json!(0.0);
        let evidence = format!(
            "RUN-REPORT exit={exit} wall=0.01s\nDOOR-COMPUTE {}\n",
            json!({"reason":"door-complete","detail":detail})
        );
        let mut reply = json!({"reason":"door-complete","status":exit,"compute_exit_status":exit});
        compute::finish(&mut reply, &words, evidence.as_bytes());
        assert_eq!(reply["reason"], "door-complete");
        assert_eq!(reply["status"], exit);
        assert_eq!(reply["compute"]["wrapper_exit_status"], exit);
        assert_eq!(reply["compute"]["wrapper_wall_seconds"], 0.01);
    }
    for exit in [126, 127] {
        let mut reply = json!({"reason":"door-complete","status":exit,"compute_exit_status":exit});
        compute::finish(&mut reply, &words, b"missing executable\n");
        assert_eq!(reply["reason"], "door-compute-tool-refusal");
    }
    let mut reply = json!({"reason":"door-complete","status":125,"compute_exit_status":125});
    compute::finish(&mut reply, &words, b"DOOR-COMPUTE-TOOL-REFUSAL\n");
    assert_eq!(reply["reason"], "door-compute-tool-refusal");
    let mut changed = compute::pending(&words);
    changed["tree_clean"] = json!(true);
    changed["tree_change_count"] = json!(1);
    assert!(!compute::valid_detail(&changed));
    changed["tree_change_count"] = json!(0);
    assert!(compute::valid_detail(&changed));
    changed["discarded"] = json!({"tracked":0,"untracked":-1});
    assert!(!compute::valid_detail(&changed));
}

/// ´test:unit:door-compute-running-deadline-keeps-remote-outcome-unmeasured´
#[test]
fn door_compute_running_deadline_keeps_remote_outcome_unmeasured() {
    for (run, worker, disconnect) in [("R", 3000, false), ("S", 3001, true)] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (ready, spawned) = std::sync::mpsc::sync_channel(1);
        let (release, proceed) = std::sync::mpsc::sync_channel(1);
        super::REQUEST_READY.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |_| {
                super::transport::fixture_after_spawn(move || {
                    ready.send(()).expect("spawn observed");
                    proceed
                        .recv_timeout(super::tests::FIXTURE_HANG)
                        .expect("peer action after spawn");
                    if disconnect {
                        Instant::now() + super::tests::FIXTURE_HANG
                    } else {
                        Instant::now()
                    }
                });
                Ok(Instant::now() + super::tests::FIXTURE_HANG)
            }));
        });
        let (socket, calls, server) =
            compute_service(&fixture, run, worker, worker, Scope::Work, None);
        crate::fixture_exec::write_executable(
            &fixture.home.join(format!("node-{run}")),
            b"#!/usr/bin/python3\nimport signal\nsignal.pause()\n",
        )
        .expect("closed slow executable");
        let mut client = socket;
        client.send(&json!({"schema":2,"argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report git diff".to_vec()],"deadline_ms":120_000})).expect("request");
        client.shutdown(Shutdown::Write).expect("input end");
        spawned
            .recv_timeout(super::tests::FIXTURE_HANG)
            .expect("running child before stop");
        if disconnect {
            drop(client);
            release.send(()).expect("observe full close");
        } else {
            release.send(()).expect("expire running deadline");
            assert_eq!(client.event("compute-deadline")["type"], "compute-deadline");
            let reply = client.answer();
            assert_eq!(reply["reason"], "door-deadline-refusal");
            assert_eq!(reply["remote"]["state"], "unconfirmed");
            assert!(
                reply["remote"]["bound_seconds"]
                    .as_f64()
                    .is_some_and(|n| n > 0.0)
            );
            assert_eq!(reply["remote"]["start"], "unobserved");
            assert_eq!(reply["wall_clock"], "monotonic-awake");
            let line = super::final_line(
                &["fixture".into(), "/opt/fixture/bin/report git diff".into()],
                &reply,
            )
            .expect("stop line");
            assert!(line.contains("the remote command is unconfirmed"));
            assert!(line.contains(&format!(
                    "up to {:.0} s after it started",
                    reply["remote"]["bound_seconds"]
                        .as_f64()
                        .expect("bound")
                        .ceil()
                )));
            assert!(line.contains("report this stop to your loop"));
            assert!(!line.contains("remote_bound_seconds="));
            #[allow(clippy::print_stderr)] // Captured caller evidence.
            {
                eprintln!("STOPPED-REPLY {reply}\nSTUB-LINE {line}");
            }
            assert!(reply["compute"]["wrapper_exit_status"].is_null());
        }
        let result = server.join().expect("server ends");
        if !disconnect {
            result.expect("service");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let rows = fixture.store().list_run(run).expect("record");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].value()["effect"]["compute"]["wrapper_exit_status"].is_null());
        assert_eq!(
            rows[0].value()["effect"]["ending"]["wall_clock"],
            "monotonic-awake"
        );
        #[allow(clippy::print_stderr)] // Captured terminal evidence.
        {
            eprintln!("STOPPED-RECORD {}", rows[0].value());
        }
        assert_eq!(
            rows[0].value()["effect"]["ending"]["cause"],
            if disconnect { "disconnect" } else { "deadline" }
        );
    }
}

/// ´test:unit:door-compute-deadline-selects-only-the-exact-owner-form´
#[test]
fn door_compute_deadline_selects_only_the_exact_owner_form() {
    let form = super::config::ComputeDeadline {
        words: ["cargo", "test", "--locked", "-p", "fixture"]
            .map(str::to_owned)
            .to_vec(),
        deadline_ms: 3_600_000,
    };
    for induce_wait in [false, true] {
        for (tail, bound) in [
            ("cargo test --locked -p fixture", 3_600_000),
            ("cargo test --locked -p other", compute::DEADLINE_MS),
            (
                "cargo test --locked -p fixture --release",
                compute::DEADLINE_MS,
            ),
            ("cargo --locked test -p fixture", compute::DEADLINE_MS),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            store
                .ensure_first_mode("compute")
                .expect("initial compute mode");
            let (contended, release) = if induce_wait {
                let held = store.fixture_exclusive_lock().expect("competing writer");
                let (contended, observed) = std::sync::mpsc::channel();
                let release = thread::spawn(move || {
                    observed
                        .recv_timeout(Duration::from_secs(10))
                        .expect("measured store contention");
                    drop(held);
                });
                (Some(contended), Some(release))
            } else {
                (None, None)
            };
            let remaining = Arc::new(std::sync::Mutex::new(0.0));
            let (socket, calls, server) = compute_stub_service_with_policy(
                &fixture,
                "R",
                3000,
                3000,
                Scope::Work,
                None,
                std::slice::from_ref(&form),
                Some(Arc::clone(&remaining)),
                contended,
            );
            let (reply, _, _) = compute_call(&socket, &format!("/opt/fixture/bin/report {tail}"));
            server.join().expect("server").expect("service");
            let credit = reply["request_lock_wait_credit_ms"]
                .as_u64()
                .expect("credit");
            if let Some(release) = release {
                release.join().expect("holder released");
                assert!(credit >= 50);
            }
            assert_eq!(reply["effective_deadline_ms"], bound + credit);
            assert_eq!(reply["reason"], "door-complete");
            assert_eq!(reply["registered_deadline_ms"], bound);
            assert_eq!(reply["request_deadline_ms"], bound);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let remaining = *remaining.lock().expect("remaining");
            assert!(remaining <= Duration::from_millis(bound).as_secs_f64());
            if bound > compute::DEADLINE_MS {
                assert!(remaining > 1800.0);
            }
        }
    }
}

fn compute_refusal_frame(client: &mut FixtureClient) -> (Value, u64) {
    // Preserve the credit assertions; an ordinary final reader would discard them.
    let mut observed_credit = 0;
    loop {
        let frame = super::frame_read(client.wire()).expect("deadline progress or final");
        if frame["type"] != "request-lock-wait" {
            assert_eq!(frame["type"], "final");
            return (frame, observed_credit);
        }
        assert_eq!(frame["schema"], 2);
        let credit = frame["wait_ms"].as_u64().expect("credit milliseconds");
        assert!(credit >= observed_credit && credit <= super::MAX_LOCK_WAIT_CREDIT_MS);
        observed_credit = credit;
    }
}

fn compute_refusal_call(socket: &std::path::Path, use_stub: bool) -> (Value, Option<u64>) {
    if use_stub {
        let previous = super::transport::STUB_TEST_BUDGET.with(|slot| slot.replace(Some(1000)));
        let (reply, _, _) = compute_call(socket, "/opt/fixture/bin/report cargo test --locked");
        super::transport::STUB_TEST_BUDGET.with(|slot| slot.set(previous));
        return (reply, None);
    }
    let mut client = FixtureClient::connect(socket).expect("socket");
    client.send(&json!({"schema":2,"argv":[b"fixture".to_vec(),b"/opt/fixture/bin/report cargo test --locked".to_vec()],"deadline_ms":1000})).expect("shorter caller bound");
    client.shutdown(Shutdown::Write).expect("EOF");
    // The deadline announcement precedes admission and every request-lock wait.
    let announcement = super::frame_read(client.wire()).expect("announcement");
    assert_eq!(announcement["type"], "compute-deadline");
    assert_eq!(announcement["registered_deadline_ms"], 3_600_000);
    assert_eq!(announcement["request_deadline_ms"], 1000);
    let (reply, observed_credit) = compute_refusal_frame(&mut client);
    (reply, Some(observed_credit))
}

fn compute_queue_refusal(
    fixture: &Fixture,
    filed: std::sync::mpsc::Receiver<String>,
) -> thread::JoinHandle<()> {
    let store = fixture.store();
    thread::spawn(move || {
        let id = filed
            .recv_timeout(Duration::from_secs(120))
            .expect("compute request filed");
        store.triage("R", &[json!({"id":id,"action":"adjudicate","treatment":"refuse","reason":"fixture refusal"})], "fixture", "1").expect("queued refusal");
    })
}

fn compute_deadline_refusal_case(
    floor: &str,
    reason: &str,
    queue: &str,
    induce_wait: bool,
    use_stub: bool,
) {
    let fixture = Fixture::new();
    fixture.set_floor(floor);
    let store = fixture.store();
    store
        .ensure_first_mode("compute")
        .expect("initial compute mode");
    let (contended, release) = if induce_wait {
        let held = store.fixture_exclusive_lock().expect("competing writer");
        let (contended, observed) = std::sync::mpsc::channel();
        let release = thread::spawn(move || {
            observed
                .recv_timeout(Duration::from_secs(120))
                .expect("measured store contention");
            drop(held);
        });
        (Some(contended), Some(release))
    } else {
        (None, None)
    };
    let form = super::config::ComputeDeadline {
        words: ["cargo", "test", "--locked"].map(str::to_owned).to_vec(),
        deadline_ms: 3_600_000,
    };
    let (filed_tx, filed_rx) = std::sync::mpsc::channel();
    if queue == "refused" {
        super::REQUEST_FILED.with(|slot| *slot.borrow_mut() = Some(filed_tx));
    }
    let (socket, calls, server) = compute_stub_service_with_policy(
        &fixture,
        "R",
        3000,
        3000,
        Scope::Work,
        None,
        &[form],
        None,
        contended,
    );
    let answer = (queue == "refused").then(|| compute_queue_refusal(&fixture, filed_rx));
    let (reply, observed_credit) = compute_refusal_call(&socket, use_stub);
    server.join().expect("server").expect("service");
    if let Some(answer) = answer {
        answer.join().expect("queued refusal recorded");
    }
    let credit = reply["request_lock_wait_credit_ms"]
        .as_u64()
        .expect("credit");
    if let Some(release) = release {
        release.join().expect("holder released after progress");
        assert!(credit >= 50);
        if let Some(observed_credit) = observed_credit {
            assert!(observed_credit >= 50);
            assert!(credit >= observed_credit);
        }
    }
    assert!(credit <= super::MAX_LOCK_WAIT_CREDIT_MS);
    assert_eq!(reply["effective_deadline_ms"], 1000 + credit);
    assert_eq!(reply["reason"], reason);
    assert_eq!(reply["queue_state"], queue);
    assert_eq!(reply["registered_deadline_ms"], 3_600_000);
    assert_eq!(reply["request_deadline_ms"], 1000);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let expected_line = if reason == "door-request-deadline" {
        "door-request-deadline: registered_deadline_ms=3600000 request_deadline_ms=1000"
    } else {
        "door-adjudicated-refusal"
    };
    let line = super::final_line(&["fixture".into(), "cargo test".into()], &reply).expect("notice");
    if reason == "door-request-deadline" {
        assert!(line.starts_with(expected_line), "{line}");
        assert!(line.contains("no remote command started"), "{line}");
        #[allow(clippy::print_stderr)]
        {
            eprintln!("UNSTARTED-STUB-LINE {line}");
        }
        assert!(
            !line.contains("null") && !line.contains("unobserved"),
            "{line}"
        );
        assert!(
            line.contains("ask again through the ordinary door route"),
            "{line}"
        );
    } else {
        assert_eq!(line, expected_line);
    }
}

/// ´test:unit:door-compute-deadline-refusal-names-the-owner-bound´
#[test]
fn door_compute_deadline_refusal_names_the_owner_bound() {
    for (induce_wait, use_stub) in [(false, false), (true, false), (true, true)] {
        for (floor, reason, queue) in [
            ("allow", "door-request-deadline", "no-queue"),
            ("enforce", "door-request-deadline", "deadline"),
            ("enforce", "door-adjudicated-refusal", "refused"),
        ] {
            compute_deadline_refusal_case(floor, reason, queue, induce_wait, use_stub);
        }
    }
}

/// ´test:unit:door-compute-node-measurements-do-not-require-a-report-line´
#[test]
fn door_compute_node_measurements_do_not_require_a_report_line() {
    let words = vec!["git".to_owned(), "diff".to_owned()];
    let mut detail = compute::pending(&words);
    detail["wrapper_exit_status"] = json!(3);
    detail["wrapper_wall_seconds"] = json!(0.8);
    detail["wrapper_user_cpu_seconds"] = json!(0.2);
    detail["wrapper_system_cpu_seconds"] = json!(0.1);
    let evidence = format!(
        "DOOR-COMPUTE {}\n",
        json!({"reason":"door-complete","detail":detail})
    );
    let mut reply = json!({"reason":"door-complete","status":3,"compute_exit_status":3});
    compute::finish(&mut reply, &words, evidence.as_bytes());
    assert_eq!(reply["reason"], "door-complete");
    assert_eq!(reply["compute"], detail);
    assert!(reply.get("run_report").is_none());
    let mut wrong_exit = detail.clone();
    wrong_exit["wrapper_exit_status"] = json!(4);
    let evidence = format!(
        "DOOR-COMPUTE {}\n",
        json!({"reason":"door-complete","detail":wrong_exit})
    );
    let mut reply = json!({"reason":"door-complete","status":3,"compute_exit_status":3});
    compute::finish(&mut reply, &words, evidence.as_bytes());
    assert_eq!(
        reply["reason"], "door-compute-evidence-refusal",
        "node status must match the transport status"
    );
    let mut unmeasured = detail.clone();
    unmeasured["wrapper_user_cpu_seconds"] = Value::Null;
    unmeasured["wrapper_system_cpu_seconds"] = Value::Null;
    assert!(
        compute::valid_detail(&unmeasured),
        "historical CPU remains unmeasured"
    );
    let evidence = format!(
        "DOOR-COMPUTE {}\n",
        json!({"reason":"door-complete","detail":unmeasured})
    );
    let mut reply = json!({"reason":"door-complete","status":3,"compute_exit_status":3});
    compute::finish(&mut reply, &words, evidence.as_bytes());
    assert_eq!(
        reply["reason"], "door-compute-evidence-refusal",
        "new completion requires CPU measurement"
    );
    for key in [
        "wrapper_wall_seconds",
        "wrapper_user_cpu_seconds",
        "wrapper_system_cpu_seconds",
    ] {
        let mut invalid = detail.clone();
        invalid[key] = json!(-1);
        assert!(!compute::valid_detail(&invalid), "{key}");
        invalid.as_object_mut().expect("detail").remove(key);
        assert!(!compute::valid_detail(&invalid), "{key}");
    }
    let mut missing = json!({"reason":"door-complete","status":3,"compute_exit_status":3});
    compute::finish(&mut missing, &words, b"RUN-REPORT exit=3 wall=0.2s\n");
    assert_eq!(missing["reason"], "door-compute-evidence-refusal");
    assert_eq!(
        missing["run_report"],
        json!({"wall_seconds":0.2,"exit_status":3})
    );
    assert!(missing["compute"]["wrapper_wall_seconds"].is_null());
}

/// ´test:unit:door-rejected-compute-announces-before-admission´
#[test]
fn door_rejected_compute_announces_before_admission() {
    for (command, scope, reason) in [
        (
            "/wrong/wrapper cargo test --locked",
            Scope::Work,
            "door-compute-wrapper-refusal",
        ),
        (
            "/opt/fixture/bin/report cargo test --locked;id",
            Scope::Work,
            "door-compute-words-refusal",
        ),
        (
            "/opt/fixture/bin/report cargo test",
            Scope::Work,
            "door-compute-locked-refusal",
        ),
        (
            "/opt/fixture/bin/report git diff",
            Scope::Review,
            "door-review-compute-refusal",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            scope,
        )
        .expect("registration");
        let held = super::RequestGuard::acquire(&fixture.home, &registration)
            .expect("guard")
            .expect("free admission");
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, scope, None);
        let mut client = socket;
        client.send(&json!({"schema":2,"argv":[b"fixture".to_vec(),command.as_bytes().to_vec()],"deadline_ms":60000})).expect("compute-shaped request");
        let announced = client.event("compute-deadline");
        assert_eq!(announced["type"], "compute-deadline");
        assert_eq!(announced["registered_deadline_ms"], compute::DEADLINE_MS);
        assert_eq!(announced["request_deadline_ms"], 60000);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(
            fixture
                .store()
                .list_run("R")
                .expect("no preflight before admission")
                .is_empty()
        );
        drop(held);
        let reply = client.answer();
        server.join().expect("server").expect("service");
        assert_eq!(reply["reason"], reason);
        assert_eq!(reply["status"], 125);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

/// ´test:unit:door-compute-report-refusals-keep-inner-and-node-measurements´
#[test]
fn door_compute_report_refusals_keep_inner_and_node_measurements() {
    let words = vec!["git".to_owned(), "diff".to_owned()];
    let mut detail = compute::pending(&words);
    detail["wrapper_exit_status"] = json!(3);
    detail["wrapper_wall_seconds"] = json!(0.8);
    detail["wrapper_user_cpu_seconds"] = json!(0.2);
    detail["wrapper_system_cpu_seconds"] = json!(0.1);
    for (report, expected, reported) in [
        (
            "RUN-REPORT exit=3 wall=0.2s\n",
            "door-complete",
            Some(json!({"wall_seconds":0.2,"exit_status":3})),
        ),
        (
            "RUN-REPORT exit=2 wall=0.2s\n",
            "door-compute-report-contradiction",
            Some(json!({"wall_seconds":0.2,"exit_status":2})),
        ),
        (
            "RUN-REPORT exit=3 wall=2.0s\n",
            "door-compute-report-contradiction",
            Some(json!({"wall_seconds":2.0,"exit_status":3})),
        ),
        (
            "RUN-REPORT malformed\n",
            "door-compute-report-refusal",
            Some(json!({"wall_seconds":null,"exit_status":null})),
        ),
        (
            "RUN-REPORT exit=3 wall=-0.2s\n",
            "door-compute-report-refusal",
            Some(json!({"wall_seconds":-0.2,"exit_status":3})),
        ),
        (
            "RUN-REPORT exit=3 wall=NaNs\n",
            "door-compute-report-refusal",
            Some(json!({"wall_seconds":null,"exit_status":3})),
        ),
    ] {
        let evidence = format!(
            "{report}DOOR-COMPUTE {}\n",
            json!({"reason":"door-complete","detail":detail})
        );
        let mut reply = json!({"reason":"door-complete","status":3,"compute_exit_status":3});
        compute::finish(&mut reply, &words, evidence.as_bytes());
        assert_eq!(reply["reason"], expected, "{report}");
        assert_eq!(reply["compute"]["wrapper_exit_status"], 3);
        assert_eq!(reply["compute_exit_status"], 3);
        assert_eq!(reply["compute"]["wrapper_wall_seconds"], 0.8);
        assert_eq!(reply["compute"]["wrapper_user_cpu_seconds"], 0.2);
        assert_eq!(reply["compute"]["wrapper_system_cpu_seconds"], 0.1);
        assert_eq!(reply.get("run_report"), reported.as_ref());
        assert_eq!(
            reply["status"],
            if expected == "door-complete" { 3 } else { 125 }
        );
    }
}

/// ´test:unit:door-root-refusal-announces-before-admission´
#[test]
fn door_root_refusal_announces_before_admission() {
    let fixture = Fixture::new();
    let registration = Registration::from_row(
        &json!({"name":"alpha","uid":41001}),
        "alpha",
        "R",
        3000,
        Scope::Work,
    )
    .expect("registration");
    let held = super::RequestGuard::acquire(&fixture.home, &registration)
        .expect("guard")
        .expect("free admission");
    let (mut client, mut service) = FixtureClient::pair().expect("socket pair");
    let home = fixture.home.clone();
    let server = thread::spawn(move || {
        let home_fd = std::fs::File::open(&home).expect("home");
        let runs = home.join("runs");
        let runs_fd = std::fs::File::open(&runs).expect("runs");
        let _namespace = crate::home::activate_private_launch(
            &home,
            &home_fd,
            &runs,
            &runs_fd,
            None,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("private fixture namespace");
        let request = fixture_request(&mut service).expect("request");
        super::root_refusal(
            &mut service,
            &registration,
            3000,
            &request,
            &home,
            &crate::error::LaneError::input("door-compute-root-refusal", "fixture root absent"),
            Instant::now(),
        )
    });
    client.send(&json!({"schema":2,"argv":[b"fixture".to_vec(),b"/opt/fixture/bin/report git diff".to_vec()],"deadline_ms":60000})).expect("request");
    let announced = client.event("compute-deadline");
    assert_eq!(announced["type"], "compute-deadline");
    assert_eq!(announced["registered_deadline_ms"], compute::DEADLINE_MS);
    assert!(
        fixture
            .store()
            .list_run("R")
            .expect("no premature record")
            .is_empty()
    );
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(5);
    // Here stderr is asserted as well as the answer; lock credits are intermediate.
    let reply = loop {
        let frame = super::frame_read_until(client.wire(), deadline)
            .expect("root diagnostic, credit or final");
        if frame.get("reason").is_some() {
            break frame;
        }
        assert!(matches!(
            frame["type"].as_str(),
            Some("stderr" | "request-lock-wait")
        ));
    };
    server.join().expect("server").expect("root refusal");
    assert_eq!(reply["reason"], "door-compute-root-refusal");
    assert_eq!(reply["status"], 125);
    let rows = fixture.store().list_run("R").expect("refusal record");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value()["state"], "preflight-refused");
}

/// ´test:unit:door-compute-report-contradiction-reaches-stub-and-record´
#[test]
fn door_compute_report_contradiction_reaches_stub_and_record() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let (socket, calls, server) =
        compute_stub_service(&fixture, "R", 3000, 3000, Scope::Work, None);
    let program = fixture.home.join("node-R");
    let source = std::fs::read_to_string(&program).expect("fixture node program");
    let contradicting =
        source.replace("RUN-REPORT exit=3 wall=0.2s", "RUN-REPORT exit=7 wall=1.5s");
    assert_ne!(source, contradicting, "fixture report replaced");
    crate::fixture_exec::write_executable(&program, contradicting.as_bytes())
        .expect("contradicting inner report");
    let (reply, stdout, _) = compute_call(&socket, "/opt/fixture/bin/report git diff");
    let service_reply = server
        .join()
        .expect("server")
        .expect("served contradiction");
    let wire_reply: Value =
        serde_json::from_slice(&serde_json::to_vec(&service_reply).expect("encode service reply"))
            .expect("decode service reply");
    assert_eq!(reply, wire_reply, "stub retains the complete wire reply");
    assert_eq!(reply["reason"], "door-compute-report-contradiction");
    assert_eq!(reply["status"], 125);
    assert_eq!(reply["compute_exit_status"], 3);
    assert_eq!(
        reply["run_report"],
        json!({"wall_seconds":1.5,"exit_status":7})
    );
    assert_eq!(reply["compute"]["wrapper_exit_status"], 3);
    assert_eq!(reply["compute"]["wrapper_wall_seconds"], 0.2);
    assert_eq!(reply["compute"]["wrapper_user_cpu_seconds"], 0.02);
    assert_eq!(reply["compute"]["wrapper_system_cpu_seconds"], 0.01);
    assert_eq!(stdout, b"generator output\n");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let rows = fixture.store().list_run("R").expect("persisted effect");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value()["effect"]["reason"],
        "door-compute-report-contradiction"
    );
    assert_eq!(rows[0].value()["effect"]["compute"], reply["compute"]);
    assert!(rows[0].value()["effect"].get("run_report").is_none());
}
