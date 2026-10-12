use super::tests::route_for;
use super::transport::{Operation, Runner};
use super::{
    Registration, Scope, compute, frame_read, frame_read_until, frame_write, serve_request,
};
use crate::requests::{
    modes::Rubric,
    store::{Store, tests::Fixture},
};
use serde_json::{Value, json};
use std::io::{self, Write as _};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
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
        assert!(seconds > 0.0 && seconds <= 1800.0);
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

fn compute_service(
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
    };
    let route = route_for(&fixture.home);
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
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let started = Instant::now();
        let request = frame_read_until(&mut stream, started + Duration::from_secs(2))?;
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
                compute_service(&fixture, run, worker, worker, Scope::Work, None);
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
                compute_service(&fixture, run, worker, worker, Scope::Work, None);
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
            };
            let (request, expected) = preflight_request(site, run);
            let (mut server, mut client) = UnixStream::pair().expect("pair");
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
            assert_eq!(frame_read(&mut client).expect("frame"), reply);
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
                compute_service(&fixture, run, worker, worker, Scope::Work, decision);
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
                compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, peer, scope, None);
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
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
                compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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

/// ´test:unit:door-compute-preserves-dash-led-package-records´
#[test]
fn door_compute_preserves_dash_led_package_records() {
    for tail in [
        "cargo test --locked -p --all-features",
        "cargo doc --locked -p --no-deps",
        "cargo run --locked -p --release -- check --root .",
        "cargo test --locked -p --locked",
        "cargo test --locked -p -pkg --all-features",
        "cargo clippy --locked -p -pkg --all-features -- -D warnings",
        "cargo clippy --locked -p --locked --all-features -- -D warnings",
    ] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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

fn assert_compute_preflight(command: &str, check: &str) {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
            compute_service(&fixture, run, worker, worker, Scope::Work, None);
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
    let (socket, calls, server) = compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
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
        let (socket, calls, server) =
            compute_service(&fixture, run, worker, worker, Scope::Work, None);
        let mut client = UnixStream::connect(socket).expect("client");
        frame_write(&mut client, &json!({"schema":2,"argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report git diff".to_vec()],"deadline_ms":100})).expect("request");
        if disconnect {
            drop(client);
        } else {
            let reply = frame_read(&mut client).expect("deadline reply");
            assert_eq!(reply["reason"], "door-request-deadline");
        }
        server.join().expect("server").expect("service");
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let rows = fixture.store().list_run(run).expect("records");
        assert_eq!(rows.len(), 1);
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
        let (socket, calls, server) =
            compute_service(&fixture, run, worker, worker, Scope::Work, None);
        crate::fixture_exec::write_executable(
            &fixture.home.join(format!("node-{run}")),
            b"#!/usr/bin/python3\nimport time\ntime.sleep(20)\n",
        )
        .expect("closed slow executable");
        let mut client = UnixStream::connect(socket).expect("client");
        frame_write(&mut client, &json!({"schema":2,"argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report git diff".to_vec()],"deadline_ms":11_000})).expect("request");
        client.shutdown(Shutdown::Write).expect("input end");
        if disconnect {
            drop(client);
        } else {
            let reply = frame_read_until(&mut client, Instant::now() + Duration::from_secs(15))
                .expect("deadline reply");
            assert_eq!(reply["reason"], "door-deadline-refusal");
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
    }
}
