// Included in the door tests to reuse the production-handler fixture.

/// # Panics
/// Panics only if the isolated fixture fails or overlapping requests corrupt custody.
/// ´test:unit:door-concurrent-request-refuses-before-record´
#[test]
fn door_concurrent_request_refuses_before_record() {
    const CHILD: &str = "SUPERLOOP_DOOR_CONCURRENT_CHILD";
    if std::env::var(CHILD).as_deref() == Ok("peer") {
        concurrent_process_peer();
        return;
    }
    if std::env::var_os(CHILD).is_none() {
        let output = concurrent_fixture_command()
            .env(CHILD, "1")
            .output()
            .expect("built concurrency fixture");
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let (runner, calls, _) = counting_runner(&fixture);
    let (socket, first) = fixture_service(&fixture, runner, rubric(Some("allow")), 120_000, None);
    let mut client = UnixStream::connect(socket).expect("first connection");
    frame_write(
        &mut client,
        &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
    )
    .expect("first request");
    let id = wait_filed(&store);
    let deadline = Instant::now() + Duration::from_secs(120);
    while store.request(&id).expect("first record").value()["state"] != "waiting" {
        assert!(
            Instant::now() < deadline,
            "first request did not await judgement"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // Repeat the overlap to prove a rejected claimant cannot release the first guard.
    for running in [false, true] {
        if running {
            label(&store, &id, "allow");
            while calls.load(Ordering::Relaxed) == 0 {
                assert!(Instant::now() < deadline, "first effect did not start");
                thread::sleep(Duration::from_millis(5));
            }
        }
        let reply = concurrent_process_request(&fixture, 3000, false);
        assert_eq!(reply["status"], 125);
        assert_eq!(reply["reason"], "door-request-concurrent");
        assert_eq!(
            reply["admission_window"],
            "the door waited for admission held through the durable effect and final reply; allow-mode agent publication may finish after admission is released; retry after 30 seconds"
        );
        let waited = reply["waited_seconds"].as_f64().expect("measured wait");
        assert_eq!(Duration::from_secs_f64(waited), Duration::from_secs(1));
        assert_eq!(reply["retry_after_seconds"], 30);
        assert!(reply.get("request_id").is_none());
        assert!(reply.get("request_record_error").is_none());
        let records = store.list_run("R").expect("unchanged custody");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id(), id);
        assert_eq!(records[0].value()["effect"]["state"], "pending");
    }
    client
        .shutdown(Shutdown::Write)
        .expect("release first effect");
    let reply = frame_read(&mut client).expect("first final frame");
    assert_eq!(reply["reason"], "door-complete");
    assert_eq!(reply["status"], 0);
    first.join().expect("first thread").expect("first served");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let record = store.request(&id).expect("complete record");
    assert_eq!(record.value()["effect"]["state"], "completed");
    assert_eq!(record.value()["state"], "adjudicated");
    // Completion releases admission, including for a subsequent refusal record.
    let (runner, _, _) = counting_runner(&fixture);
    let (socket, next) = fixture_service(&fixture, runner, rubric(None), 120_000, None);
    let mut peer = UnixStream::connect(socket).expect("next connection");
    frame_write(&mut peer, &json!({"schema":2})).expect("next request");
    let reply = frame_read(&mut peer).expect("next refusal");
    assert_eq!(reply["reason"], "door-request-refusal");
    assert!(reply["request_id"].is_string());
    next.join().expect("next thread").expect("next served");
    assert_eq!(store.list_run("R").expect("two records").len(), 2);
}

fn concurrent_fixture_command() -> Command {
    concurrent_fixture_command_for("door::tests::door_concurrent_request_refuses_before_record")
}

fn concurrent_fixture_command_for(test: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("concurrency test executable"));
    command.args(["--exact", test, "--nocapture"]);
    command
}

fn concurrent_registration(uid: u32) -> Registration {
    Registration::from_row(
        &json!({"name":"alpha","uid":2001}),
        "alpha",
        "R",
        uid,
        Scope::Work,
    )
    .expect("registration")
}

fn concurrent_namespace(home: &std::path::Path) -> crate::home::PrivateHomeGuard {
    let home_fd = File::open(home).expect("fixture home");
    let runs = home.join("runs");
    let runs_fd = File::open(&runs).expect("fixture runs");
    crate::home::activate_private_launch(
        home,
        &home_fd,
        &runs,
        &runs_fd,
        None,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("fixture namespace")
}

fn concurrent_process_peer() {
    let home =
        PathBuf::from(std::env::var_os("SUPERLOOP_DOOR_CONCURRENT_HOME").expect("peer home"));
    let socket = std::env::var_os("SUPERLOOP_DOOR_CONCURRENT_SOCKET").expect("peer socket");
    let _namespace = concurrent_namespace(&home);
    let uid = std::env::var("SUPERLOOP_DOOR_CONCURRENT_UID")
        .expect("peer uid")
        .parse()
        .expect("numeric uid");
    let registration = concurrent_registration(uid);
    let mut stream = UnixStream::connect(socket).expect("peer connection");
    let request = frame_read(&mut stream).expect("peer request");
    let clock = std::rc::Rc::new(ControlledAdmissionClock::default());
    let started = super::AdmissionClock::now(clock.as_ref());
    super::ADMISSION_CLOCK.with(|slot| *slot.borrow_mut() = Some(clock));
    if std::env::var_os("SUPERLOOP_DOOR_CONCURRENT_ROOT").is_some() {
        super::root_refusal(
            &mut stream,
            &registration,
            uid,
            &request,
            &home,
            &super::LaneError::input("fixture-root", "root absent"),
            started,
        )
        .expect("root refusal");
    } else {
        serve_request(
            &mut stream,
            &registration,
            uid,
            &request,
            None,
            None,
            Some(&home),
            None,
            None,
            started,
        )
        .expect("peer served");
    }
}

fn concurrent_process_request(fixture: &Fixture, uid: u32, root: bool) -> Value {
    let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join(format!(
        "peer-{}.sock",
        super::REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )));
    let listener = UnixListener::bind(&socket).expect("peer listener");
    let mut command = concurrent_fixture_command();
    command
        .env("SUPERLOOP_DOOR_CONCURRENT_CHILD", "peer")
        .env("SUPERLOOP_DOOR_CONCURRENT_HOME", &fixture.home)
        .env("SUPERLOOP_DOOR_CONCURRENT_SOCKET", &socket)
        .env("SUPERLOOP_DOOR_CONCURRENT_UID", uid.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if root {
        command.env("SUPERLOOP_DOOR_CONCURRENT_ROOT", "1");
    }
    let child = command.spawn().expect("separate handler process");
    let (mut stream, _) = listener.accept().expect("separate handler connected");
    frame_write(&mut stream, &json!({"schema":2,"deadline_ms":3000})).expect("peer request");
    let reply = frame_read(&mut stream).expect("peer reply");
    let output = child.wait_with_output().expect("peer completion");
    assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
    if reply["reason"] == "door-request-concurrent" {
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("door preflight: run=R check=door-request-concurrent"),
            "{output:?}"
        );
    }
    reply
}

/// # Panics
/// Panics only if the isolated handlers fail to enforce the admission boundary.
/// ´test:unit:door-concurrent-root-refusal-and-independent-boxes´
#[test]
fn door_concurrent_root_refusal_and_independent_boxes() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let (mut client, mut server) = UnixStream::pair().expect("root pair");
    let home = fixture.home.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let root = thread::spawn(move || {
        let _namespace = concurrent_namespace(&home);
        super::ROOT_ADMITTED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                entered_tx.send(()).expect("root admitted");
                release_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("release root");
            }));
        });
        super::root_refusal(
            &mut server,
            &concurrent_registration(3000),
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"]}),
            &home,
            &super::LaneError::input("fixture-root", "root absent"),
            Instant::now(),
        )
    });
    entered_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("root holds admission");
    // Hold before publication and before the bounded socket write, independent of spawn speed.
    let reply = concurrent_process_request(&fixture, 3000, true);
    assert_eq!(reply["reason"], "door-request-concurrent");
    assert_eq!(reply["status"], 125);
    assert_eq!(reply["retry_after_seconds"], 30);
    assert_eq!(reply["waited_seconds"], json!(1.0));
    assert!(reply.get("request_id").is_none());
    let independent = concurrent_process_request(&fixture, 3001, false);
    assert_eq!(independent["reason"], "door-request-refusal");
    assert!(independent["request_id"].is_string());
    assert_eq!(store.list_run("R").expect("independent records").len(), 1);
    release_tx.send(()).expect("release root publication");
    loop {
        let frame = frame_read(&mut client).expect("root diagnostic or final");
        if frame["type"] == "final" {
            assert_eq!(frame["reason"], "door-compute-root-refusal");
            let id = frame["request_id"].as_str().expect("root record id");
            assert_eq!(
                store.request(id).expect("root record").value()["effect"]["reason"],
                "door-compute-root-refusal"
            );
            break;
        }
    }
    root.join().expect("root thread").expect("root final");
    assert_eq!(
        concurrent_process_request(&fixture, 3000, false)["reason"],
        "door-request-refusal"
    );
}

/// # Panics
/// Panics only if two synthetic boxes lose records, skip contention or exceed the store wait.
/// ´test:unit:door-two-boxes-share-the-bounded-store-wait´
#[test]
fn door_two_boxes_share_the_bounded_store_wait() {
    use crate::requests::store::{AFTER_WRITER_LOCK_ACQUIRED, AFTER_WRITER_LOCK_CONTENTION};
    use std::sync::mpsc;

    const CHILD: &str = "SUPERLOOP_DOOR_STORE_WAIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = concurrent_fixture_command_for(
            "door::tests::door_two_boxes_share_the_bounded_store_wait",
        )
        .env(CHILD, "1")
        .output()
        .expect("isolated two-box fixture");
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (contended_tx, contended_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let home = fixture.home.clone();
    let first = thread::spawn(move || {
        let _namespace = concurrent_namespace(&home);
        let store = Store::open(&home, "alpha", true).expect("first store");
        AFTER_WRITER_LOCK_ACQUIRED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                held_tx.send(()).expect("first writer holds store");
                release_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("release writer");
            }));
        });
        bounded_box_request(&home, &store, 3000)
    });
    held_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("first request entered store");
    let home = fixture.home;
    let second = thread::spawn(move || {
        let _namespace = concurrent_namespace(&home);
        let store = Store::open(&home, "alpha", true).expect("second store");
        AFTER_WRITER_LOCK_CONTENTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                contended_tx.send(()).expect("second writer contended");
            }));
        });
        let reply = bounded_box_request(&home, &store, 3001);
        done_tx.send(reply).expect("second completion");
    });
    contended_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("second box independently admitted and waiting on store");
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release_tx.send(()).expect("release first writer");
    let second_reply = done_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("second completes after release");
    let first_reply = first.join().expect("first box");
    second.join().expect("second box");
    assert_ne!(first_reply["request_id"], second_reply["request_id"]);
    let records = store.list_run("R").expect("both requests retained");
    assert_eq!(records.len(), 2);
    for reply in [first_reply, second_reply] {
        let id = reply["request_id"].as_str().expect("filed request");
        assert!(records.iter().any(|record| record.id() == id));
    }
}

fn bounded_box_request(home: &std::path::Path, store: &Store, uid: u32) -> Value {
    let (mut client, mut server) = UnixStream::pair().expect("box socket pair");
    let (reply, _) = serve_request(
        &mut server,
        &concurrent_registration(uid),
        uid,
        &json!({"schema":2}),
        None,
        None,
        Some(home),
        None,
        Some(store),
        Instant::now(),
    )
    .expect("box request completes");
    assert_eq!(frame_read(&mut client).expect("final reply"), as_sent(&reply));
    assert_eq!(reply["reason"], "door-request-refusal");
    assert!(reply["request_id"].is_string());
    assert!(reply.get("request_record_error").is_none());
    reply
}

struct CapturedAdmissionAgent {
    input: std::sync::mpsc::Sender<Value>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl super::agent::AgentRunner for CapturedAdmissionAgent {
    fn judge(&self, input: &[u8], _: Duration) -> super::agent::RunnerOutcome {
        self.input.send(serde_json::from_slice(input).expect("agent input"))
            .expect("captured prompt");
        self.release.lock().expect("agent release")
            .recv_timeout(FIXTURE_HANG).expect("release agent");
        let mut result = super::agent::RunnerOutcome::referral("verdict", "fixture advice", Instant::now());
        result.verdict = "refuse".into();
        result.scope = "loop".into();
        result
    }
}

struct HistoryCall {
    client: UnixStream,
    input: std::sync::mpsc::Receiver<Value>,
    slot_released: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
    handler: thread::JoinHandle<io::Result<(Value, Vec<u8>)>>,
}

fn history_call(fixture: &Fixture) -> HistoryCall {
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let (slot_tx, slot_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let agent = CapturedAdmissionAgent { input: input_tx, release: Mutex::new(release_rx) };
    let route = route_for(&fixture.home);
    let (runner, _, _) = counting_runner(fixture);
    let (client, mut server) = UnixStream::pair().expect("history pair");
    client.shutdown(Shutdown::Write).expect("EOF");
    let home = fixture.home.clone();
    let store = fixture.store();
    let handler = thread::spawn(move || {
        super::AFTER_ALLOW_ADMISSION_RELEASE.with(|slot| *slot.borrow_mut() = Some(slot_tx));
        super::serve_request_with_agent(
            &mut server, &concurrent_registration(3000), 3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
            Some(&route), Some(&runner), Some(&home), None,
            Some(&store), Some(&agent), None, Instant::now(),
        )
    });
    HistoryCall { client, input: input_rx, slot_released: slot_rx, release: release_tx, handler }
}

fn history_entry(input: &Value, id: &str) -> Value {
    input["shape_record"].as_array().expect("history").iter()
        .find(|row| row["id"] == id).expect("earlier filed entry").clone()
}

/// # Panics
/// Panics if a final reply retains admission or agent advice gains label authority.
/// ´test:unit:door-concurrent-allow-agent-publication-window´
#[test]
fn door_concurrent_allow_agent_publication_window() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let store = fixture.store();
    let mut first = history_call(&fixture);
    first.input.recv_timeout(FIXTURE_HANG).expect("first agent held");
    assert_eq!(fixture_final_frame(&mut first.client)["reason"], "door-complete");
    first.slot_released.recv_timeout(FIXTURE_HANG).expect("slot released while agent held");
    let id = store.list_run("R").expect("first filed")[0].id().to_owned();
    assert_eq!(store.request(&id).expect("effect").value()["effect"]["state"], "completed");
    let began = Instant::now();
    let mut second = history_call(&fixture);
    let input = second.input.recv_timeout(FIXTURE_HANG).expect("same-worker second agent overlaps");
    let _measured = writeln!(io::stderr().lock(), "admission-history second_agent_wait_ms={}", began.elapsed().as_millis());
    assert_eq!(store.list_run("R").expect("both filed").len(), 2);
    assert_eq!(history_entry(&input, &id)["would_do"]["decision"], "undecided");
    assert_eq!(fixture_final_frame(&mut second.client)["reason"], "door-complete");
    second.slot_released.recv_timeout(FIXTURE_HANG).expect("second slot released");
    first.release.send(()).expect("first advice released");
    first.handler.join().expect("first handler").expect("first publication");
    assert_eq!(store.request(&id).expect("advice recorded").value()["would_do"]["decision"], "refuse");
    let mut third = history_call(&fixture);
    let input = third.input.recv_timeout(FIXTURE_HANG).expect("unlabelled advice remains a miss");
    assert_eq!(history_entry(&input, &id)["would_do"]["decision"], "refuse");
    assert!(history_entry(&input, &id)["label"].is_null());
    assert_eq!(fixture_final_frame(&mut third.client)["reason"], "door-complete");
    for call in [second, third] {
        call.release.send(()).expect("release remaining agent");
        call.handler.join().expect("handler").expect("publication");
    }
    assert_eq!(store.list_run("R").expect("three agent requests").len(), 3);
}

/// # Panics
/// Panics only if unavailable admission custody loses the root preflight name.
/// ´test:unit:door-root-admission-custody-failure-keeps-preflight-name´
#[test]
fn door_root_admission_custody_failure_keeps_preflight_name() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let lock = fixture
        .home
        .join(".config/loops/alpha/door-admission-3000.lock");
    fs::create_dir(&lock).expect("invalid lock type");
    let (mut server, mut client) = UnixStream::pair().expect("root pair");
    super::root_refusal(
        &mut server,
        &concurrent_registration(3000),
        3000,
        &json!({"schema":2,"argv":[b"door-attribution-probe"]}),
        &fixture.home,
        &super::LaneError::input("fixture-root", "root absent"),
        Instant::now(),
    )
    .expect("named root refusal");
    assert_eq!(
        frame_read(&mut client).expect("diagnostic")["type"],
        "stderr"
    );
    let reply = frame_read(&mut client).expect("root final");
    assert_eq!(reply["reason"], "door-compute-root-refusal");
    assert_eq!(reply["request_record_state"], "failed");
    assert!(
        reply["request_record_error"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(reply.get("request_id").is_none());
    assert!(store.list_run("R").expect("no unlocked write").is_empty());
}

/// # Panics
/// Panics only if the exercise does not retry a temporary admission refusal.
/// ´test:unit:door-exercise-retries-concurrent-admission´
#[test]
fn door_exercise_retries_concurrent_admission() {
    let fixture = Fixture::new();
    let _route = route_for(&fixture.home);
    let registration = concurrent_registration(3000);
    let guard = super::RequestGuard::acquire(&fixture.home, &registration)
        .expect("lock")
        .expect("admitted");
    let retried = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = std::rc::Rc::clone(&retried);
    super::EXERCISE_RETRY_OBSERVED.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            observed.set(true);
            // Release only after the first admission refusal, proving a retry occurred.
            drop(guard);
        }));
    });
    // The service spends its admission budget on logical polls; the release follows
    // the observed refusal, so the retry window remains only a hang bound.
    let (result, clock) = super::with_fixture_admission_clock(Duration::from_secs(120), || {
        super::fixture_agent_call(
            &fixture.home,
            &registration,
            "fixture-retry",
            Some("allow"),
            Some("allow"),
            Some(Arc::new(super::CatRunner)),
            None,
        )
    });
    let report = result.expect("retried fixture");
    assert!(retried.get(), "first admission refusal was not observed");
    assert_eq!(clock.waited(), super::ADMISSION_WAIT);
    assert_eq!(clock.attempts(), 2, "one refusal then one admitted retry");
    assert_eq!(report["final"]["reason"], "door-complete", "{report}");
    assert_eq!(
        fixture
            .store()
            .list_run("R")
            .expect("one admitted record")
            .len(),
        1
    );
}

fn admission_final(client: &mut UnixStream) -> serde_json::Value {
    let mut observed_credit = 0;
    loop {
        let frame = frame_read(client).expect("admission progress or final");
        if frame["type"] != "request-lock-wait" {
            assert_eq!(frame["type"], "final");
            return frame;
        }
        let credit = frame["wait_ms"].as_u64().expect("credit milliseconds");
        assert!(credit >= observed_credit && credit <= 120_000);
        observed_credit = credit;
    }
}

#[derive(Default)]
struct ControlledAdmissionClock {
    now: std::cell::Cell<Option<Instant>>,
    sleeps: std::cell::Cell<u32>,
}

impl super::AdmissionClock for ControlledAdmissionClock {
    fn now(&self) -> Instant {
        let now = self.now.get().unwrap_or_else(Instant::now);
        self.now.set(Some(now));
        now
    }

    fn sleep(&self, duration: Duration) {
        self.now.set(Some(self.now() + duration));
        self.sleeps.set(self.sleeps.get() + 1);
    }
}

/// # Panics
/// Panics if the admission loop changes its budget or acquisition-before-expiry order.
/// ´test:unit:door-admission-controlled-clock-expires´
#[test]
fn door_admission_controlled_clock_expires() {
    use super::AdmissionClock as _;
    let fixture = Fixture::new();
    let registration = concurrent_registration(3000);
    let held = super::RequestGuard::acquire(&fixture.home, &registration)
        .expect("holder")
        .expect("uncontended");
    let clock = ControlledAdmissionClock::default();
    let started = clock.now();
    let request = json!({"deadline_ms":3000});
    let (guard, waited) = super::RequestGuard::acquire_wait_with_clock(
        &fixture.home, &registration, &request, None, started, &clock,
    ).expect("controlled admission");
    assert!(guard.is_none(), "held admission must expire");
    assert_eq!(waited, Duration::from_secs(1), "reply margin fixes the budget");
    assert_eq!(clock.sleeps.get(), 10, "each poll advances only the admission clock");
    drop(held);
    let (guard, waited) = super::RequestGuard::acquire_wait_with_clock(
        &fixture.home, &registration, &request, None, started, &clock,
    ).expect("released admission");
    assert!(guard.is_some(), "acquisition still precedes the exhausted-budget check");
    assert_eq!(waited, Duration::ZERO);
    assert_eq!(clock.sleeps.get(), 10, "uncontended acquisition does not sleep");
}

fn assert_admission_ticks(clock: &ControlledAdmissionClock, last_interval: bool) {
    let expected = if last_interval {
        super::ADMISSION_WAIT.as_millis() / super::ADMISSION_POLL.as_millis()
    } else {
        1
    };
    assert_eq!(u128::from(clock.sleeps.get()), expected, "controlled admission interval");
}

fn admission_release_hook(
    last_interval: bool,
    contended: std::sync::mpsc::Sender<()>,
    released: std::sync::mpsc::Receiver<()>,
    store: Store,
    holder: std::sync::mpsc::Sender<thread::JoinHandle<()>>,
) -> std::rc::Rc<ControlledAdmissionClock> {
    let clock = std::rc::Rc::new(ControlledAdmissionClock::default());
    super::ADMISSION_CLOCK.with(|slot| {
        *slot.borrow_mut() = Some(clock.clone());
    });
    let hook = if last_interval {
        &super::ADMISSION_LAST_POLL
    } else {
        &super::ADMISSION_CONTENDED
    };
    hook.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            contended.send(()).expect("overlap contended");
            released
                .recv_timeout(Duration::from_secs(120))
                .expect("first guard released");
            holder
                .send(referral_contender(&store, true).expect("competing writer"))
                .expect("holder thread retained");
        }));
    });
    clock
}

/// # Panics
/// Panics only if admission does not resume after the first request completes.
/// ´test:unit:door-concurrent-request-admits-after-release´
#[test]
fn door_concurrent_request_admits_after_release() {
    // Exercise both an early release and a release in the final polling interval.
    for last_interval in [false, true] {
        let fixture = Fixture::new();
        let store = fixture.store();
        let (runner, first_calls, _) = counting_runner(&fixture);
        let (socket, first) = fixture_service(&fixture, runner, rubric(Some("allow")), 120_000, None);
        let mut client = send_probe(&socket, 120_000);
        let first_id = wait_filed(&store);
        let (runner, second_calls, _) = counting_runner(&fixture);
        let route = route_for(&fixture.home);
        let home = fixture.home.clone();
        let second_store = fixture.store();
        let (mut second_client, mut second_server) = UnixStream::pair().expect("overlap pair");
        second_client
            .shutdown(Shutdown::Write)
            .expect("overlap EOF");
        let (contended_tx, contended_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let (holder_tx, holder_rx) = std::sync::mpsc::channel();
        let holder_store = fixture.store();
        let second = thread::spawn(move || {
            let clock = admission_release_hook(
                last_interval,
                contended_tx,
                released_rx,
                holder_store,
                holder_tx,
            );
            let result = serve_request(
                &mut second_server,
                &concurrent_registration(3000),
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&home),
                Some(&rubric(Some("allow"))),
                Some(&second_store),
                super::AdmissionClock::now(clock.as_ref()),
            );
            assert_admission_ticks(&clock, last_interval);
            holder_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("holder thread")
                .join()
                .expect("holder released after progress");
            result
        });
        contended_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("overlap waiting");
        assert_eq!(store.list_run("R").expect("before release").len(), 1);
        label(&store, &first_id, "allow");
        let first_reply = admission_final(&mut client);
        assert_eq!(first_reply["reason"], "door-complete");
        first.join().expect("first handler").expect("first served");
        released_tx.send(()).expect("resume admission poll");
        let deadline = Instant::now() + Duration::from_secs(120);
        let second_id = loop {
            if let Some(record) = store
                .list_run("R")
                .expect("admitted records")
                .into_iter()
                .find(|record| record.id() != first_id)
            {
                break record.id().to_owned();
            }
            assert!(Instant::now() < deadline, "overlap never admitted");
            thread::sleep(Duration::from_millis(5));
        };
        label(&store, &second_id, "allow");
        let reply = admission_final(&mut second_client);
        assert!(
            reply["request_lock_wait_credit_ms"]
                .as_u64()
                .expect("credit")
                >= 50
        );
        second
            .join()
            .expect("second handler")
            .expect("second served");
        assert_eq!(reply["reason"], "door-complete");
        assert_eq!(reply["status"], 0);
        assert!(reply.get("waited_seconds").is_none());
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 1);
        let records = store.list_run("R").expect("two complete records");
        assert_eq!(records.len(), 2);
        for record in records {
            assert_eq!(record.value()["effect"]["state"], "completed");
        }
    }
}

/// # Panics
/// Panics if a second process bypasses a same-class or exclusive admission guard.
/// ´test:unit:door-compute-receive-admission-cross-process´
#[test]
fn door_compute_receive_admission_cross_process() {
    const CHILD: &str = "SUPERLOOP_ADMISSION_MATRIX";
    let operation = |name: &str| match name {
        "compute" => Some(Operation::Compute),
        "receive" => Some(Operation::GitReceive),
        _ => None,
    };
    if let Ok(case) = std::env::var(CHILD) {
        let home = PathBuf::from(std::env::var_os("SUPERLOOP_ADMISSION_HOME").expect("home"));
        let _namespace = concurrent_namespace(&home);
        let parts: Vec<_> = case.split(':').collect();
        let guard = super::RequestGuard::acquire_operation(
            &home,
            &concurrent_registration(3000),
            operation(parts[0]),
        )
        .expect("child guard");
        assert_eq!(guard.is_some(), parts[1] == "true");
        return;
    }
    let fixture = Fixture::new();
    let registration = concurrent_registration(3000);
    for first in ["compute", "receive", "exclusive"] {
        let held =
            super::RequestGuard::acquire_operation(&fixture.home, &registration, operation(first))
                .expect("parent guard")
                .expect("free slot");
        for second in ["compute", "receive", "exclusive"] {
            let expected = first != second && first != "exclusive" && second != "exclusive";
            let result = concurrent_fixture_command_for(
                "door::tests::door_compute_receive_admission_cross_process",
            )
            .env(CHILD, format!("{second}:{expected}"))
            .env("SUPERLOOP_ADMISSION_HOME", &fixture.home)
            .output()
            .expect("child process");
            assert!(result.status.success(), "{first}/{second}: {result:?}");
        }
        drop(held);
        assert!(
            super::RequestGuard::acquire(&fixture.home, &registration)
                .expect("released guard")
                .is_some()
        );
    }
}

/// # Panics
/// Panics if a receive cannot complete beside compute or either record loses its effect identity.
/// ´test:unit:door-receive-completes-beside-running-compute´
#[test]
fn door_receive_completes_beside_running_compute() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let (socket, compute_calls, compute_server) =
        super::compute_tests::compute_service(&fixture, "R", 3000, 3000, Scope::Work, None);
    let mut compute = UnixStream::connect(socket).expect("compute connection");
    frame_write(
        &mut compute,
        &json!({"schema":2,
        "argv":[b"fixture".to_vec(), b"/opt/fixture/bin/report cargo run --locked".to_vec()],
        "deadline_ms":60000}),
    )
    .expect("compute request");
    let deadline = Instant::now() + Duration::from_secs(120);
    while compute_calls.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "compute effect starts");
        thread::sleep(Duration::from_millis(5));
    }
    let (runner, receive_calls, _) = counting_runner(&fixture);
    let (socket, receive_server) = fixture_service(&fixture, runner, rubric(None), 60000, None);
    let command = format!(
        "{} {} refs/heads/lane/R\0report-status\n",
        "0".repeat(40),
        "a".repeat(40)
    );
    let packet = format!("{:04x}{command}0000", command.len() + 4);
    let reply = super::stub_call_stream(
        &socket,
        &[
            "fixture".into(),
            "git-receive-pack '~/mirrors/R.git'".into(),
        ],
        io::Cursor::new(packet.into_bytes()),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .expect("receive transport");
    assert_eq!(reply["reason"], "door-complete", "{reply}");
    assert_eq!(reply["ref_check"], "admitted");
    receive_server
        .join()
        .expect("receive thread")
        .expect("receive result");
    assert_eq!(receive_calls.load(Ordering::Relaxed), 1);
    assert!(
        !compute_server.is_finished(),
        "compute remains held on its input"
    );
    compute
        .shutdown(Shutdown::Write)
        .expect("finish compute input");
    loop {
        let reply = frame_read_until(&mut compute, deadline).expect("compute reply");
        if reply["type"] == "final" {
            assert_eq!(reply["reason"], "door-complete", "{reply}");
            break;
        }
    }
    compute_server
        .join()
        .expect("compute thread")
        .expect("compute result");
    let rows = fixture.store().list_run("R").expect("both records");
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].id(), rows[1].id());
    let operations: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|row| row.value()["operation"].as_str().expect("record operation"))
        .collect();
    assert_eq!(
        operations,
        std::collections::BTreeSet::from(["compute", "git-receive"])
    );
    let receive = rows
        .iter()
        .find(|row| row.value()["operation"] == "git-receive")
        .expect("receive record");
    assert_eq!(receive.value()["effect"]["ref_check"], "admitted");
    assert!(
        rows.iter()
            .all(|row| row.value()["effect"]["state"] == "completed")
    );
    assert_eq!(compute_calls.load(Ordering::Relaxed), 1);
}

/// This real-clock integration proof runs on demand with
/// `cargo test --locked -p superloop-lane --lib door::tests::door_two_requesters_credit_contention_before_unlocked_triage -- --ignored --exact`.
/// ´test:unit:door-two-requesters-credit-contention-before-unlocked-triage´
#[test]
#[ignore = "real-clock credit and agent budget proof; run on demand"]
fn door_two_requesters_credit_contention_before_unlocked_triage() {
    struct PausedAgent {
        run: &'static str,
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl super::agent::AgentRunner for PausedAgent {
        fn judge(&self, _: &[u8], remaining: Duration) -> super::agent::RunnerOutcome {
            assert!(!remaining.is_zero(), "contention consumed the agent budget");
            self.entered.send(()).expect("agent entered");
            self.release.lock().expect("release lock")
                .recv_timeout(Duration::from_secs(10)).expect("release agent");
            let mut result = super::agent::RunnerOutcome::referral("failure", "fixture", Instant::now());
            result.status = "verdict".into();
            result.verdict = "allow".into();
            result.scope = "loop".into();
            result.reason = format!("fixture independent judgement {}", self.run);
            result
        }
    }
    let fixture = Fixture::new();
    fixture.set_floor("enforce");
    let store = fixture.store();
    store.ensure_first_mode("ssh").expect("initial mode");
    let route = route_for(&fixture.home);
    let (contended_tx, contended_rx) = std::sync::mpsc::channel();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let holder = store.fixture_exclusive_lock().expect("bounded contender");
    let mut services = Vec::new();
    let mut clients = Vec::new();
    let mut releases = Vec::new();
    for (index, run) in ["R", "S"].into_iter().enumerate() {
        let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join(format!("credit-{run}.sock")));
        let listener = UnixListener::bind(&socket).expect("listener");
        let home = fixture.home.clone();
        let service_store = fixture.store();
        let route = route.clone();
        let (runner, _, _) = counting_runner(&fixture);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        releases.push(release_tx);
        let agent = PausedAgent { run, entered: entered_tx.clone(), release: Mutex::new(release_rx) };
        let contended = contended_tx.clone();
        services.push(thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = frame_read(&mut stream).expect("request");
            let registration = Registration::from_row(&json!({"name":"alpha","uid":2001}), "alpha", run, 3000 + u32::try_from(index).expect("two callers"), Scope::Work).expect("registration");
            super::WAIT_CREDIT_OBSERVED.with(|slot| *slot.borrow_mut() = Some(contended));
            super::serve_request_with_agent(&mut stream, &registration, registration.worker_uid,
                &request, Some(&route), Some(&runner), Some(&home), Some(&rubric(None)),
                Some(&service_store), Some(&agent), None, Instant::now()).expect("served")
        }));
        clients.push(thread::spawn(move || {
            super::transport::STUB_TEST_BUDGET.with(|slot| slot.set(Some(3000)));
            super::transport::stub_call_stream(&socket, &[OsString::from("door-attribution-probe")], io::empty(), Vec::new(), Vec::new()).expect("stub completes")
        }));
    }
    for _ in 0..2 { contended_rx.recv_timeout(Duration::from_secs(10)).expect("both requests contend"); }
    // Exceed the requested active budget while both callers are measured waiting.
    thread::sleep(Duration::from_secs(6));
    drop(holder);
    for _ in 0..2 { entered_rx.recv_timeout(Duration::from_secs(10)).expect("both agents entered"); }
    let mut pending_ids = std::collections::BTreeMap::new();
    for run in ["R", "S"] {
        let rows = store.list_run(run).expect("pending custody is readable during triage");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].id().starts_with(&format!("{run}:")));
        pending_ids.insert(run, rows[0].id().to_owned());
        assert_eq!(rows[0].value()["effect"]["state"], "pending");
    }
    drop(store.fixture_exclusive_lock().expect("triage holds no writer lock"));
    for release in releases { release.send(()).expect("release judgement"); }
    for client in clients {
        let reply = client.join().expect("client");
        assert_eq!(reply["reason"], "door-complete", "{reply}");
        assert_eq!(reply["status"], 0);
        assert!(reply["request_lock_wait_ms"].as_u64().expect("measured wait") >= 3000);
    }
    for service in services { service.join().expect("service"); }
    for run in ["R", "S"] {
        let rows = store.list_run(run).expect("completed custody");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value()["effect"]["state"], "completed");
        assert_eq!(rows[0].value()["would_do"]["decision"], "allow");
        assert_eq!(rows[0].id(), pending_ids[run]);
        assert_eq!(rows[0].value()["would_do"]["reason"], format!("fixture independent judgement {run}"));
    }
}

/// ´test:unit:door-wait-credit-announces-fifty-ms-steps-and-caps-deadline´
#[test]
fn door_wait_credit_announces_fifty_ms_steps_and_caps_deadline() {
    let (server, mut peer) = UnixStream::pair().expect("pair");
    peer.set_read_timeout(Some(Duration::from_secs(120)))
        .expect("hang guard");
    let wait = super::RequestWait::new(&server).expect("wait credit");
    wait.credit(Duration::from_millis(49));
    assert_eq!(*wait.announced.lock().expect("announcement"), 0);
    wait.credit(Duration::from_millis(1));
    assert_eq!(frame_read(&mut peer).expect("first credit")["wait_ms"], 50);
    wait.credit(Duration::from_millis(49));
    assert_eq!(*wait.announced.lock().expect("announcement"), 50);
    wait.credit(Duration::from_millis(1));
    assert_eq!(frame_read(&mut peer).expect("second credit")["wait_ms"], 100);
    wait.credit(Duration::from_secs(200));
    assert_eq!(frame_read(&mut peer).expect("capped credit")["wait_ms"], 120_000);
    assert_eq!(wait.elapsed(), Duration::from_secs(120));
    let base = Instant::now();
    assert_eq!(wait.deadline(base), base + Duration::from_secs(120));
}

/// # Panics
/// Panics if a late credit writes a frame or stops accounting after final sealing.
/// ´test:unit:door-final-seal-suppresses-late-credit´
#[test]
fn door_final_seal_suppresses_late_credit() {
    let (server, mut peer) = UnixStream::pair().expect("pair");
    let wait = Arc::new(super::RequestWait::new(&server).expect("request wait"));
    drop(server);
    wait.credit(Duration::from_millis(50));
    assert_eq!(frame_read(&mut peer).expect("early credit")["type"], "request-lock-wait");
    let (ready, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let other = Arc::clone(&wait);
    let writer = thread::spawn(move || {
        super::BEFORE_CREDIT_WRITE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                ready.send(()).expect("credit reached writer boundary");
                released.recv_timeout(FIXTURE_HANG).expect("final written");
            }));
        });
        other.credit(Duration::from_millis(50));
    });
    entered.recv_timeout(FIXTURE_HANG).expect("credit writer exists");
    let reply = json!({"schema":2,"status":0,"reason":"fixture-final"});
    wait.write_final(&reply, Instant::now() + FIXTURE_HANG).expect("final");
    assert_eq!(frame_read(&mut peer).expect("final frame"), reply);
    release.send(()).expect("late credit");
    writer.join().expect("credit writer");
    assert_eq!(wait.elapsed(), Duration::from_millis(100), "agent credit remains active");
    drop(wait);
    let mut tail = Vec::new();
    std::io::Read::read_to_end(&mut peer, &mut tail).expect("writer closed");
    assert!(tail.is_empty(), "frame after final: {tail:?}");
}

struct PostReplyAgent {
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    failure_phase: &'static str,
}

impl super::agent::AgentRunner for PostReplyAgent {
    fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
        self.entered.send(()).expect("agent entered");
        self.release.lock().expect("release channel")
            .recv_timeout(FIXTURE_HANG).expect("release after final");
        let mut result = super::agent::RunnerOutcome::referral(
            "failure", "fixture judgement", Instant::now(),
        );
        assert_ne!(self.failure_phase, "agent-join", "fixture agent panic after final");
        if self.failure_phase == "agent-record" {
            result.rubric_digest = Some("invalid digest".into());
        }
        result
    }
}

/// ´test:unit:door-recovery-waits-without-retaining-admission´
#[test]
fn door_recovery_waits_without_retaining_admission() {
    let fixture = Fixture::new();
    let registration = concurrent_registration(3000);
    let store = fixture.store();
    let recovery = fixture.store();
    let admission = super::RequestGuard::acquire(&fixture.home, &registration)
        .expect("admission").expect("free admission");
    thread::scope(|scope| {
        let held = store.fixture_exclusive_lock().expect("hold request lock");
        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let child = scope.spawn(move || {
            crate::requests::store::AFTER_READER_LOCK_CONTENTION.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    observed_tx.send(()).expect("recovery is waiting");
                }));
            });
            super::recover_after_success(&recovery, "R", &json!({"status":0}),
                &mut Some(admission));
        });
        observed_rx.recv_timeout(FIXTURE_HANG).expect("recovery reaches held lock");
        let next = super::RequestGuard::acquire(&fixture.home, &registration)
            .expect("next admission").expect("recovery must not retain admission");
        drop(next);
        drop(held);
        child.join().expect("recovery completes");
    });
}

fn post_reply_failure_case(phase: &'static str) {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let store = fixture.store();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let agent = PostReplyAgent {
        entered: entered_tx, release: Mutex::new(release_rx), failure_phase: phase,
    };
    let route = route_for(&fixture.home);
    let (runner, calls, _) = counting_runner(&fixture);
    let (mut client, mut server) = UnixStream::pair().expect("allow pair");
    client.shutdown(Shutdown::Write).expect("EOF");
    let home = fixture.home.clone();
    let server_store = fixture.store();
    let handler = thread::spawn(move || {
        if phase == "waiting-publication" {
            fixture_fault(Some(FixtureFault::WaitingWrite));
        }
        let result = super::serve_request_with_agent(
            &mut server, &concurrent_registration(3000), 3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
            Some(&route), Some(&runner), Some(&home), Some(&rubric(None)),
            Some(&server_store), Some(&agent), None, Instant::now(),
        );
        fixture_fault(None);
        result
    });
    entered_rx.recv_timeout(FIXTURE_HANG).expect("agent held");
    let reply = fixture_final_frame(&mut client);
    assert_eq!(reply["reason"], "door-complete", "{phase}");
    let id = store.list_run("R").expect("durable effect")[0].id().to_owned();
    let active = fixture.command(&["status", "alpha"], b"").expect("active status");
    assert_eq!(active["unpublished_effects"][0]["publication_status"], "running");
    super::recover_at_start(&fixture.home, "alpha");
    assert!(store.request(&id).expect("live advice remains unpublished").publication_pending());
    release_tx.send(()).expect("release agent after final");
    let result = handler.join().expect("handler");
    assert_eq!(as_sent(&result.expect("no late error reaches second-refusal writer").0), reply);
    let mut tail = Vec::new();
    std::io::Read::read_to_end(&mut client, &mut tail).expect("closed handler");
    assert!(tail.is_empty(), "{phase}: post-final bytes {tail:?}");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_incomplete(&fixture, &id);
    fs::remove_file(fixture.home.join(".config/loops/alpha/door-requests-attempt.json"))
        .expect("visibility does not depend on the latest marker");
    assert_unpublished_visible(&fixture, &store, &id);
    let effect = store.request(&id).expect("original effect").value()["effect"].clone();
    if phase == "agent-join" {
        super::recover_at_start(&fixture.home, "alpha");
    } else {
        let (mut next_client, mut next_server) = UnixStream::pair().expect("next request");
        next_client.shutdown(Shutdown::Write).expect("next EOF");
        super::serve_request_with_agent(
            &mut next_server, &concurrent_registration(3000), 3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
            Some(&route_for(&fixture.home)), Some(&counting_runner(&fixture).0),
            Some(&fixture.home), Some(&rubric(Some("allow"))), Some(&store), None,
            None, Instant::now(),
        ).expect("later successful request recovers prior effect");
        assert_eq!(fixture_final_frame(&mut next_client)["status"], 0);
    }
    let recovered = store.request(&id).expect("recovered record");
    assert_eq!(recovered.value()["state"], "waiting", "{phase}");
    assert_eq!(recovered.value()["effect"], effect, "effect is not rerun");
    assert_eq!(calls.load(Ordering::Relaxed), 1, "prior effect was not executed again");
    assert!(recovered.value()["label"].is_null(), "no invented owner decision");
    assert_eq!(fixture.command(&["status", "alpha"], b"").expect("recovered status")
        ["unpublished_effects"].as_array().expect("listing").as_slice(), [] as [Value; 0]);
}

fn assert_unpublished_visible(fixture: &Fixture, store: &Store, id: &str) {
    let status = fixture.command(&["status", "alpha"], b"").expect("owner status");
    assert_eq!(status["unpublished_effects"].as_array().expect("listing").len(), 1);
    assert_eq!(status["unpublished_effects"][0]["id"], id);
    assert_eq!(status["unpublished_effects"][0]["publication_status"], "awaiting-recovery");
    let runs = File::open(fixture.home.join("runs")).expect("runs");
    let error = store.retirement_guard("R", &runs, true).expect_err("unpublished blocks retire");
    assert_eq!(error.kind, "retire-requests-pending");
    assert!(error.detail.contains(&format!("unpublished effect ids: {id}")));
}

/// # Panics
/// Panics if a late transaction error changes the final reply or escapes owner visibility.
/// ´test:unit:door-post-reply-failure-is-visible-and-silent´
#[test]
fn door_post_reply_failure_is_visible_and_silent() {
    if !post_reply_journal_child(&["agent-join", "agent-record", "waiting-publication"]) {
        return;
    }
    for phase in ["agent-join", "agent-record", "waiting-publication"] {
        post_reply_failure_case(phase);
    }
}

/// # Panics
/// Panics if losing the incomplete marker also loses the service-journal event.
/// ´test:unit:door-post-reply-marker-failure-keeps-journal-event´
#[test]
fn door_post_reply_marker_failure_keeps_journal_event() {
    if !post_reply_journal_child(&["waiting-publication", "incomplete-marker"]) {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let marker = fixture.home.join(".config/loops/alpha/door-requests-attempt.json");
    fs::write(&marker, b"not a private record").expect("invalid marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o666)).expect("marker refused");
    super::post_reply_failure(&store, "R", "R:1a", "waiting-publication", "fixture-failure");
}

fn post_reply_journal_child(phases: &[&str]) -> bool {
    let name = thread::current().name().expect("test name").to_owned();
    if std::env::var("SUPERLOOP_POST_REPLY_PROOF").as_deref() == Ok(name.as_str()) {
        return true;
    }
    let mut environment: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    environment.insert("SUPERLOOP_POST_REPLY_PROOF".into(), name.clone());
    let spec = crate::build::child(
        &std::env::current_exe().expect("test image"),
        vec!["--exact".into(), name, "--nocapture".into()],
        &environment, &std::env::current_dir().expect("cwd"), 180, "post-reply fixture",
    );
    let output = crate::build::run_child(&spec, None).expect("bounded fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("test result: ok. 1 passed;"), "{stdout}");
    let events: Vec<Value> = stderr.lines()
        .filter_map(|line| line.strip_prefix("door-post-reply-failure "))
        .map(|line| serde_json::from_str(line).expect("journal JSON")).collect();
    assert_eq!(events.len(), phases.len(), "service journal: {stderr}");
    for (event, phase) in events.iter().zip(phases) {
        assert_eq!(event["phase"], *phase);
        assert!(event["request_id"].as_str().is_some_and(|id| id.starts_with("R:")));
        assert!(event["kind"].as_str().is_some_and(|kind| !kind.is_empty()));
        assert_eq!(event.as_object().expect("event").len(), 3);
    }
    false
}

/// ´test:unit:door-success-without-pending-adds-no-exclusive-recovery-hold´
#[test]
fn door_success_without_pending_adds_no_exclusive_recovery_hold() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let store = fixture.store();
    recovery_record(&store, false);
    crate::requests::store::WRITE_ACQUISITIONS.set(0);
    super::recover_after_success(&store, "R", &json!({"status":0}), &mut None);
    assert_eq!(crate::requests::store::WRITE_ACQUISITIONS.get(), 0,
        "ordinary successful after-request path adds no exclusive hold");
}

fn recovery_record(store: &Store, unpublished: bool) {
    let mut row = crate::requests::tests::waiting("R", "aa", 3000,
        crate::requests::Mode::Allow).into_value();
    row["mode"] = json!("allow");
    row["class_setting"]["mode"] = json!("allow");
    row["loop_setting"]["mode"] = json!("allow");
    if unpublished { row["state"] = Value::Null; }
    row["effect"]["state"] = json!("completed");
    row["effect"]["reason"] = json!("door-complete");
    row["effect"]["exit_status"] = json!(0);
    row["effect"]["ref_check"] = json!("not-applicable");
    store.file(crate::requests::RequestRecord::decode(row).expect("recovery record"))
        .expect("file recovery record");
}

/// ´test:unit:door-live-publication-adds-no-exclusive-recovery-hold´
#[test]
fn door_live_publication_adds_no_exclusive_recovery_hold() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let store = fixture.store();
    recovery_record(&store, true);
    let _live = store.publication_activity("R:aa").expect("live advisory handler");
    let before = store.request("R:aa").expect("before").into_value();
    crate::requests::store::WRITE_ACQUISITIONS.set(0);
    super::recover_after_success(&store, "R", &json!({"status":0}), &mut None);
    assert_eq!(crate::requests::store::WRITE_ACQUISITIONS.get(), 0,
        "live advisory work adds no exclusive recovery hold");
    assert_eq!(store.request("R:aa").expect("unchanged").value(), &before);
}

/// ´test:unit:door-idle-or-malformed-publication-enters-recovery´
#[test]
fn door_idle_or_malformed_publication_enters_recovery() {
    for malformed in [false, true] {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        recovery_record(&store, true);
        drop(store.publication_activity("R:aa").expect("create then release lease"));
        if malformed {
            fs::set_permissions(fixture.home.join("runs/.launch-R/door-publication-aa.lock"),
                fs::Permissions::from_mode(0o644)).expect("malformed lease");
        }
        crate::requests::store::WRITE_ACQUISITIONS.set(0);
        super::recover_after_success(&store, "R", &json!({"status":0}), &mut None);
        assert_eq!(crate::requests::store::WRITE_ACQUISITIONS.get(), 1,
            "idle or malformed candidate escalates: malformed={malformed}");
        let row = store.request("R:aa").expect("result");
        assert_eq!(row.publication_pending(), malformed, "malformed={malformed}");
        if !malformed { assert_eq!(row.value()["state"], "waiting"); }
    }
}
