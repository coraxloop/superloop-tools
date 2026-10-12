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
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let (runner, calls, _) = counting_runner(&fixture);
    let (socket, first) = fixture_service(&fixture, runner, rubric(Some("allow")), 15000, None);
    let mut client = UnixStream::connect(socket).expect("first connection");
    frame_write(
        &mut client,
        &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":15000}),
    )
    .expect("first request");
    let id = wait_filed(&store);
    let deadline = Instant::now() + Duration::from_secs(10);
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
        assert_eq!(reply["admission_window"], super::ADMISSION_WINDOW);
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
    let (socket, next) = fixture_service(&fixture, runner, rubric(None), 15000, None);
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
    if std::env::var_os("SUPERLOOP_DOOR_CONCURRENT_ROOT").is_some() {
        super::root_refusal(
            &mut stream,
            &registration,
            uid,
            &request,
            &home,
            &super::LaneError::input("fixture-root", "root absent"),
            Instant::now(),
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
            Instant::now(),
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
    frame_write(&mut stream, &json!({"schema":2})).expect("peer request");
    let reply = frame_read(&mut stream).expect("peer reply");
    let output = child.wait_with_output().expect("peer completion");
    assert!(output.status.success(), "{output:?}");
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
                    .recv_timeout(Duration::from_secs(30))
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
        .recv_timeout(Duration::from_secs(10))
        .expect("root holds admission");
    // Hold before publication and before the bounded socket write, independent of spawn speed.
    let reply = concurrent_process_request(&fixture, 3000, true);
    assert_eq!(reply["reason"], "door-request-concurrent");
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
                    .recv_timeout(Duration::from_secs(10))
                    .expect("release writer");
            }));
        });
        bounded_box_request(&home, &store, 3000)
    });
    held_rx
        .recv_timeout(Duration::from_secs(10))
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
        let began = Instant::now();
        let reply = bounded_box_request(&home, &store, 3001);
        done_tx
            .send((reply, began.elapsed()))
            .expect("second completion");
    });
    contended_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("second box independently admitted and waiting on store");
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release_tx.send(()).expect("release first writer");
    let (second_reply, wall) = done_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("second completes within store bound");
    let first_reply = first.join().expect("first box");
    second.join().expect("second box");
    assert!(wall < Duration::from_secs(15), "second box wall={wall:?}");
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
    assert_eq!(frame_read(&mut client).expect("final reply"), reply);
    assert_eq!(reply["reason"], "door-request-refusal");
    assert!(reply["request_id"].is_string());
    assert!(reply.get("request_record_error").is_none());
    reply
}

struct HeldAdmissionAgent {
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl super::agent::AgentRunner for HeldAdmissionAgent {
    fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
        self.entered.send(()).expect("agent entered");
        self.release
            .lock()
            .expect("agent release lock")
            .recv_timeout(Duration::from_secs(10))
            .expect("release agent");
        super::agent::RunnerOutcome::referral("failure", "fixture bounded agent", Instant::now())
    }
}

/// # Panics
/// Panics only if allow-mode publication releases admission before agent completion.
/// ´test:unit:door-concurrent-allow-agent-publication-window´
#[test]
fn door_concurrent_allow_agent_publication_window() {
    let fixture = Fixture::new();
    fixture.set_floor("allow");
    let store = fixture.store();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let agent = HeldAdmissionAgent {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    };
    let route = route_for(&fixture.home);
    let (runner, _, _) = counting_runner(&fixture);
    let (mut client, mut server) = UnixStream::pair().expect("allow pair");
    let home = fixture.home.clone();
    let server_store = fixture.store();
    let handler = thread::spawn(move || {
        super::serve_request_with_agent(
            &mut server,
            &concurrent_registration(3000),
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":15000}),
            Some(&route),
            Some(&runner),
            Some(&home),
            Some(&rubric(None)),
            Some(&server_store),
            Some(&agent),
            None,
            Instant::now(),
        )
    });
    client.shutdown(Shutdown::Write).expect("EOF");
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("agent active");
    let reply = frame_read(&mut client).expect("early allow final");
    assert_eq!(reply["reason"], "door-complete");
    let id = wait_filed(&store);
    assert_eq!(
        store.request(&id).expect("effect").value()["effect"]["state"],
        "completed"
    );
    let overlap = concurrent_process_request(&fixture, 3000, false);
    assert_eq!(overlap["reason"], "door-request-concurrent");
    assert_eq!(overlap["admission_window"], super::ADMISSION_WINDOW);
    assert_eq!(store.list_run("R").expect("one record").len(), 1);
    release_tx.send(()).expect("release publication");
    handler
        .join()
        .expect("allow thread")
        .expect("publication finished");
    assert_eq!(
        store.request(&id).expect("published").value()["state"],
        "waiting"
    );
    assert_eq!(
        concurrent_process_request(&fixture, 3000, false)["reason"],
        "door-request-refusal"
    );
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
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        drop(guard);
    });
    let report = super::fixture_agent_call(
        &fixture.home,
        &registration,
        "fixture-retry",
        Some("allow"),
        Some("allow"),
        Some(Arc::new(super::CatRunner)),
        None,
    )
    .expect("retried fixture");
    release.join().expect("release thread");
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
