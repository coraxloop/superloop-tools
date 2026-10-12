// Real Git clients cross the production stub and request handler; node spawning and the registered route and upload ceiling are substituted.
use std::io::Write as _;
use std::sync::Arc;

use super::*;

fn route_wait<T>(
    deadline: Instant,
    reason: &str,
    mut ready: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<T> {
    loop {
        if let Some(value) = ready()? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, reason));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[allow(unsafe_code)]
fn route_accept(
    listener: &UnixListener,
    deadline: Instant,
    reason: &str,
) -> io::Result<UnixStream> {
    use std::os::fd::AsRawFd as _;
    listener.set_nonblocking(true)?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, reason));
        }
        let mut descriptor = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: the live listener owns this fd, and poll borrows one initialized
        // descriptor for the duration of this call without retaining its pointer.
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready > 0 {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn route_join<T>(handle: thread::JoinHandle<T>, reason: &str) -> T {
    route_wait(Instant::now() + Duration::from_secs(5), reason, || {
        Ok(handle.is_finished().then_some(()))
    })
    .unwrap_or_else(|error| panic!("{error}"));
    handle
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// ´test:unit:door-route-deadlines-end-missing-peers-and-threads´
#[test]
fn door_route_deadlines_end_missing_peers_and_threads() {
    let temp = tempfile::tempdir().expect("deadline fixture");
    let socket = crate::fixture_exec::fixture_socket_path(temp.path().join("deadline.sock"));
    let listener = UnixListener::bind(socket).expect("listener");
    for reason in [
        "route-service-accept-deadline",
        "route-bridge-accept-deadline",
    ] {
        let error = route_accept(
            &listener,
            Instant::now() + Duration::from_millis(20),
            reason,
        )
        .expect_err("absent peer");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), reason);
    }
    let (send, receive) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || receive.recv().expect("release"));
    let error = route_wait(
        Instant::now() + Duration::from_millis(20),
        "route-bridge-join-deadline",
        || Ok(handle.is_finished().then_some(())),
    )
    .expect_err("unfinished thread");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "route-bridge-join-deadline");
    send.send(()).expect("release thread");
    route_join(handle, "route-bridge-join-deadline");
}

struct RouteRunner {
    mirror: PathBuf,
    limit: Option<usize>,
    output: Option<usize>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Runner for RouteRunner {
    fn upload_output_limit(&self) -> Option<usize> {
        self.limit
    }

    fn spawn(&self, _: &Registration, operation: Operation) -> io::Result<Child> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut command = self.output.map_or_else(|| {
            let mut command = Command::new("git");
            command.arg(if operation == Operation::GitReceive {
                "receive-pack"
            } else {
                "upload-pack"
            });
            command.arg(&self.mirror);
            if operation == Operation::GitUploadV2 {
                command.env("GIT_PROTOCOL", "version=2");
            }
            command
        }, |bytes| {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-c", "import sys\nn=int(sys.argv[1])\nwhile n:\n b=min(n,8192);sys.stdout.buffer.write(b'x'*b);n-=b\nsys.stdout.buffer.flush()\n"]);
            command.arg(bytes.to_string());
            command
        });
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn spawn_compute(
        &self,
        registration: &Registration,
        _: &[String],
        _: f64,
    ) -> io::Result<Child> {
        self.spawn(registration, Operation::Compute)
    }
}

fn route_service(
    fixture: &Fixture,
    run: &str,
    worker: u32,
    peer: u32,
    runner: RouteRunner,
) -> (PathBuf, thread::JoinHandle<io::Result<serde_json::Value>>) {
    fixture.set_floor("allow");
    let store = fixture.store();
    for target in [
        ModeTarget::Loop,
        ModeTarget::class("ssh").expect("class"),
        ModeTarget::class("compute").expect("class"),
    ] {
        if let Err(error) = store.set_mode(&target, Mode::Allow, "fixture", "route", "1", &[]) {
            assert_eq!(error.detail, "mode is unchanged");
        }
    }
    let socket = crate::fixture_exec::fixture_socket_path(
        fixture.home.join(format!("route-{run}-{peer}.sock")),
    );
    if socket.exists() {
        fs::remove_file(&socket).expect("previous route socket");
    }
    let listener = UnixListener::bind(&socket).expect("route listener");
    let home = fixture.home.clone();
    let registration = Registration::from_row(
        &json!({"name":"alpha","uid":2001}),
        "alpha",
        run,
        worker,
        Scope::Work,
    )
    .expect("registration");
    let route = super::HostRunner {
        node_root: "/srv/loops/loop-a".to_owned(),
        alias: "fixture".into(),
        ssh_options: Vec::new(),
        ssh_config_sha256: String::new(),
        mirror_root: "~/mirrors".into(),
        key_path: PathBuf::from("unused"),
        upload_output_limit: runner.limit,
        compute_wrapper: Some("/opt/fixture/bin/report".to_owned()),
        compute_environment: Some(
            json!({"RUSTUP_HOME":"/opt/fixture/rustup","PATH":"/opt/fixture/tools:/opt/fixture/cargo/bin:/usr/bin:/bin","PUBLIC_PACK_TEST_LINTER":"/opt/fixture/tools/superloop-lint"}),
        ),
    };
    let server = thread::spawn(move || {
        let mut stream = route_accept(
            &listener,
            Instant::now() + Duration::from_secs(5),
            "route-service-accept-deadline",
        )?;
        let started = Instant::now();
        let request = frame_read_until(&mut stream, started + Duration::from_secs(5))?;
        serve_request(
            &mut stream,
            &registration,
            peer,
            &request,
            Some(&route),
            Some(&runner),
            Some(&home),
            None,
            Some(&store),
            started,
        )
        .map(|(reply, _)| reply)
    });
    (socket, server)
}

fn git_ok(directory: &std::path::Path, words: &[&str]) -> std::process::Output {
    let started = Instant::now();
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(words)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .expect("git fixture");
    writeln!(
        io::stderr().lock(),
        "route_git={words:?} wall={:.6} exit={:?}",
        started.elapsed().as_secs_f64(),
        output.status.code()
    )
    .expect("measurement");
    assert!(
        output.status.success(),
        "git {words:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn seed_route(root: &std::path::Path, bytes: u64) -> PathBuf {
    let source = root.join("source");
    fs::create_dir(&source).expect("source");
    git_ok(&source, &["init", "-q", "--initial-branch=lane/R"]);
    let mut random = fs::File::open("/dev/urandom").expect("random").take(bytes);
    let mut file = fs::File::create(source.join("data")).expect("data");
    io::copy(&mut random, &mut file).expect("random bytes");
    git_ok(&source, &["add", "data"]);
    git_ok(
        &source,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture base",
        ],
    );
    git_ok(
        &source,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture tip",
        ],
    );
    let mirror = root.join("R.git");
    git_ok(
        &source,
        &["clone", "--bare", ".", mirror.to_str().expect("mirror")],
    );
    git_ok(&mirror, &["config", "uploadpack.allowFilter", "true"]);
    mirror
}

// This adapter only carries raw duplex bytes. The Rust endpoint calls stub_call_stream.
fn git_through_route(
    fixture: &Fixture,
    socket: &std::path::Path,
    args: Vec<std::ffi::OsString>,
    directory: &std::path::Path,
    words: &[&str],
    ssh_command: Option<&str>,
) -> serde_json::Value {
    let bridge = crate::fixture_exec::fixture_socket_path(fixture.home.join("git-bridge.sock"));
    let listener = UnixListener::bind(&bridge).expect("bridge listener");
    let socket = socket.to_owned();
    let relay = thread::spawn(move || {
        let stream = route_accept(
            &listener,
            Instant::now() + Duration::from_secs(5),
            "route-bridge-accept-deadline",
        )
        .expect("bridge peer");
        let reply = stub_call_stream(
            &socket,
            &args,
            stream.try_clone().expect("input"),
            stream.try_clone().expect("output"),
            io::sink(),
        )
        .expect("production stub");
        stream
            .shutdown(std::net::Shutdown::Both)
            .expect("bridge shutdown");
        reply
    });
    let adapter = fixture.home.join("git-ssh");
    crate::fixture_exec::write_executable(&adapter, b"#!/usr/bin/python3\nimport os,socket,sys,threading\ns=socket.socket(socket.AF_UNIX);s.connect(os.environ['DOOR_TEST_BRIDGE'])\ndef send():\n try:\n  while True:\n   b=os.read(0,8192)\n   if not b:break\n   s.sendall(b)\n  s.shutdown(socket.SHUT_WR)\n except OSError:pass\nthreading.Thread(target=send,daemon=True).start()\nwhile True:\n b=s.recv(8192)\n if not b:break\n sys.stdout.buffer.write(b);sys.stdout.buffer.flush()\n").expect("adapter");
    let started = Instant::now();
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(words)
        .env(
            "GIT_SSH_COMMAND",
            ssh_command.map_or_else(
                || {
                    format!(
                        "/usr/bin/python3 '{}'",
                        adapter
                            .to_str()
                            .expect("adapter path")
                            .replace('\'', "'\\''")
                    )
                },
                str::to_owned,
            ),
        )
        .env("GIT_SSH_VARIANT", "ssh")
        .env("DOOR_TEST_BRIDGE", &bridge)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git route client");
    let wall = started.elapsed().as_secs_f64();
    writeln!(
        io::stderr().lock(),
        "route_git={words:?} wall={wall:.6} status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )
    .expect("Git diagnostic");
    if !output.status.success() {
        // Wake an accept whose client exited before opening the bridge, then
        // collect it before publishing the client failure.
        drop(UnixStream::connect(&bridge));
        route_wait(
            Instant::now() + Duration::from_secs(5),
            "route-git-client-failure: relay deadline",
            || Ok(relay.is_finished().then_some(())),
        )
        .expect("route-git-client-failure: collect relay");
        drop(relay.join());
        fs::remove_file(&bridge).expect("failed bridge cleanup");
        panic!("route-git-client-failure: {}", output.status);
    }
    let reply = route_join(relay, "route-bridge-join-deadline");
    fs::remove_file(bridge).expect("bridge cleanup");
    writeln!(
        io::stderr().lock(),
        "route_git={words:?} wall={wall:.6} exit={:?} reply={reply}",
        output.status.code()
    )
    .expect("measurement");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(reply["status"], 0);
    reply
}

fn route_args(run: &str, receive: bool) -> Vec<std::ffi::OsString> {
    let mut args = Vec::new();
    if !receive {
        args.extend(["-o".into(), "SendEnv=GIT_PROTOCOL".into()]);
    }
    args.push("fixture".into());
    args.push(
        format!(
            "git-{}-pack '~/mirrors/{run}.git'",
            if receive { "receive" } else { "upload" }
        )
        .into(),
    );
    args
}

/// # Panics
/// Panics only if the fixture fails or an immediate client exit hangs or loses its reason.
/// ´test:unit:door-route-immediate-client-exit-is-named-and-bounded´
#[test]
fn door_route_immediate_client_exit_is_named_and_bounded() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        git_through_route(
            &fixture,
            &fixture.home.join("absent.sock"),
            route_args("R", false),
            &fixture.home,
            &["ls-remote", "fixture:~/mirrors/R.git"],
            Some("false"),
        );
    }))
    .expect_err("immediate client failure");
    let reason = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("named panic");
    assert!(reason.contains("route-git-client-failure"), "{reason}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "route-git-client-failure-deadline"
    );
    assert!(!fixture.home.join("git-bridge.sock").exists());
}

/// ´test:unit:door-upload-large-mirror-through-route´
#[test]
#[ignore = "slow: 206 MiB route transfer; run at deployment with --ignored"]
fn door_upload_large_mirror_through_route() {
    upload_mirror_through_route(206);
}

/// ´test:unit:door-upload-exceeds-default-output-ceiling-through-route´
#[test]
fn door_upload_exceeds_default_output_ceiling_through_route() {
    upload_mirror_through_route(17);
}

fn upload_mirror_through_route(mebibytes: u32) {
    let fixture = Fixture::new();
    let storage_root = std::env::temp_dir();
    fs::create_dir_all(&storage_root).expect("disk fixture root");
    let storage = tempfile::tempdir_in(storage_root).expect("disk fixture");
    let bytes = u64::from(mebibytes) * 1024 * 1024;
    let mirror = seed_route(storage.path(), bytes);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let runner = RouteRunner {
        mirror: mirror.clone(),
        limit: Some(512 * 1024 * 1024),
        output: None,
        calls: calls.clone(),
    };
    let (socket, server) = route_service(&fixture, "R", 3000, 3000, runner);
    let clone = storage.path().join("full");
    let started = Instant::now();
    let reply = git_through_route(
        &fixture,
        &socket,
        route_args("R", false),
        &fixture.home,
        &[
            "clone",
            "--no-checkout",
            "--single-branch",
            "fixture:~/mirrors/R.git",
            clone.to_str().expect("clone"),
        ],
        None,
    );
    let wall = started.elapsed().as_secs_f64();
    writeln!(
        io::stderr().lock(),
        "route_payload_bytes={bytes} route_wall_seconds={wall:.6} route_mib_per_second={:.6}",
        f64::from(mebibytes) / wall
    )
    .expect("measurement");
    assert!(
        wall < 120.0,
        "route-upload-deadline: {mebibytes} MiB exceeded 120 seconds"
    );
    assert_eq!(reply["bound"], 512 * 1024 * 1024);
    assert!(reply["stdout_bytes"].as_u64().expect("count") > bytes);
    route_join(server, "route-service-join-deadline").expect("reply");
    assert_eq!(
        git_ok(&clone, &["rev-parse", "HEAD"]).stdout,
        git_ok(&mirror, &["rev-parse", "HEAD"]).stdout
    );
    git_ok(&clone, &["fsck", "--full"]);
    assert_eq!(
        git_ok(&clone, &["cat-file", "-s", "HEAD:data"]).stdout,
        format!("{bytes}\n").as_bytes()
    );
    let rows = fixture.store().list_run("R").expect("stored output");
    assert_eq!(rows[0].value()["effect"]["bound"], reply["bound"]);
    assert_eq!(
        rows[0].value()["effect"]["output_bytes"],
        reply["output_bytes"]
    );
    for (run, worker, peer) in [("S", 3001, 3000), ("R", 3000, 3001)] {
        let runner = RouteRunner {
            mirror: mirror.clone(),
            limit: Some(512 * 1024 * 1024),
            output: None,
            calls: calls.clone(),
        };
        let (socket, server) = route_service(&fixture, run, worker, peer, runner);
        let reply = stub_call(&socket, &route_args(run, false), b"").expect("cross registration");
        assert_eq!(reply["reason"], "door-peer-refusal");
        route_join(server, "route-service-join-deadline").expect("refusal");
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// ´test:unit:door-output-limit-refusal-records-bound-and-observed-bytes´
#[test]
fn door_output_limit_refusal_records_bound_and_observed_bytes() {
    for limit in [None, Some(32 * 1024 * 1024)] {
        let fixture = Fixture::new();
        let bound = limit.unwrap_or(super::super::OUTPUT_LIMIT);
        let runner = RouteRunner {
            mirror: PathBuf::new(),
            limit,
            output: Some(bound + 8192),
            calls: Arc::default(),
        };
        let (socket, server) = route_service(&fixture, "R", 3000, 3000, runner);
        let mut args = route_args("R", false);
        if limit.is_some() {
            args.drain(..2);
        }
        let reply = stub_call_stream(&socket, &args, io::empty(), io::sink(), io::sink())
            .expect("bounded output");
        assert_eq!(reply["reason"], "door-output-limit-refusal");
        assert_eq!(reply["bound"], bound);
        assert_eq!(
            crate::door::final_line(&args, &reply),
            Some(format!(
                "door-output-limit-refusal bound={bound} output_bytes={} registered={}",
                reply["output_bytes"].as_u64().expect("observed bytes"),
                if limit.is_some() { "present" } else { "absent" },
            ))
        );
        assert!(reply["output_bytes"].as_u64().expect("observed") > bound as u64);
        assert!(reply["stdout_bytes"].as_u64().expect("delivered") <= bound as u64);
        assert_eq!(
            reply["registered"],
            if limit.is_some() { "present" } else { "absent" }
        );
        route_join(server, "route-service-join-deadline").expect("reply");
        assert_eq!(
            fixture.store().list_run("R").expect("reader")[0].value()["effect"]["output_bytes"],
            reply["output_bytes"]
        );
    }
}

/// ´test:unit:door-output-limits-preserve-compute-and-receive´
#[test]
fn door_output_limits_preserve_compute_and_receive() {
    for compute in [false, true] {
        let fixture = Fixture::new();
        let runner = RouteRunner {
            mirror: PathBuf::new(),
            limit: Some(512 * 1024 * 1024),
            output: Some(super::super::OUTPUT_LIMIT + 8192),
            calls: Arc::default(),
        };
        let (socket, server) = route_service(&fixture, "R", 3000, 3000, runner);
        let args = if compute {
            vec![
                "fixture".into(),
                "/opt/fixture/bin/report cargo test --locked".into(),
            ]
        } else {
            route_args("R", true)
        };
        let reply = stub_call_stream(
            &socket,
            &args,
            io::Cursor::new(if compute { vec![] } else { b"0000".to_vec() }),
            io::sink(),
            io::sink(),
        )
        .expect("fixed output bound");
        assert_eq!(reply["reason"], "door-output-limit-refusal");
        assert_eq!(reply["bound"], super::super::OUTPUT_LIMIT);
        assert_eq!(reply["registered"], "not-applicable");
        route_join(server, "route-service-join-deadline").expect("reply");
    }
}

/// ´test:unit:door-node-root-registration-is-explicit-and-required´
#[test]
fn door_node_root_registration_is_explicit_and_required() {
    let fixture = Fixture::new();
    let _route = crate::door::tests::route_for(&fixture.home);
    let config = fixture.home.join(".config/loops/alpha");
    let path = config.join("door-compute-registration.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("registration")).expect("JSON");
    let directory = fs::File::open(&config).expect("directory");
    for root in ["/srv/loops/alpha", "/srv/loops/loop-b"] {
        document["node_root"] = json!(root);
        fs::write(&path, serde_json::to_vec(&document).expect("bytes")).expect("registration");
        let runner = HostRunner::load(
            &directory,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("explicit root");
        assert_eq!(runner.node_root, root);
    }
    for root in [
        None,
        Some(json!("relative")),
        Some(json!("")),
        Some(json!(null)),
        Some(json!(17)),
        Some(json!("/bad\0root")),
    ] {
        document
            .as_object_mut()
            .expect("object")
            .remove("node_root");
        if let Some(root) = &root {
            document["node_root"] = root.clone();
        }
        fs::write(&path, serde_json::to_vec(&document).expect("bytes")).expect("registration");
        let error = HostRunner::load(
            &directory,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
        .err()
        .expect("root refusal");
        assert_eq!(error.kind, "door-compute-root-refusal");
        assert!(error.detail.contains(path.to_str().expect("path")));
        if let Some(root) = root {
            assert!(error.detail.contains(&root.to_string()));
        }
    }
}

/// ´test:unit:door-compute-wrapper-is-owner-declared´
#[test]
fn door_compute_wrapper_is_owner_declared() {
    let fixture = Fixture::new();
    let _route = crate::door::tests::route_for(&fixture.home);
    let config = fixture.home.join(".config/loops/alpha");
    let path = config.join("door-compute-registration.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("registration")).expect("JSON");
    let directory = fs::File::open(&config).expect("directory");
    let load = || {
        HostRunner::load(
            &directory,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
    };
    for wrapper in ["/opt/fixture/bin/report", "/another/owner-wrapper"] {
        document["compute_wrapper"] = json!(wrapper);
        fs::write(&path, document.to_string()).expect("registration");
        let route = load().expect("declared wrapper");
        let words = route
            .compute_words(&[
                b"fixture".to_vec(),
                format!("{wrapper} git diff").into_bytes(),
            ])
            .expect("registered command");
        assert_eq!(words, ["git", "diff"]);
        assert_eq!(
            route.compute_words(&[b"fixture".to_vec(), b"/caller/chosen git diff".to_vec()]),
            Err("door-compute-wrapper-refusal")
        );
    }
    for invalid in [
        json!(null),
        json!(17),
        json!("relative"),
        json!("/"),
        json!("/a//b"),
        json!("/a/../b"),
        json!("/a b"),
        json!("/a\nb"),
        json!(format!("/{}", "a".repeat(256))),
    ] {
        document["compute_wrapper"] = invalid;
        fs::write(&path, document.to_string()).expect("registration");
        assert!(load().is_err());
    }
    document
        .as_object_mut()
        .expect("route")
        .remove("compute_wrapper");
    fs::write(&path, document.to_string()).expect("registration");
    let route = load().expect("Git-only legacy route");
    assert_eq!(
        route.compute_words(&[
            b"fixture".to_vec(),
            b"/opt/fixture/bin/report git diff".to_vec()
        ]),
        Err("door-compute-wrapper-refusal")
    );
    document["unknown_wrapper"] = json!("/arbitrary");
    fs::write(&path, document.to_string()).expect("registration");
    assert!(load().is_err());
}

/// # Panics
/// Panics only if fixture setup or the asserted route-validation contract fails.
///
/// ´test:unit:door-compute-environment-is-owner-declared´
#[test]
fn door_compute_environment_is_owner_declared() {
    let fixture = Fixture::new();
    let _route = crate::door::tests::route_for(&fixture.home);
    let config = fixture.home.join(".config/loops/alpha");
    let path = config.join("door-compute-registration.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("registration")).expect("JSON");
    let directory = fs::File::open(&config).expect("directory");
    let load = || {
        HostRunner::load(
            &directory,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
    };
    let valid = document["compute_environment"].clone();
    for invalid in [
        json!(null),
        json!({}),
        json!({"PATH":"/bin"}),
        json!({"RUSTUP_HOME":"relative","PATH":"/bin","PUBLIC_PACK_TEST_LINTER":"/bin/superloop-lint"}),
        json!({"RUSTUP_HOME":"/rustup","PATH":"/bin:","PUBLIC_PACK_TEST_LINTER":"/bin/superloop-lint"}),
        json!({"RUSTUP_HOME":"/rustup","PATH":"/bin","PUBLIC_PACK_TEST_LINTER":"/bin/../superloop-lint"}),
    ] {
        document["compute_environment"] = invalid;
        fs::write(&path, document.to_string()).expect("invalid registration");
        let error = load().err().expect("environment refusal");
        assert!(error.detail.contains("compute_environment"));
    }
    document["compute_environment"] = valid.clone();
    fs::write(&path, document.to_string()).expect("valid registration");
    assert_eq!(
        load().expect("registered environment").compute_environment,
        Some(valid)
    );
    document
        .as_object_mut()
        .expect("object")
        .remove("compute_environment");
    fs::write(&path, document.to_string()).expect("Git-only registration");
    let route = load().expect("Git route without compute settings");
    assert_eq!(
        route.compute_words(&[
            b"fixture".to_vec(),
            b"/opt/fixture/bin/report git diff".to_vec()
        ]),
        Err("door-compute-settings-refusal")
    );
}

/// ´test:unit:door-upload-registration-bound-is-optional-and-strict´
#[test]
fn door_upload_registration_bound_is_optional_and_strict() {
    let fixture = Fixture::new();
    let route = crate::door::tests::route_for(&fixture.home);
    assert_eq!(route.upload_output_limit(), None);
    let config = fixture.home.join(".config/loops/alpha");
    let path = config.join("door-compute-registration.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("registration")).expect("JSON");
    let directory = fs::File::open(&config).expect("directory");
    for (value, valid) in [
        (json!(1), true),
        (json!(16_777_216), true),
        (json!(1_073_741_824_u64), true),
        (json!(0), false),
        (json!(-1), false),
        (json!(1.5), false),
        (json!("16"), false),
        (json!(null), false),
        (json!(1_073_741_825_u64), false),
    ] {
        document["git_upload_output_limit_bytes"] = value;
        fs::write(&path, document.to_string()).expect("registration value");
        let loaded = HostRunner::load(
            &directory,
            &config,
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        );
        assert_eq!(loaded.is_ok(), valid, "{document}");
        if valid {
            assert_eq!(
                loaded.expect("valid route").upload_output_limit(),
                Some(
                    usize::try_from(
                        document["git_upload_output_limit_bytes"]
                            .as_u64()
                            .expect("integer")
                    )
                    .expect("bound fits usize")
                ),
                "parsed upload bound must survive registration",
            );
        }
    }
}

/// ´test:unit:door-stub-refuses-output-beyond-announced-bound´
#[test]
fn door_stub_refuses_output_beyond_announced_bound() {
    let temp = tempfile::tempdir().expect("stub fixture");
    let socket = crate::fixture_exec::fixture_socket_path(temp.path().join("limit.sock"));
    let listener = UnixListener::bind(&socket).expect("listener");
    let server = thread::spawn(move || {
        let mut peer = route_accept(
            &listener,
            Instant::now() + Duration::from_secs(5),
            "route-stub-accept-deadline",
        )
        .expect("peer");
        let deadline = Instant::now() + Duration::from_secs(5);
        frame_read_until(&mut peer, deadline).expect("request");
        frame_write_until(
            &mut peer,
            &json!({"schema":2,"type":"limits","bound":3,"registered":"present"}),
            deadline,
        )
        .expect("limits");
        frame_write_until(
            &mut peer,
            &json!({"schema":2,"type":"stdout","bytes":[1,2,3,4]}),
            deadline,
        )
        .expect("output");
    });
    let mut output = Vec::new();
    let error = stub_call_stream(
        &socket,
        &route_args("R", false),
        io::empty(),
        &mut output,
        io::sink(),
    )
    .expect_err("stub ceiling");
    assert_eq!(output, [] as [u8; 0]);
    assert_eq!(
        error.to_string(),
        "door-output-limit-refusal bound=3 output_bytes=4 registered=present"
    );
    route_join(server, "route-service-join-deadline");
}

fn ref_wire(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut wire = Vec::new();
    for body in bodies {
        write!(wire, "{:04x}", body.len() + 4).expect("packet length");
        wire.extend(body);
    }
    wire.extend(b"0000");
    wire
}

fn advance_partial(clone: &std::path::Path) -> (String, String) {
    let old = String::from_utf8(git_ok(clone, &["rev-parse", "HEAD"]).stdout).expect("old");
    let tree = String::from_utf8(git_ok(clone, &["rev-parse", "HEAD:"]).stdout).expect("tree");
    let new = String::from_utf8(
        git_ok(
            clone,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit-tree",
                tree.trim(),
                "-p",
                old.trim(),
                "-m",
                "worker fast forward",
            ],
        )
        .stdout,
    )
    .expect("new");
    git_ok(clone, &["update-ref", "HEAD", new.trim()]);
    (old, new)
}

/// ´test:unit:door-shallow-clone-push-through-route´
#[test]
fn door_shallow_clone_push_through_route() {
    for (run, worker, shallow) in [("R", 3000, true), ("S", 3001, true), ("R", 3000, false)] {
        let fixture = Fixture::new();
        let mirror = seed_route(&fixture.home, 1024);
        let expected = format!("refs/heads/lane/{run}");
        if run != "R" {
            git_ok(&mirror, &["update-ref", &expected, "HEAD"]);
            git_ok(&mirror, &["symbolic-ref", "HEAD", &expected]);
            git_ok(&mirror, &["update-ref", "-d", "refs/heads/lane/R"]);
        }
        let make_runner = || RouteRunner {
            mirror: mirror.clone(),
            limit: None,
            output: None,
            calls: Arc::default(),
        };
        let calls = Arc::default();
        let mut denied_runner = make_runner();
        denied_runner.calls = Arc::clone(&calls);
        let peer = if worker == 3000 { 3001 } else { 3000 };
        let (socket, server) = route_service(&fixture, run, worker, peer, denied_runner);
        let denied = stub_call(&socket, &route_args(run, true), b"0000")
            .expect("cross registration receive");
        route_join(server, "route-service-join-deadline").expect("peer refusal");
        assert_eq!(denied["reason"], "door-peer-refusal");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        let (socket, server) = route_service(&fixture, run, worker, worker, make_runner());
        let clone = fixture.home.join("partial");
        let remote = format!("fixture:~/mirrors/{run}.git");
        let mut words = vec![
            "clone",
            "--no-checkout",
            "--filter=blob:none",
            "--single-branch",
        ];
        if shallow {
            words.extend(["--depth", "1"]);
        }
        words.extend([&remote, clone.to_str().expect("clone")]);
        git_through_route(
            &fixture,
            &socket,
            route_args(run, false),
            &fixture.home,
            &words,
            None,
        );
        route_join(server, "route-service-join-deadline").expect("clone reply");
        assert_eq!(clone.join(".git/shallow").exists(), shallow);
        let (old, new) = advance_partial(&clone);
        let (socket, server) = route_service(&fixture, run, worker, worker, make_runner());
        let refspec = format!("HEAD:{expected}");
        let reply = git_through_route(
            &fixture,
            &socket,
            route_args(run, true),
            &clone,
            &["push", "origin", &refspec],
            None,
        );
        route_join(server, "route-service-join-deadline").expect("push reply");
        assert_eq!(reply["ref_check"], "admitted");
        assert!(reply.get("ref_packet").is_none());
        assert_eq!(
            git_ok(&mirror, &["rev-parse", "HEAD"]).stdout,
            new.as_bytes()
        );

        let (socket, server) = route_service(&fixture, run, worker, worker, make_runner());
        let wrong = format!(
            "{} {} refs/heads/foreign\0report-status",
            old.trim(),
            new.trim()
        )
        .into_bytes();
        let mut wire = ref_wire(&[format!("shallow {}\n", old.trim()).into_bytes(), wrong]);
        wire.extend(b"PACK-secret-must-not-be-evidence");
        let reply = stub_call_stream(
            &socket,
            &route_args(run, true),
            io::Cursor::new(wire),
            io::sink(),
            io::sink(),
        )
        .expect("foreign ref");
        route_join(server, "route-service-join-deadline").expect("refusal");
        assert_eq!(reply["reason"], "door-changed-ref-refusal");
        assert_eq!(reply["ref_check"], "refused");
        assert_eq!(reply["ref_packet"]["word_count"], 3);
        assert_eq!(reply["ref_packet"]["first_word"], old.trim());
        assert!(!reply.to_string().contains("PACK-secret"));
        assert_eq!(
            git_ok(&mirror, &["rev-parse", "HEAD"]).stdout,
            new.as_bytes()
        );
        let rows = fixture.store().list_run(run).expect("stored packets");
        assert!(
            rows.iter()
                .any(|row| row.value()["effect"]["ref_packet"] == reply["ref_packet"])
        );
    }
}

struct FragmentedPackets(io::Cursor<Vec<u8>>);
impl io::Read for FragmentedPackets {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = buffer.len().min(3);
        self.0.read(&mut buffer[..size])
    }
}

/// ´test:unit:door-shallow-packets-preserve-ref-authority´
#[test]
fn door_shallow_packets_preserve_ref_authority() {
    let old = "0".repeat(40);
    let new = "1".repeat(40);
    let command = format!("{old} {new} refs/heads/lane/R\0report-status").into_bytes();
    let shallow = format!("shallow {new}\n").into_bytes();
    let mut cases = vec![
        (vec![shallow.clone(), command.clone()], "admitted", None),
        (
            vec![
                format!("shallow {}\n", "a".repeat(64)).into_bytes(),
                command.clone(),
            ],
            "admitted",
            None,
        ),
        (vec![shallow.clone()], "no-ref", None),
        (vec![command.clone(), command.clone()], "admitted", None),
        (
            vec![command.clone(), shallow.clone()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![format!("shallow {new}").into_bytes(), command.clone()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![
                format!("shallow {new} extra\n").into_bytes(),
                command.clone(),
            ],
            "refused",
            Some("shallow"),
        ),
        (
            vec![
                format!("shallow {new}\0hidden\n").into_bytes(),
                command.clone(),
            ],
            "refused",
            Some("shallow"),
        ),
        (
            vec![format!("shallow {}\n", "g".repeat(40)).into_bytes()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![b"shallow short\n".to_vec()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![format!("shallow {new}\r\n").into_bytes()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![format!("shallow {new}\nextra\n").into_bytes()],
            "refused",
            Some("shallow"),
        ),
        (
            vec![format!("{old} invalid refs/heads/lane/R").into_bytes()],
            "refused",
            Some(old.as_str()),
        ),
        (
            vec![format!("{} {} refs/heads/lane/R", "0".repeat(64), "1".repeat(64)).into_bytes()],
            "admitted",
            None,
        ),
        (vec![b"shallow  \n".to_vec()], "refused", Some("shallow")),
        (
            vec![b"\x01bad ref token".to_vec()],
            "refused",
            Some("[non-text]"),
        ),
        (
            vec![format!("{} new ref", "a".repeat(65)).into_bytes()],
            "refused",
            Some("[overlong]"),
        ),
    ];
    cases.push((
        vec![
            shallow,
            command,
            format!("{old} {new} refs/heads/foreign").into_bytes(),
        ],
        "refused",
        Some(old.as_str()),
    ));
    for (bodies, expected, first) in cases {
        assert_packet_case(&bodies, expected, first);
    }
}

fn assert_packet_case(bodies: &[Vec<u8>], expected: &str, first: Option<&str>) {
    let (_fixture, socket, server) = fixture(Scope::Work);
    let mut wire = ref_wire(bodies);
    wire.extend(b"PACK-secret-must-not-be-evidence");
    // Every truncated prefix waits for more input; nothing is admitted before the flush.
    if expected != "refused" {
        let end = wire.len() - b"PACK-secret-must-not-be-evidence".len();
        for length in 0..end {
            assert_eq!(
                checked_ref_packet(&wire[..length], "refs/heads/lane/R"),
                Ok(None)
            );
        }
    }
    let reply = stub_call_stream(
        &socket,
        &route_args("R", true),
        FragmentedPackets(io::Cursor::new(wire)),
        io::sink(),
        io::sink(),
    )
    .expect("packet route");
    route_join(server, "route-service-join-deadline").expect("packet reply");
    assert_eq!(reply["ref_check"], expected, "{bodies:?}: {reply}");
    if let Some(first) = first {
        assert_eq!(reply["reason"], "door-changed-ref-refusal");
        assert_eq!(reply["ref_packet"]["first_word"], first);
        if bodies[0] == b"shallow short\n" {
            assert_eq!(reply["ref_packet"]["word_count"], 2);
        }
        assert!(
            reply["ref_packet"]["word_count"]
                .as_u64()
                .is_some_and(|count| count <= 65_536)
        );
    } else {
        assert!(reply.get("ref_packet").is_none());
    }
    assert!(!reply.to_string().contains("PACK-secret"));
}
