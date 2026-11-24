use super::*;
use execute_command::workspace::{Execution, Grant};
use std::fs;
use std::net::Shutdown;
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub struct Fixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) identity: PathBuf,
    pub(crate) grant: Grant,
    pub(crate) placement: Value,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("work");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("sub")).unwrap();
        let mut grant =
            Grant::decode(crate::plan::fixture_workspace_snapshot()["grant"].clone()).unwrap();
        grant.workspace = workspace.to_str().unwrap().into();
        grant.baseline_env = vec![("PATH".into(), "/usr/bin".into())];
        grant.shells = vec!["/bin/sh".into()];
        let root_identity =
            crate::placement::read_identity(&File::open(&workspace).unwrap()).unwrap();
        let placement = json!({
            "schema":1,"placement":"1".repeat(32),"loop":grant.loop_name,
            "run":grant.run,"node":grant.node,"grant_digest":grant.digest().unwrap(),
            "mode":"own-path","root":grant.workspace,"root_identity":root_identity,"seed":null,
        });
        let identity = root.path().join("node-identity");
        fs::write(&identity, format!("{}\n", grant.node)).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
        Self {
            root,
            identity,
            grant,
            placement,
        }
    }

    pub(crate) fn call(&self, execution: Execution) -> NodeCall {
        let envelope = Envelope {
            schema: 3,
            grant_digest: self.grant.digest().unwrap(),
            cwd: vec!["sub".into()],
            execution,
            env_additions: vec![("FIXTURE_EXTRA".into(), "fictional-value".into())],
            deadline_ms: 10_000,
        };
        NodeCall {
            protocol: 1,
            request_id: "R:1".into(),
            nonce: "0123456789abcdef".into(),
            node: self.grant.node.clone(),
            grant: json!(self.grant),
            placement: self.placement.clone(),
            envelope: json!(envelope),
        }
    }

    pub(crate) fn owner() -> u32 {
        nix::unistd::Uid::effective().as_raw()
    }

    fn start(
        &self,
        call: &NodeCall,
        silence: Duration,
        output_limit: usize,
    ) -> (
        UnixStream,
        UnixStream,
        std::thread::JoinHandle<io::Result<()>>,
    ) {
        self.start_with_bounds(
            call,
            silence,
            silence,
            output_limit,
            OUTPUT_WRITE_BOUND,
            OUTPUT_DRAIN_BOUND,
        )
    }

    fn start_with_bounds(
        &self,
        call: &NodeCall,
        start_wait: Duration,
        silence: Duration,
        output_limit: usize,
        write_bound: Duration,
        drain_bound: Duration,
    ) -> (
        UnixStream,
        UnixStream,
        std::thread::JoinHandle<io::Result<()>>,
    ) {
        let (mut door_input, node_input) = UnixStream::pair().unwrap();
        let (node_output, door_output) = UnixStream::pair().unwrap();
        door_output
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let identity = self.identity.clone();
        let thread = std::thread::spawn(move || {
            serve_with_limits(
                node_input,
                node_output,
                &identity,
                Self::owner(),
                StreamBounds {
                    start_wait,
                    silence,
                    output_limit,
                    write: write_bound,
                    drain: drain_bound,
                },
            )
        });
        write_frame(&mut door_input, call).unwrap();
        (door_input, door_output, thread)
    }
}

/// Test-only process front: the installed binary keeps its fixed identity path.
/// The parent passes protocol descriptors 3 and 4, clear of libtest's stdout.
/// ´test:unit:workspace-node-process-entry-fixture´
#[test]
#[allow(unsafe_code)]
fn workspace_node_process_entry_fixture() {
    if std::env::var_os("SUPERLOOP_NODE_PROCESS_FIXTURE").is_none() {
        return;
    }
    // SAFETY: the exact parent fixture passes two owned descriptors at these numbers.
    let input = unsafe { File::from_raw_fd(3) };
    // SAFETY: descriptor 4 is distinct and owned by this child.
    let output = unsafe { File::from_raw_fd(4) };
    let identity = PathBuf::from(
        std::env::var_os("SUPERLOOP_NODE_PROCESS_IDENTITY").expect("fixture identity path"),
    );
    let silence_ms = std::env::var("SUPERLOOP_NODE_PROCESS_SILENCE_MS")
        .expect("fixture silence bound")
        .parse::<u64>()
        .expect("fixture silence milliseconds");
    let start_ms = std::env::var("SUPERLOOP_NODE_PROCESS_START_MS")
        .ok()
        .map_or(10_000, |value| {
            value.parse::<u64>().expect("fixture start milliseconds")
        });
    serve_with_limits(
        input,
        output,
        &identity,
        Fixture::owner(),
        StreamBounds {
            start_wait: Duration::from_millis(start_ms),
            silence: Duration::from_millis(silence_ms),
            output_limit: MAX_OUTPUT_BYTES,
            write: Duration::from_secs(2),
            drain: Duration::from_secs(2),
        },
    )
    .expect("real node serving function");
}

/// ´test:unit:workspace-node-prestart-bound-is-not-renewed-by-heartbeat´
#[test]
fn workspace_node_prestart_bound_is_not_renewed_by_heartbeat() {
    let fixture = Fixture::new();
    let marker = fixture.root.path().join("work/sub/started");
    let call = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "/usr/bin/touch started".into(),
    });
    let (mut input, node_input) = UnixStream::pair().unwrap();
    let (node_output, mut output) = UnixStream::pair().unwrap();
    output
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    write_frame(&mut input, &call).unwrap();
    let sent = std::sync::Arc::new(AtomicBool::new(false));
    let stop_sending = std::sync::Arc::clone(&sent);
    let heartbeats = std::thread::spawn(move || {
        while !stop_sending.load(Ordering::Acquire) {
            if write_frame(&mut input, &json!({"schema":1,"type":"heartbeat"})).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let identity = fixture.identity;
    let thread = std::thread::spawn(move || {
        serve_with_limits(
            node_input,
            node_output,
            &identity,
            Fixture::owner(),
            StreamBounds {
                start_wait: Duration::from_secs(1),
                silence: Duration::from_secs(10),
                output_limit: MAX_OUTPUT_BYTES,
                write: OUTPUT_WRITE_BOUND,
                drain: OUTPUT_DRAIN_BOUND,
            },
        )
    });
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    let terminal_read = read_frame(&mut output);
    sent.store(true, Ordering::Release);
    heartbeats.join().unwrap();
    let terminal = terminal_read.unwrap();
    assert_eq!(terminal["reason"], "node-heartbeat-silence");
    assert_eq!(terminal["steps"], json!([]));
    assert!(!marker.exists());
    thread.join().unwrap().unwrap();
}

/// ´test:unit:workspace-node-prestart-timeout-names-first-bound´
#[test]
fn workspace_node_prestart_timeout_names_first_bound() {
    let now = Instant::now();
    assert_eq!(
        prestart_timeout_cause(now + Duration::from_secs(1), now + Duration::from_secs(2)),
        CAUSE_SILENCE
    );
    assert_eq!(
        prestart_timeout_cause(now + Duration::from_secs(2), now + Duration::from_secs(1)),
        CAUSE_NONE
    );
    assert_eq!(
        end_reason(CAUSE_NONE, &Outcome::TimedOut, false),
        "node-deadline"
    );
}

fn argv(words: &[&str]) -> Execution {
    Execution::Argv {
        words: words.iter().map(|word| word.as_bytes().to_vec()).collect(),
    }
}

fn control(writer: &mut UnixStream, kind: &str) {
    write_frame(writer, &json!({"schema":1,"type":kind})).unwrap();
}

fn frames_until_terminal(reader: &mut UnixStream) -> Vec<Value> {
    let mut frames = Vec::new();
    loop {
        let frame = read_frame(reader).unwrap();
        let terminal = frame["type"] == "terminal";
        frames.push(frame);
        if terminal {
            return frames;
        }
    }
}

fn output_bytes(frames: &[Value], kind: &str) -> Vec<u8> {
    frames
        .iter()
        .filter(|frame| frame["type"] == kind)
        .flat_map(|frame| serde_json::from_value::<Vec<u8>>(frame["bytes"].clone()).unwrap())
        .collect()
}

/// ´test:unit:workspace-node-entry-names-failed-start-and-prior-step´
#[test]
fn workspace_node_entry_names_failed_start_and_prior_step() {
    let fixture = Fixture::new();
    let missing = "/no-such-workspace-program";
    let noexec = fixture.root.path().join("work/sub/noexec");
    fs::write(&noexec, b"fictional program").unwrap();
    fs::set_permissions(&noexec, fs::Permissions::from_mode(0o644)).unwrap();
    let noexec = noexec.to_str().unwrap();
    for (execution, kind, index, started, line) in [
        (
            argv(&[missing]),
            "not-found",
            0,
            false,
            format!("{missing}: not found\n"),
        ),
        (
            argv(&[noexec]),
            "not-executable",
            0,
            false,
            format!("{noexec}: not executable\n"),
        ),
        (
            Execution::Sequence {
                steps: vec![
                    vec![
                        b"/bin/sh".to_vec(),
                        b"-c".to_vec(),
                        b"printf prior".to_vec(),
                    ],
                    vec![missing.as_bytes().to_vec()],
                ],
            },
            "not-found",
            1,
            true,
            format!("{missing}: not found\n"),
        ),
    ] {
        let call = fixture.call(execution);
        let (mut input, mut output, thread) =
            fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
        assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
        control(&mut input, "start");
        let frames = frames_until_terminal(&mut output);
        let terminal = frames.last().unwrap();
        assert_eq!(terminal["reason"], "node-start-failed");
        assert_eq!(terminal["start_failure"]["kind"], kind);
        assert_eq!(terminal["start_failure"]["step_index"], index);
        assert_eq!(terminal["child_started"], started);
        assert_eq!(terminal["result"]["outcome"], json!(Outcome::Unknown));
        assert_eq!(output_bytes(&frames, "stderr"), line.as_bytes());
        if started {
            assert_eq!(output_bytes(&frames, "stdout"), b"prior");
        }
        thread.join().unwrap().unwrap();
    }
}

/// ´test:unit:workspace-node-entry-refuses-changed-context-before-open´
#[test]
fn workspace_node_entry_refuses_changed_context_before_open() {
    let fixture = Fixture::new();
    let linked = fixture.root.path().join("linked-identity");
    std::os::unix::fs::symlink(&fixture.identity, &linked).unwrap();
    assert!(installed_node_name(&linked, Fixture::owner()).is_err());
    fs::set_permissions(&fixture.identity, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(installed_node_name(&fixture.identity, Fixture::owner()).is_err());
    fs::set_permissions(&fixture.identity, fs::Permissions::from_mode(0o644)).unwrap();
    let clean = fixture.call(argv(&["/usr/bin/true"]));
    let cases = [
        ("grant", "door-workspace-context-differs", {
            let mut call = clean.clone();
            call.grant["workspace"] = json!("/other-workspace");
            call
        }),
        ("placement", "door-workspace-context-differs", {
            let mut call = clean.clone();
            call.placement["grant_digest"] = json!("f".repeat(64));
            call
        }),
        ("grant-node", "door-workspace-context-differs", {
            let mut call = clean.clone();
            call.grant["node"] = json!("other-node");
            let grant = Grant::decode(call.grant.clone()).unwrap();
            call.envelope["grant_digest"] = json!(grant.digest().unwrap());
            call.placement["node"] = json!("other-node");
            call.placement["grant_digest"] = call.envelope["grant_digest"].clone();
            call
        }),
        ("node", "door-workspace-context-differs", {
            let mut call = clean.clone();
            call.node = "other-node".into();
            call
        }),
        ("version", "door-workspace-protocol-refusal", {
            let mut call = clean.clone();
            call.protocol = 2;
            call
        }),
        ("nonce", "door-workspace-protocol-refusal", {
            let mut call = clean.clone();
            call.nonce = "not hex".into();
            call
        }),
    ];
    for (case, kind, call) in cases {
        let (input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
        input.shutdown(Shutdown::Write).unwrap();
        let error = thread.join().unwrap().unwrap_err();
        assert!(error.to_string().starts_with(kind), "{case}: {error}");
        let refused = read_frame(&mut output).unwrap();
        assert_eq!(refused["type"], "refusal", "{case}");
        assert_eq!(refused["reason"], kind, "{case}");
        assert!(read_frame(&mut output).is_err(), "{case}: one refusal");
    }
    let (mut input, mut output, thread) = fixture.start(&clean, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    let ack = read_frame(&mut output).unwrap();
    assert_eq!(ack["request_id"], "R:1");
    assert_eq!(ack["nonce"], "0123456789abcdef");
    assert_eq!(ack["entry_version"], env!("CARGO_PKG_VERSION"));
    control(&mut input, "stop");
    assert_eq!(read_frame(&mut output).unwrap()["type"], "terminal");
    thread.join().unwrap().unwrap();
}

/// ´test:unit:workspace-node-entry-rejects-oversized-frame-before-allocation´
#[test]
fn workspace_node_entry_rejects_oversized_frame_before_allocation() {
    let fixture = Fixture::new();
    let (mut input, node_input) = UnixStream::pair().unwrap();
    let (node_output, mut output) = UnixStream::pair().unwrap();
    let identity = fixture.identity;
    let thread =
        std::thread::spawn(move || serve(node_input, node_output, &identity, Fixture::owner()));
    input
        .write_all(&u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes())
        .unwrap();
    input.shutdown(Shutdown::Write).unwrap();
    assert!(
        thread
            .join()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("frame length")
    );
    assert_eq!(read_frame(&mut output).unwrap()["type"], "refusal");
    assert!(read_frame(&mut output).is_err());
}

/// ´test:unit:workspace-node-entry-frames-missing-identity-and-truncated-call´
#[test]
fn workspace_node_entry_frames_missing_identity_and_truncated_call() {
    let fixture = Fixture::new();
    let call = fixture.call(argv(&["/usr/bin/true"]));
    fs::remove_file(&fixture.identity).unwrap();
    let (input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    input.shutdown(Shutdown::Write).unwrap();
    assert!(thread.join().unwrap().is_err());
    let refused = read_frame(&mut output).unwrap();
    assert_eq!(refused["type"], "refusal");
    assert_eq!(refused["reason"], "door-workspace-context-differs");
    assert!(read_frame(&mut output).is_err());

    let (mut input, node_input) = UnixStream::pair().unwrap();
    let (node_output, mut output) = UnixStream::pair().unwrap();
    let identity = fixture.identity;
    let thread =
        std::thread::spawn(move || serve(node_input, node_output, &identity, Fixture::owner()));
    input.write_all(&10_u32.to_be_bytes()).unwrap();
    input.write_all(b"half").unwrap();
    input.shutdown(Shutdown::Write).unwrap();
    assert!(thread.join().unwrap().is_err());
    let refused = read_frame(&mut output).unwrap();
    assert_eq!(refused["type"], "refusal");
    assert_eq!(refused["reason"], "door-workspace-protocol-refusal");
    assert!(read_frame(&mut output).is_err());
}

/// ´test:unit:workspace-node-entry-stop-and-eof-before-spawn´
#[test]
fn workspace_node_entry_stop_and_eof_before_spawn() {
    let fixture = Fixture::new();
    let marker = fixture.root.path().join("work/sub/spawned");
    let call = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "touch spawned".into(),
    });
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "stop");
    let terminal = read_frame(&mut output).unwrap();
    assert_eq!(terminal["type"], "terminal");
    assert_eq!(terminal["reason"], "node-stopped");
    assert_eq!(terminal["child_started"], false);
    assert_eq!(terminal["result"]["outcome"], json!(Outcome::TimedOut));
    thread.join().unwrap().unwrap();
    assert!(!marker.exists());

    let (input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    input.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        read_frame(&mut output).unwrap()["reason"],
        "node-input-closed"
    );
    thread.join().unwrap().unwrap();
    assert!(!marker.exists());

    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "junk");
    assert_eq!(
        read_frame(&mut output).unwrap()["reason"],
        "node-malformed-control"
    );
    thread.join().unwrap().unwrap();
    assert!(!marker.exists());

    let (_input, mut output, thread) = fixture.start(&call, Duration::ZERO, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    assert_eq!(
        read_frame(&mut output).unwrap()["reason"],
        "node-heartbeat-silence"
    );
    thread.join().unwrap().unwrap();
    assert!(!marker.exists());
}

/// ´test:unit:workspace-node-entry-frames-exact-execution-and-measurements´
#[test]
fn workspace_node_entry_frames_exact_execution_and_measurements() {
    let fixture = Fixture::new();
    let call = fixture.call(argv(&["/usr/bin/env"]));
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    let ack = read_frame(&mut output).unwrap();
    assert_eq!(ack["type"], "ack");
    assert_eq!(ack["frame_handle"].as_str().unwrap().len(), 16);
    control(&mut input, "start");
    let frames = frames_until_terminal(&mut output);
    let stdout = output_bytes(&frames, "stdout");
    assert!(
        stdout
            .windows(b"FIXTURE_EXTRA=fictional-value".len())
            .any(|part| part == b"FIXTURE_EXTRA=fictional-value")
    );
    assert_eq!(
        frames.last().unwrap()["result"]["outcome"],
        json!(Outcome::Exited { code: 0 })
    );
    assert_eq!(frames.last().unwrap()["output_bytes"], stdout.len());
    thread.join().unwrap().unwrap();

    let call = fixture.call(argv(&["/bin/sh", "-c", "printf out; printf err >&2"]));
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    let frames = frames_until_terminal(&mut output);
    assert_eq!(output_bytes(&frames, "stdout"), b"out");
    assert_eq!(output_bytes(&frames, "stderr"), b"err");
    thread.join().unwrap().unwrap();

    let call = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf '%s' \"$FIXTURE_EXTRA\"; pwd -P".into(),
    });
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    let frames = frames_until_terminal(&mut output);
    let stdout = String::from_utf8(output_bytes(&frames, "stdout")).unwrap();
    assert!(stdout.starts_with("fictional-value"));
    assert!(stdout.contains(&fixture.root.path().join("work/sub").display().to_string()));
    assert_eq!(
        frames.last().unwrap()["result"]["outcome"],
        json!(Outcome::Exited { code: 0 })
    );
    thread.join().unwrap().unwrap();
}

/// ´test:unit:workspace-node-entry-cancels-on-stop-eof-and-silence´
#[test]
fn workspace_node_entry_cancels_on_stop_eof_and_silence() {
    let fixture = Fixture::new();
    let waiting = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf ready; exec /usr/bin/sleep 30".into(),
    });
    for (ending, reason) in [
        ("stop", "node-stopped"),
        ("eof", "node-input-closed"),
        ("junk", "node-malformed-control"),
    ] {
        let (mut input, mut output, thread) =
            fixture.start(&waiting, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
        assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
        control(&mut input, "start");
        assert_eq!(read_frame(&mut output).unwrap()["type"], "stdout");
        if ending == "eof" {
            input.shutdown(Shutdown::Write).unwrap();
        } else {
            control(&mut input, ending);
        }
        let frames = frames_until_terminal(&mut output);
        assert_eq!(
            frames.last().unwrap()["result"]["outcome"],
            json!(Outcome::TimedOut)
        );
        assert_eq!(frames.last().unwrap()["reason"], reason);
        assert_eq!(frames.last().unwrap()["child_started"], true);
        thread.join().unwrap().unwrap();
    }
    let (_input, mut output, thread) = fixture.start(&waiting, Duration::ZERO, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    let frames = frames_until_terminal(&mut output);
    assert_eq!(
        frames.last().unwrap()["result"]["outcome"],
        json!(Outcome::TimedOut)
    );
    assert_eq!(frames.last().unwrap()["reason"], "node-heartbeat-silence");
    thread.join().unwrap().unwrap();
}

/// ´test:unit:workspace-node-entry-bounds-escaped-descendant-output-pipe´
#[test]
fn workspace_node_entry_bounds_escaped_descendant_output_pipe() {
    let fixture = Fixture::new();
    let marker = fixture.root.path().join("work/sub/escaped.pid");
    let call = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "setsid /usr/bin/sleep 30 & echo $! > escaped.pid; printf ready".into(),
    });
    let (mut input, mut output, thread) = fixture.start_with_bounds(
        &call,
        CONTROL_SILENCE,
        CONTROL_SILENCE,
        MAX_OUTPUT_BYTES,
        OUTPUT_WRITE_BOUND,
        Duration::ZERO,
    );
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    let frames = frames_until_terminal(&mut output);
    assert_eq!(output_bytes(&frames, "stdout"), b"ready");
    assert_eq!(frames.last().unwrap()["output_incomplete"], true);
    assert_eq!(frames.last().unwrap()["reason"], "node-output-incomplete");
    thread.join().unwrap().unwrap();
    let pid: i32 = fs::read_to_string(marker).unwrap().trim().parse().unwrap();
    // SAFETY: the fixture created this child and reads its pid from its private workspace.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// ´test:unit:workspace-node-drain-follows-last-byte-with-total-bound´
#[test]
fn workspace_node_drain_follows_last_byte_with_total_bound() {
    let ended = Instant::now();
    let idle = Duration::from_secs(2);
    assert!(!drain_expired(
        ended,
        Some(ended + Duration::from_secs(1)),
        ended + Duration::from_secs(2),
        idle,
    ));
    assert!(drain_expired(
        ended,
        Some(ended + Duration::from_secs(1)),
        ended + Duration::from_secs(3),
        idle,
    ));
    assert!(drain_expired(
        ended,
        Some(ended + Duration::from_secs(119)),
        ended + OUTPUT_DRAIN_TOTAL,
        idle,
    ));
}

/// ´test:unit:workspace-node-entry-stalled-output-bounds-memory-and-command´
#[test]
fn workspace_node_entry_stalled_output_bounds_memory_and_command() {
    let fixture = Fixture::new();
    let marker = fixture.root.path().join("work/sub/queue-drained");
    let call = fixture.call(Execution::Shell {
        shell: "/bin/sh".into(),
        text: "/usr/bin/head -c 8388608 /dev/zero; /usr/bin/touch queue-drained".into(),
    });
    let (mut input, mut output, thread) = fixture.start_with_bounds(
        &call,
        CONTROL_SILENCE,
        CONTROL_SILENCE,
        MAX_OUTPUT_BYTES,
        Duration::from_secs(2),
        OUTPUT_DRAIN_BOUND,
    );
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    // Leave output unread: the writer must end the command without buffering the stream.
    let error = thread.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        !marker.exists(),
        "the child drained an unbounded output queue"
    );
}

/// ´test:unit:workspace-node-entry-bounds-output-and-sequence´
#[test]
fn workspace_node_entry_bounds_output_and_sequence() {
    let fixture = Fixture::new();
    assert_eq!(MAX_OUTPUT_BYTES, 16 * 1024 * 1024);
    let call = fixture.call(argv(&["/usr/bin/head", "-c", "4096", "/dev/zero"]));
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, 1024);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    let frames = frames_until_terminal(&mut output);
    assert_eq!(frames.last().unwrap()["reason"], "node-output-limit");
    assert!(output_bytes(&frames, "stdout").len() <= 1024);
    thread.join().unwrap().unwrap();

    let call = fixture.call(Execution::Sequence {
        steps: vec![
            vec![
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                b"printf ready; exec /usr/bin/sleep 30".to_vec(),
            ],
            vec![b"/usr/bin/touch".to_vec(), b"later-step".to_vec()],
        ],
    });
    let (mut input, mut output, thread) = fixture.start(&call, CONTROL_SILENCE, MAX_OUTPUT_BYTES);
    assert_eq!(read_frame(&mut output).unwrap()["type"], "ack");
    control(&mut input, "start");
    assert_eq!(read_frame(&mut output).unwrap()["type"], "stdout");
    control(&mut input, "stop");
    let frames = frames_until_terminal(&mut output);
    assert_eq!(
        frames.last().unwrap()["result"]["outcome"],
        json!(Outcome::TimedOut)
    );
    assert_eq!(frames.last().unwrap()["steps"].as_array().unwrap().len(), 1);
    assert!(!fixture.root.path().join("work/sub/later-step").exists());
    thread.join().unwrap().unwrap();
}

/// ´test:unit:workspace-node-terminal-reasons-stay-separate-from-door-replies´
#[test]
fn workspace_node_terminal_reasons_stay_separate_from_door_replies() {
    let timed_out = Outcome::TimedOut;
    let completed = Outcome::Exited { code: 0 };
    for (cause, outcome, incomplete, reason) in [
        (CAUSE_STOP, &timed_out, false, "node-stopped"),
        (CAUSE_INPUT_GONE, &timed_out, false, "node-input-closed"),
        (CAUSE_SILENCE, &timed_out, false, "node-heartbeat-silence"),
        (CAUSE_MALFORMED, &timed_out, false, "node-malformed-control"),
        (CAUSE_OUTPUT_LIMIT, &timed_out, false, "node-output-limit"),
        (CAUSE_NONE, &completed, true, "node-output-incomplete"),
        (CAUSE_NONE, &timed_out, true, "node-output-incomplete"),
        (CAUSE_NONE, &timed_out, false, "node-deadline"),
        (CAUSE_NONE, &completed, false, "node-complete"),
        (CAUSE_STOP, &timed_out, true, "node-stopped"),
    ] {
        assert_eq!(end_reason(cause, outcome, incomplete), reason);
        assert!(!reason.starts_with("door-"));
    }
}
