//! Door half of the protocol-one workspace executor call. No serving caller selects it yet.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use execute_command::workspace::{Measurement, Outcome, canonical_digest};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::workspace_node::NodeCall;
use crate::workspace_node::{read_frame_before, write_frame_before};

use super::transport::AuthenticatedNode;
use super::{WorkspaceAllowance, WorkspaceRequest};

fn refusal(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

/// An authenticated route name and the exact owner-held request, before SSH.
pub(super) struct WorkspaceCall {
    frame: NodeCall,
    handle: String,
}

impl WorkspaceCall {
    /// Compose one call only after checking the allowance against its owner-held request.
    /// # Errors
    /// Refuses a changed grant, missing placement, invalid id or unavailable randomness.
    pub(crate) fn compose(
        request: &WorkspaceRequest,
        allowance: &WorkspaceAllowance,
        node: &AuthenticatedNode,
        request_id: &str,
    ) -> Result<Self, LaneError> {
        allowance.check(request)?;
        if request.grant().node != node.name() {
            return Err(refusal(
                "door-workspace-context-differs",
                "registered route node differs from the protected grant; check register-door-node --node",
            ));
        }
        let placement = request.placement().ok_or_else(|| {
            refusal(
                "door-workspace-context-differs",
                "protected workspace placement is absent",
            )
        })?;
        if request_id.is_empty()
            || request_id.len() > 160
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "request id differs",
            ));
        }
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|error| refusal("door-workspace-protocol-refusal", error.to_string()))?;
        let nonce = random
            .iter()
            .fold(String::with_capacity(32), |mut text, byte| {
                use std::fmt::Write as _;
                let _written = write!(text, "{byte:02x}");
                text
            });
        let frame = NodeCall {
            protocol: 1,
            request_id: request_id.to_owned(),
            nonce,
            node: node.name().to_owned(),
            grant: json!(request.grant()),
            placement: json!(placement),
            envelope: json!(request.envelope()),
        };
        let digest = canonical_digest(&frame).map_err(|error| refusal(error.kind, error.detail))?;
        let handle = digest
            .get(..16)
            .ok_or_else(|| refusal("door-workspace-protocol-refusal", "frame handle differs"))?;
        Ok(Self {
            frame,
            handle: handle.to_owned(),
        })
    }

    pub(crate) const fn frame(&self) -> &NodeCall {
        &self.frame
    }

    fn check_echo(&self, value: &Value) -> Result<(), LaneError> {
        if value["schema"] != 1
            || value["request_id"] != self.frame.request_id
            || value["nonce"] != self.frame.nonce
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node frame belongs to another request",
            ));
        }
        Ok(())
    }

    /// Check the acknowledgement, including its same-connection frame handle.
    /// # Errors
    /// Refuses an altered echo, unsupported shape or unbounded version.
    pub(crate) fn acknowledge(&self, value: &Value) -> Result<BuildEvidence, LaneError> {
        self.check_echo(value)?;
        let object = value.as_object().ok_or_else(|| {
            refusal(
                "door-workspace-protocol-refusal",
                "node acknowledgement is not an object",
            )
        })?;
        if object.len() != 6 || value["type"] != "ack" || value["frame_handle"] != self.handle {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node acknowledgement differs",
            ));
        }
        let version = value["entry_version"]
            .as_str()
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= 80
                    && text.bytes().all(|byte| byte.is_ascii_graphic())
            })
            .ok_or_else(|| refusal("door-workspace-protocol-refusal", "node build is invalid"))?;
        Ok(BuildEvidence {
            entry_version: version.to_owned(),
            differs: version != env!("CARGO_PKG_VERSION"),
        })
    }
}

/// The release printed by the entry's `--version`, preserved even when it differs.
pub(super) struct BuildEvidence {
    pub(crate) entry_version: String,
    pub(crate) differs: bool,
}

/// Door-owned interpretation of the node's terminal reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Ending {
    Complete,
    NodeDeadline,
    Interrupted(&'static str),
    OutputLimit,
    OutputIncomplete,
    Incomplete,
}

/// A terminal result, with the node word retained only as evidence.
pub(super) struct WorkspaceResult {
    pub(crate) ending: Ending,
    pub(crate) node_reason: String,
    pub(crate) result: Measurement,
    pub(crate) steps: Vec<Measurement>,
    pub(crate) output_bytes: usize,
    pub(crate) output_incomplete: bool,
    pub(crate) build: BuildEvidence,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    schema: u8,
    #[serde(rename = "type")]
    kind: String,
    request_id: String,
    nonce: String,
    result: Measurement,
    steps: Vec<Measurement>,
    output_bytes: usize,
    reason: String,
    output_incomplete: bool,
}

impl WorkspaceResult {
    /// Map a terminal by reason, including a pre-start terminal with no steps.
    /// # Errors
    /// Refuses an unrecognized or crossed terminal, never treating it as completed.
    pub(crate) fn from_terminal(
        call: &WorkspaceCall,
        frame: Value,
        build: BuildEvidence,
    ) -> Result<Self, LaneError> {
        let terminal: Terminal = serde_json::from_value(frame)
            .map_err(|error| refusal("door-workspace-protocol-refusal", error.to_string()))?;
        if terminal.schema != 1
            || terminal.kind != "terminal"
            || terminal.request_id != call.frame.request_id
            || terminal.nonce != call.frame.nonce
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node terminal belongs to another request",
            ));
        }
        let ending = match terminal.reason.as_str() {
            "node-complete" if !terminal.output_incomplete => Ending::Complete,
            "node-deadline" => Ending::NodeDeadline,
            "node-stopped" => Ending::Interrupted("stop"),
            "node-input-closed" => Ending::Interrupted("input-closed"),
            "node-heartbeat-silence" => Ending::Interrupted("heartbeat-silence"),
            "node-malformed-control" => Ending::Interrupted("malformed-control"),
            "node-output-limit" => Ending::OutputLimit,
            "node-output-incomplete" if terminal.output_incomplete => Ending::OutputIncomplete,
            _ => {
                return Err(refusal(
                    "door-workspace-protocol-refusal",
                    "node terminal reason differs",
                ));
            }
        };
        if matches!(ending, Ending::Complete) && terminal.result.outcome == Outcome::Unknown {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "completed node call has no outcome",
            ));
        }
        Ok(Self {
            ending,
            node_reason: terminal.reason,
            result: terminal.result,
            steps: terminal.steps,
            output_bytes: terminal.output_bytes,
            output_incomplete: terminal.output_incomplete,
            build,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    pub(crate) fn evidence(&self) -> Value {
        let (state, cause) = match &self.ending {
            Ending::Complete => ("completed", None),
            Ending::NodeDeadline => ("interrupted", Some("node-command-deadline")),
            Ending::Interrupted(cause) => ("interrupted", Some(*cause)),
            Ending::OutputLimit => ("refused", Some("output-limit")),
            Ending::OutputIncomplete => ("incomplete", Some("held-output")),
            Ending::Incomplete => ("unknown", Some("route-incomplete")),
        };
        json!({"node_reason":self.node_reason,"entry_version":self.build.entry_version,
            "entry_version_differs":self.build.differs,"output_incomplete":self.output_incomplete,
            "output_bytes":self.output_bytes,"result":self.result,"steps":self.steps,
            "ending":state,"cause":cause})
    }
}

fn io_refusal(error: &io::Error) -> LaneError {
    refusal("door-workspace-protocol-refusal", error.to_string())
}

const START_BOUND: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const NODE_DRAIN_AND_WRITE: Duration = Duration::from_secs(240);
const FINAL_BOUND: Duration = Duration::from_secs(5);

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let group = nix::unistd::Pid::from_raw(self.0.id().cast_signed());
        let _killed = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        let _reaped = self.0.wait();
    }
}

enum Control {
    Stop,
    Finish,
}

/// Run one already composed call over a route process. The host route supplies
/// only a fixed remote program; all request bytes travel in the bounded frame.
/// # Errors
/// Refuses a crossed frame, route fault or output above the door's own ceiling.
pub(super) fn run_command(
    call: &WorkspaceCall,
    mut command: Command,
    stop: &AtomicBool,
    lifetime: Instant,
) -> Result<WorkspaceResult, LaneError> {
    command.process_group(0);
    let mut child = ChildGuard(
        command
            .spawn()
            .map_err(|error| refusal("door-compute-tool-refusal", error.to_string()))?,
    );
    let input = child
        .0
        .stdin
        .take()
        .ok_or_else(|| refusal("door-compute-tool-refusal", "route input is absent"))?;
    let mut output = child
        .0
        .stdout
        .take()
        .ok_or_else(|| refusal("door-compute-tool-refusal", "route output is absent"))?;
    let answer = run_stream(call, input, &mut output, stop, lifetime, HEARTBEAT_INTERVAL);
    if answer.is_err() {
        let settle = Instant::now() + Duration::from_millis(100);
        loop {
            if let Ok(Some(status)) = child.0.try_wait() {
                if matches!(status.code(), Some(126 | 127)) {
                    return Err(refusal(
                        "door-compute-tool-refusal",
                        "registered node entry is absent or cannot run; install superloop-lane-node-exec",
                    ));
                }
                break;
            }
            if Instant::now() >= settle {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    answer
}

/// Drive protocol one over one already connected pair of descriptors.
/// The process fixture uses this same driver against a separate test process.
// The one connection's control, output and terminal progression stays together
// so a terminal already read wins over a later closed control pipe.
#[allow(clippy::too_many_lines)]
fn run_stream<I: AsRawFd + Send + 'static, O: AsRawFd + io::Read>(
    call: &WorkspaceCall,
    input: I,
    output: &mut O,
    stop: &AtomicBool,
    lifetime: Instant,
    heartbeat_interval: Duration,
) -> Result<WorkspaceResult, LaneError> {
    write_frame_before(&input, call.frame(), Instant::now() + START_BOUND)
        .map_err(|error| io_refusal(&error))?;
    let first = read_frame_before(
        output,
        lifetime.min(Instant::now() + Duration::from_secs(20)),
        stop,
    )
    .map_err(|error| io_refusal(&error))?;
    if first["type"] == "refusal" {
        let object = first.as_object().ok_or_else(|| {
            refusal(
                "door-workspace-protocol-refusal",
                "node refusal is not an object",
            )
        })?;
        let kind = first["reason"].as_str().ok_or_else(|| {
            refusal(
                "door-workspace-protocol-refusal",
                "node refusal has no reason",
            )
        })?;
        let recognized = match kind {
            "door-workspace-context-differs" => "door-workspace-context-differs",
            "door-workspace-unregistered" => "door-workspace-unregistered",
            "door-workspace-protocol-refusal" => "door-workspace-protocol-refusal",
            _ => {
                return Err(refusal(
                    "door-workspace-protocol-refusal",
                    "node refusal differs",
                ));
            }
        };
        if object.len() != 3 || first["schema"] != 1 {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node refusal differs",
            ));
        }
        return Err(refusal(
            recognized,
            format!(
                "node entry refused before acknowledgement; check registered node, grant and placement ({kind})"
            ),
        ));
    }
    let build = call.acknowledge(&first)?;
    let (control_tx, control_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let writer = thread::spawn(move || -> io::Result<()> {
        let start = write_frame_before(
            &input,
            &json!({"schema":1,"type":"start"}),
            Instant::now() + START_BOUND,
        );
        let _sent = started_tx.send(start.as_ref().err().map(ToString::to_string));
        start?;
        loop {
            match control_rx.recv_timeout(heartbeat_interval) {
                Ok(Control::Stop) => {
                    let _sent = write_frame_before(
                        &input,
                        &json!({"schema":1,"type":"stop"}),
                        Instant::now() + START_BOUND,
                    );
                    return Ok(());
                }
                Ok(Control::Finish) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => write_frame_before(
                    &input,
                    &json!({"schema":1,"type":"heartbeat"}),
                    Instant::now() + START_BOUND,
                )?,
            }
        }
    });
    let started = started_rx.recv_timeout(START_BOUND).map_err(|error| {
        refusal(
            "door-workspace-protocol-refusal",
            format!("start was not sent: {error}"),
        )
    })?;
    if let Some(error) = started {
        let _joined = writer.join();
        return Err(refusal("door-workspace-protocol-refusal", error));
    }
    let terminal_deadline = lifetime.min(
        Instant::now()
            + Duration::from_millis(call.frame.envelope["deadline_ms"].as_u64().unwrap_or(0))
            + NODE_DRAIN_AND_WRITE
            + FINAL_BOUND,
    );
    let mut forwarded = 0_usize;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut sent_stop = false;
    let mut frame_fault = None;
    let never_stop = AtomicBool::new(false);
    let terminal = loop {
        let check_stop = if sent_stop { &never_stop } else { stop };
        let frame = match read_frame_before(output, terminal_deadline, check_stop) {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && !sent_stop => {
                let _sent = control_tx.send(Control::Stop);
                sent_stop = true;
                continue;
            }
            Err(_) => {
                if !sent_stop {
                    let _sent = control_tx.send(Control::Stop);
                }
                break None;
            }
        };
        match frame["type"].as_str() {
            Some("terminal") => break Some(frame),
            Some("stdout" | "stderr") => {
                if frame["schema"] != 1 || frame.as_object().is_none_or(|o| o.len() != 3) {
                    frame_fault = Some("node output frame shape differs");
                    break None;
                }
                let bytes = frame["bytes"].as_array().ok_or_else(|| {
                    refusal(
                        "door-workspace-protocol-refusal",
                        "node output bytes differ",
                    )
                })?;
                forwarded = forwarded.checked_add(bytes.len()).ok_or_else(|| {
                    refusal("door-output-limit-refusal", "node output length overflow")
                })?;
                if forwarded > crate::workspace_node::MAX_OUTPUT_BYTES {
                    break None;
                }
                let bytes = bytes
                    .iter()
                    .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        refusal(
                            "door-workspace-protocol-refusal",
                            "node output byte differs",
                        )
                    })?;
                if frame["type"] == "stdout" {
                    stdout.extend_from_slice(&bytes);
                } else {
                    stderr.extend_from_slice(&bytes);
                }
            }
            _ => {
                frame_fault = Some("node frame kind differs");
                break None;
            }
        }
    };
    let _sent = control_tx.send(Control::Finish);
    let _joined = writer.join();
    if let Some(detail) = frame_fault {
        return Err(refusal("door-workspace-protocol-refusal", detail));
    }
    let Some(terminal) = terminal else {
        if forwarded > crate::workspace_node::MAX_OUTPUT_BYTES {
            return Err(refusal(
                "door-output-limit-refusal",
                "door output exceeded 16 MiB",
            ));
        }
        return Ok(WorkspaceResult {
            ending: Ending::Incomplete,
            node_reason: "unobserved".to_owned(),
            result: Measurement {
                outcome: Outcome::Unknown,
                wall_seconds: None,
                user_cpu_seconds: None,
                system_cpu_seconds: None,
            },
            steps: Vec::new(),
            output_bytes: forwarded,
            output_incomplete: true,
            build,
            stdout,
            stderr,
        });
    };
    let mut result = WorkspaceResult::from_terminal(call, terminal, build)?;
    if result.output_bytes != forwarded {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "node output count differs from forwarded bytes",
        ));
    }
    result.stdout = stdout;
    result.stderr = stderr;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use execute_command::workspace::Execution;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    #[allow(unsafe_code)]
    fn process_fixture(identity: &std::path::Path) -> (UnixStream, UnixStream, ChildGuard) {
        let (door_input, node_input) = UnixStream::pair().expect("call pipe");
        let (node_output, door_output) = UnixStream::pair().expect("reply pipe");
        door_output
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("reply bound");
        let node_input_fd = node_input.as_raw_fd();
        let node_output_fd = node_output.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "workspace_node::tests::workspace_node_process_entry_fixture",
                "--nocapture",
            ])
            .env("SUPERLOOP_NODE_PROCESS_FIXTURE", "1")
            .env("SUPERLOOP_NODE_PROCESS_IDENTITY", identity)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        // SAFETY: only async-signal-safe descriptor operations run after fork.
        unsafe {
            command.pre_exec(move || {
                let source_input = libc::fcntl(node_input_fd, libc::F_DUPFD_CLOEXEC, 10);
                let source_output = libc::fcntl(node_output_fd, libc::F_DUPFD_CLOEXEC, 10);
                if source_input < 0
                    || source_output < 0
                    || libc::dup2(source_input, 3) < 0
                    || libc::dup2(source_output, 4) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                libc::close(source_input);
                libc::close(source_output);
                Ok(())
            });
        }
        let child = ChildGuard(command.spawn().expect("node process fixture"));
        drop(node_input);
        drop(node_output);
        (door_input, door_output, child)
    }

    fn custodied_request(
        fixture: &crate::workspace_node::tests::Fixture,
        envelope: &execute_command::workspace::Envelope,
    ) -> WorkspaceRequest {
        use std::fs;
        let runs = fixture.root.path().join("runs");
        fs::create_dir_all(runs.join("R")).expect("run directory");
        let snapshot = json!({"grant":fixture.grant,"digest":fixture.grant.digest().unwrap()});
        let saved = json!({"schema":1,"phase":"started","loop":"alpha","run":"R",
            "worker_uid":3000,"door_scope":"work","plan":{"loop":"alpha","run":"R",
            "compute_workspace":snapshot,"compute_placement":fixture.placement}});
        let reservation = crate::launch::reservation_path(&runs, "R");
        crate::launch::publish_reservation(&reservation, &saved).expect("reservation");
        let held = fs::File::open(&runs).expect("runs descriptor").into();
        let registration = super::super::Registration {
            loop_name: "alpha".into(),
            run: "R".into(),
            worker_uid: 3000,
            loop_uid: crate::workspace_node::tests::Fixture::owner(),
            scope: super::super::Scope::Work,
            mirror_ref: "refs/heads/lane/R".into(),
        };
        super::super::workspace_request(
            &held,
            &registration,
            crate::workspace_node::tests::Fixture::owner(),
            &fixture.grant.node,
            &serde_json::to_vec(envelope).expect("wire"),
        )
        .expect("custodied request")
    }

    /// ´test:unit:workspace-adapter-maps-real-process-completion-and-output´
    #[test]
    fn workspace_adapter_maps_real_process_completion_and_output() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Shell {
            shell: "/bin/sh".into(),
            text: "printf answer; printf warning >&2".into(),
        });
        let digest = canonical_digest(&frame).expect("frame digest");
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let (input, mut output, mut child) = process_fixture(&fixture.identity);
        let result = run_stream(
            &call,
            input,
            &mut output,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(15),
            Duration::from_millis(100),
        )
        .expect("node call");
        assert_eq!(result.ending, Ending::Complete);
        assert_eq!(result.stdout, b"answer");
        assert_eq!(result.stderr, b"warning");
        assert!(!result.build.differs);
        assert!(child.0.wait().expect("node exit").success());
    }

    /// ´test:unit:workspace-adapter-refuses-node-mismatch-before-route-spawn´
    #[test]
    fn workspace_adapter_refuses_node_mismatch_before_route_spawn() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let envelope = execute_command::workspace::Envelope::decode(frame.envelope).unwrap();
        let request = custodied_request(&fixture, &envelope);
        let allowance = super::super::workspace::fixture_allowance(&request);
        let foreign = super::super::transport::fixture_node("foreign-node");
        let error = WorkspaceCall::compose(&request, &allowance, &foreign, "R:1")
            .err()
            .expect("node mismatch");
        assert_eq!(error.kind, "door-workspace-context-differs");
        assert!(error.detail.contains("register-door-node --node"));
        let own = super::super::transport::fixture_node(&fixture.grant.node);
        let call = WorkspaceCall::compose(&request, &allowance, &own, "R:1")
            .expect("registered node and protected request");
        assert_eq!(call.frame.node, fixture.grant.node);
        assert_eq!(call.frame.grant, json!(fixture.grant));
        assert_eq!(call.frame.placement, fixture.placement);
        assert_eq!(call.frame.envelope, json!(envelope));
    }

    /// ´test:unit:workspace-adapter-crossed-ack-and-version-drift-are-visible´
    #[test]
    fn workspace_adapter_crossed_ack_and_version_drift_are_visible() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let ack = json!({"schema":1,"type":"ack","request_id":call.frame.request_id,
            "nonce":call.frame.nonce,"frame_handle":call.handle,"entry_version":"0.0.0"});
        let build = call
            .acknowledge(&ack)
            .expect("version difference is evidence");
        assert!(build.differs);
        assert_eq!(build.entry_version, "0.0.0");
        let mut crossed = ack;
        crossed["nonce"] = json!("f00d");
        assert_eq!(
            call.acknowledge(&crossed).err().expect("crossed ack").kind,
            "door-workspace-protocol-refusal"
        );
        let terminal = json!({"schema":1,"type":"terminal","request_id":"another",
            "nonce":call.frame.nonce,"result":{"outcome":{"kind":"Unknown"},
                "wall_seconds":null,"user_cpu_seconds":null,"system_cpu_seconds":null},
            "steps":[],"output_bytes":0,"reason":"node-complete","output_incomplete":false});
        let build = call
            .acknowledge(&json!({"schema":1,"type":"ack",
            "request_id":call.frame.request_id,"nonce":call.frame.nonce,
            "frame_handle":call.handle,"entry_version":"0.0.0"}))
            .unwrap();
        assert_eq!(
            WorkspaceResult::from_terminal(&call, terminal, build)
                .err()
                .expect("crossed terminal")
                .kind,
            "door-workspace-protocol-refusal"
        );
    }

    /// ´test:unit:workspace-adapter-maps-every-prestart-terminal-by-reason´
    #[test]
    fn workspace_adapter_maps_every_prestart_terminal_by_reason() {
        use std::net::Shutdown;
        for (control, reason, cause) in [
            ("stop", "node-stopped", "stop"),
            ("eof", "node-input-closed", "input-closed"),
            ("other", "node-malformed-control", "malformed-control"),
            ("silence", "node-heartbeat-silence", "heartbeat-silence"),
        ] {
            let fixture = crate::workspace_node::tests::Fixture::new();
            let frame = fixture.call(Execution::Argv {
                words: vec![b"/bin/true".to_vec()],
            });
            let digest = canonical_digest(&frame).unwrap();
            let call = WorkspaceCall {
                frame,
                handle: digest[..16].to_owned(),
            };
            let (mut input, mut output, mut child) = process_fixture(&fixture.identity);
            crate::workspace_node::write_frame(&mut input, call.frame()).unwrap();
            match control {
                "eof" => input.shutdown(Shutdown::Write).unwrap(),
                "silence" => {}
                _ => crate::workspace_node::write_frame(
                    &mut input,
                    &json!({"schema":1,"type":control}),
                )
                .unwrap(),
            }
            let ack = crate::workspace_node::read_frame(&mut output).unwrap();
            let build = call.acknowledge(&ack).unwrap();
            let terminal = crate::workspace_node::read_frame(&mut output).unwrap();
            let result = WorkspaceResult::from_terminal(&call, terminal, build).unwrap();
            assert_eq!(result.node_reason, reason);
            assert_eq!(result.ending, Ending::Interrupted(cause));
            assert_eq!(result.steps.len(), 0);
            assert!(child.0.wait().unwrap().success());
        }
    }

    /// ´test:unit:workspace-adapter-maps-running-stop-and-closed-route´
    #[test]
    fn workspace_adapter_maps_running_stop_and_closed_route() {
        use std::net::Shutdown;
        for (control, cause) in [("stop", "stop"), ("eof", "input-closed")] {
            let fixture = crate::workspace_node::tests::Fixture::new();
            let frame = fixture.call(Execution::Shell {
                shell: "/bin/sh".into(),
                text: "printf ready; exec /usr/bin/sleep 30".into(),
            });
            let digest = canonical_digest(&frame).unwrap();
            let call = WorkspaceCall {
                frame,
                handle: digest[..16].to_owned(),
            };
            let (mut input, mut output, mut child) = process_fixture(&fixture.identity);
            crate::workspace_node::write_frame(&mut input, call.frame()).unwrap();
            crate::workspace_node::write_frame(&mut input, &json!({"schema":1,"type":"start"}))
                .unwrap();
            let ack = crate::workspace_node::read_frame(&mut output).unwrap();
            let build = call.acknowledge(&ack).unwrap();
            let ready = crate::workspace_node::read_frame(&mut output).unwrap();
            assert_eq!(ready["type"], "stdout");
            if control == "eof" {
                input.shutdown(Shutdown::Write).unwrap();
            } else {
                crate::workspace_node::write_frame(&mut input, &json!({"schema":1,"type":"stop"}))
                    .unwrap();
            }
            let terminal = crate::workspace_node::read_frame(&mut output).unwrap();
            let result = WorkspaceResult::from_terminal(&call, terminal, build).unwrap();
            assert_eq!(result.ending, Ending::Interrupted(cause));
            assert!(child.0.wait().unwrap().success());
        }
    }

    /// ´test:unit:workspace-adapter-heartbeats-outlast-silence-and-silence-cancels´
    #[test]
    fn workspace_adapter_heartbeats_outlast_silence_and_silence_cancels() {
        use std::sync::Arc;
        for heartbeat in [true, false] {
            let fixture = crate::workspace_node::tests::Fixture::new();
            let frame = fixture.call(Execution::Shell {
                shell: "/bin/sh".into(),
                text: if heartbeat {
                    "printf ready; exec /usr/bin/sleep 3".into()
                } else {
                    "printf ready; exec /usr/bin/sleep 30".into()
                },
            });
            let digest = canonical_digest(&frame).unwrap();
            let call = WorkspaceCall {
                frame,
                handle: digest[..16].to_owned(),
            };
            let (mut input, mut output, mut child) = process_fixture(&fixture.identity);
            crate::workspace_node::write_frame(&mut input, call.frame()).unwrap();
            crate::workspace_node::write_frame(&mut input, &json!({"schema":1,"type":"start"}))
                .unwrap();
            let ack = crate::workspace_node::read_frame(&mut output).unwrap();
            let build = call.acknowledge(&ack).unwrap();
            let ready = crate::workspace_node::read_frame(&mut output).unwrap();
            assert_eq!(ready["type"], "stdout");
            let finished = Arc::new(AtomicBool::new(false));
            let writer = if heartbeat {
                let finished = Arc::clone(&finished);
                Some(thread::spawn(move || {
                    while !finished.load(std::sync::atomic::Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(100));
                        if crate::workspace_node::write_frame(
                            &mut input,
                            &json!({"schema":1,"type":"heartbeat"}),
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                }))
            } else {
                None
            };
            let terminal = crate::workspace_node::read_frame(&mut output).unwrap();
            finished.store(true, std::sync::atomic::Ordering::Release);
            if let Some(writer) = writer {
                writer.join().unwrap();
            }
            let result = WorkspaceResult::from_terminal(&call, terminal, build).unwrap();
            assert_eq!(
                result.ending,
                if heartbeat {
                    Ending::Complete
                } else {
                    Ending::Interrupted("heartbeat-silence")
                }
            );
            assert!(child.0.wait().unwrap().success());
        }
    }

    /// ´test:unit:workspace-adapter-names-missing-entry-without-a-frame´
    #[test]
    fn workspace_adapter_names_missing_entry_without_a_frame() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exit 127")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let error = run_command(
            &call,
            command,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .err()
        .expect("absent entry");
        assert_eq!(error.kind, "door-compute-tool-refusal");
        assert!(error.detail.contains("install superloop-lane-node-exec"));
    }

    /// ´test:unit:workspace-adapter-stalled-route-cannot-outlive-its-call´
    #[test]
    fn workspace_adapter_stalled_route_cannot_outlive_its_call() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec /usr/bin/sleep 30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let error = run_command(
            &call,
            command,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_millis(100),
        )
        .err()
        .expect("stalled route");
        assert_eq!(error.kind, "door-workspace-protocol-refusal");
    }

    /// ´test:unit:workspace-adapter-maps-node-reasons-without-reply-reason-passthrough´
    #[test]
    fn workspace_adapter_maps_node_reasons_without_reply_reason_passthrough() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        for (reason, incomplete, ending) in [
            ("node-deadline", false, Ending::NodeDeadline),
            ("node-deadline", true, Ending::NodeDeadline),
            ("node-output-limit", false, Ending::OutputLimit),
            ("node-output-incomplete", true, Ending::OutputIncomplete),
        ] {
            let terminal = json!({"schema":1,"type":"terminal",
                "request_id":call.frame.request_id,"nonce":call.frame.nonce,
                "result":{"outcome":{"kind":"TimedOut"},"wall_seconds":0.0,
                    "user_cpu_seconds":null,"system_cpu_seconds":null},
                "steps":[],"output_bytes":0,"reason":reason,
                "output_incomplete":incomplete});
            let result = WorkspaceResult::from_terminal(
                &call,
                terminal,
                BuildEvidence {
                    entry_version: "0.0.0".into(),
                    differs: true,
                },
            )
            .unwrap();
            assert_eq!(result.ending, ending);
            assert_eq!(result.node_reason, reason);
            assert_eq!(result.evidence()["output_incomplete"], incomplete);
        }
    }
}
