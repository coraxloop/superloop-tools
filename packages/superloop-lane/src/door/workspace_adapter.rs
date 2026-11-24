//! Door half of the protocol-one workspace executor call. No serving caller selects it yet.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ChildStderr, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use execute_command::workspace::{Measurement, Outcome, canonical_digest};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::workspace_executor::StartFailure;
use crate::workspace_node::NodeCall;
use crate::workspace_node::{read_frame_before, write_frame_before};

use super::transport::AuthenticatedNode;
use super::workspace::WorkspaceIntent;
use super::{WorkspaceAllowance, WorkspaceRequest};

fn refusal(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

/// An authenticated route name and the exact owner-held request, before SSH.
pub(super) struct WorkspaceCall {
    frame: NodeCall,
    handle: String,
}

/// One already custodied authority to execute this exact request.
#[derive(Clone, Copy)]
pub(super) enum WorkspaceAdmission<'a> {
    Allowance(&'a WorkspaceAllowance),
    AllowModeIntent(&'a WorkspaceIntent),
}

impl WorkspaceAdmission<'_> {
    fn check(&self, request: &WorkspaceRequest, id: &str) -> Result<(), LaneError> {
        match self {
            Self::Allowance(allowance) => allowance.check(request),
            Self::AllowModeIntent(intent) => intent.check(request, id),
        }
    }
}

impl WorkspaceCall {
    /// Compose one call only after checking its owner-held admission.
    /// # Errors
    /// Refuses a changed grant, missing placement, invalid id or unavailable randomness.
    pub(crate) fn compose(
        request: &WorkspaceRequest,
        admission: WorkspaceAdmission<'_>,
        node: &AuthenticatedNode,
        request_id: &str,
    ) -> Result<Self, LaneError> {
        admission.check(request, request_id)?;
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
    NothingRan(&'static str),
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
    pub(crate) child_started: Option<bool>,
    pub(crate) start_failure: Option<StartFailure>,
    pub(crate) build: BuildEvidence,
    pub(crate) door_cause: Option<&'static str>,
}

/// Distinct child streams, never combined with route diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OutputChannel {
    Stdout,
    Stderr,
}

/// The serving caller owns bounded forwarding to its worker.
pub(super) trait WorkspaceOutputSink {
    /// Forward one already counted chunk before the request lifetime.
    /// # Errors
    /// Names a failed or timed-out worker write.
    fn forward(
        &mut self,
        channel: OutputChannel,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), LaneError>;
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
    #[serde(default)]
    child_started: Option<bool>,
    #[serde(default)]
    start_failure: Option<StartFailure>,
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
            "node-start-failed" if terminal.start_failure.is_some() => {
                if terminal.child_started == Some(false) {
                    Ending::NothingRan("start-failed")
                } else {
                    Ending::Interrupted("start-failed")
                }
            }
            _ => {
                return Err(refusal(
                    "door-workspace-protocol-refusal",
                    "node terminal reason differs",
                ));
            }
        };
        if terminal.child_started == Some(false)
            && terminal.start_failure.is_none()
            && (!terminal.steps.is_empty() || terminal.output_bytes != 0)
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node reports output or steps without a started child",
            ));
        }
        let ending = if terminal.child_started == Some(false) {
            match ending {
                Ending::Interrupted(cause) => Ending::NothingRan(cause),
                Ending::NodeDeadline => Ending::NothingRan("node-command-deadline"),
                other => other,
            }
        } else {
            ending
        };
        if terminal.child_started == Some(false)
            && matches!(
                ending,
                Ending::Complete | Ending::OutputLimit | Ending::OutputIncomplete
            )
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node ending differs from observed child start",
            ));
        }
        if matches!(ending, Ending::Complete) && terminal.result.outcome == Outcome::Unknown {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "completed node call has no outcome",
            ));
        }
        let result = Self {
            ending,
            node_reason: terminal.reason,
            result: terminal.result,
            steps: terminal.steps,
            output_bytes: terminal.output_bytes,
            output_incomplete: terminal.output_incomplete,
            child_started: terminal.child_started,
            start_failure: terminal.start_failure,
            build,
            door_cause: None,
        };
        let evidence = result.evidence();
        if !crate::requests::workspace_node_result_matches(&evidence, &evidence["ending"])
            || !crate::requests::workspace_start_failure_matches(
                &evidence,
                &call.frame.envelope["execution"],
            )
        {
            return Err(refusal(
                "door-workspace-protocol-refusal",
                "node terminal differs from record-readable result",
            ));
        }
        Ok(result)
    }

    pub(crate) fn evidence(&self) -> Value {
        let (state, cause) = match &self.ending {
            Ending::Complete => ("completed", None),
            Ending::NodeDeadline => ("interrupted", Some("node-command-deadline")),
            Ending::Interrupted(cause) => ("interrupted", Some(*cause)),
            Ending::NothingRan(cause) => ("not-started", Some(*cause)),
            Ending::OutputLimit => ("refused", Some("output-limit")),
            Ending::OutputIncomplete => ("incomplete", Some("held-output")),
            Ending::Incomplete => ("unknown", Some("route-incomplete")),
        };
        json!({"node_reason":self.node_reason,"entry_version":self.build.entry_version,
            "entry_version_differs":self.build.differs,"output_incomplete":self.output_incomplete,
            "output_bytes":self.output_bytes,"result":self.result,"steps":self.steps,
            "child_started":self.child_started,
            "start_failure":self.start_failure,
            "ending":state,"cause":cause,"door_cause":self.door_cause})
    }

    /// A shell-style status for a failed start, separate from door refusals.
    pub(crate) fn command_status(&self) -> Option<i32> {
        self.start_failure
            .as_ref()
            .map(|failure| failure.kind.status())
    }
}

/// Exercise the real adapter mapping from the record reader's fixture table.
#[cfg(test)]
pub fn fixture_terminal_evidence(frame: Value) -> Result<Value, LaneError> {
    fixture_terminal_result(frame, &json!({"kind":"Argv","words":[[99]]}))
        .map(|result| result.evidence())
}

#[cfg(test)]
pub fn fixture_failed_start(
    frame: Value,
    execution: &Value,
) -> Result<(Value, Option<i32>), LaneError> {
    fixture_terminal_result(frame, execution)
        .map(|result| (result.evidence(), result.command_status()))
}

#[cfg(test)]
fn fixture_terminal_result(frame: Value, execution: &Value) -> Result<WorkspaceResult, LaneError> {
    let call = WorkspaceCall {
        frame: NodeCall {
            protocol: 1,
            request_id: "R:1a".to_owned(),
            nonce: "fixture".to_owned(),
            node: "fixture-node".to_owned(),
            grant: Value::Null,
            placement: Value::Null,
            envelope: json!({"execution":execution}),
        },
        handle: String::new(),
    };
    let build = BuildEvidence {
        entry_version: "0.11.0".to_owned(),
        differs: false,
    };
    WorkspaceResult::from_terminal(&call, frame, build)
}

/// ´test:unit:workspace-quiet-stop-needs-positive-no-start-evidence´
#[cfg(test)]
#[test]
fn workspace_quiet_stop_needs_positive_no_start_evidence() {
    let frame = json!({"schema":1,"type":"terminal","request_id":"R:1a",
        "nonce":"fixture","result":{"outcome":{"kind":"Exited","code":0},
            "wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null},
        "steps":[],"output_bytes":0,"reason":"node-stopped",
        "output_incomplete":false,"child_started":true});
    let running = fixture_terminal_evidence(frame.clone()).unwrap();
    assert_eq!(running["ending"], "interrupted");
    let mut old = frame.clone();
    old.as_object_mut().unwrap().remove("child_started");
    let unknown_start = fixture_terminal_evidence(old).unwrap();
    assert_eq!(unknown_start["ending"], "interrupted");
    assert!(unknown_start["child_started"].is_null());
    let mut before_start = frame;
    before_start["child_started"] = json!(false);
    assert_eq!(
        fixture_terminal_evidence(before_start).unwrap()["ending"],
        "not-started"
    );
}

fn io_refusal(error: &io::Error) -> LaneError {
    refusal("door-workspace-protocol-refusal", error.to_string())
}

const START_BOUND: Duration = Duration::from_secs(5);
const ACK_BOUND: Duration = Duration::from_secs(30);
const FIRST_FRAME_EXIT_BOUND: Duration = Duration::from_secs(5);
const STOP_TERMINAL_BOUND: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const NODE_DRAIN_AND_WRITE: Duration = Duration::from_secs(240);
const FINAL_BOUND: Duration = Duration::from_secs(5);

/// The door's own reason for setting the stop flag, retained beside node cause.
#[derive(Clone, Copy)]
pub(super) struct WorkspaceStop<'a> {
    pub(crate) flag: &'a AtomicBool,
    pub(crate) cause: &'static str,
}

#[derive(Clone, Copy)]
struct DriverBounds {
    lifetime: Instant,
    acknowledgement: Duration,
    heartbeat_interval: Duration,
    output_limit: usize,
}

struct ChildGuard(Child);

fn first_frame_exit_deadline(lifetime: Instant, now: Instant) -> Instant {
    lifetime.min(now + FIRST_FRAME_EXIT_BOUND)
}

#[cfg(test)]
thread_local! {
    static LAST_ROUTE_GROUP: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let group = nix::unistd::Pid::from_raw(self.0.id().cast_signed());
        let _killed = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        let _reaped = self.0.wait();
    }
}

/// Drain route diagnostics without retaining their text or letting a full pipe
/// block the route. The worker-visible result contains no route stderr.
struct RouteStderrGuard {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RouteStderrGuard {
    #[allow(unsafe_code)]
    fn new(mut stderr: ChildStderr) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut bytes = [0_u8; 8192];
            loop {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                let mut poll = libc::pollfd {
                    fd: stderr.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                };
                // SAFETY: this thread owns stderr until poll returns.
                let ready = unsafe { libc::poll(&raw mut poll, 1, 100) };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if ready > 0 {
                    match stderr.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for RouteStderrGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

enum Control {
    Stop,
    Finish,
}

struct WriterGuard {
    control: mpsc::Sender<Control>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}

impl WriterGuard {
    fn stop(&self) {
        let _sent = self.control.send(Control::Stop);
    }
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        let _sent = self.control.send(Control::Finish);
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

/// Run one already composed call over a route process. The host route supplies
/// only a fixed remote program; all request bytes travel in the bounded frame.
/// # Errors
/// Refuses a crossed frame, route fault or output above the door's own ceiling.
pub(super) fn run_command(
    call: &WorkspaceCall,
    mut command: Command,
    sink: &mut impl WorkspaceOutputSink,
    stop: WorkspaceStop<'_>,
    lifetime: Instant,
) -> Result<WorkspaceResult, LaneError> {
    command.process_group(0);
    let mut child = ChildGuard(
        command
            .spawn()
            .map_err(|error| refusal("door-compute-tool-refusal", error.to_string()))?,
    );
    #[cfg(test)]
    LAST_ROUTE_GROUP.set(child.0.id().cast_signed());
    let _route_stderr = child.0.stderr.take().map(RouteStderrGuard::new);
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
    let mut first_frame_seen = false;
    let answer = run_stream(
        call,
        input,
        &mut output,
        sink,
        stop,
        DriverBounds {
            lifetime,
            acknowledgement: ACK_BOUND,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            output_limit: crate::workspace_node::MAX_OUTPUT_BYTES,
        },
        &mut first_frame_seen,
    );
    if answer.is_err() && !first_frame_seen {
        let exit_bound = first_frame_exit_deadline(lifetime, Instant::now());
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
            if Instant::now() >= exit_bound {
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
    sink: &mut impl WorkspaceOutputSink,
    stop: WorkspaceStop<'_>,
    bounds: DriverBounds,
    first_frame_seen: &mut bool,
) -> Result<WorkspaceResult, LaneError> {
    write_frame_before(&input, call.frame(), Instant::now() + START_BOUND)
        .map_err(|error| io_refusal(&error))?;
    let first = read_frame_before(
        output,
        bounds.lifetime.min(Instant::now() + bounds.acknowledgement),
        stop.flag,
    )
    .map_err(|error| io_refusal(&error))?;
    *first_frame_seen = true;
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
            match control_rx.recv_timeout(bounds.heartbeat_interval) {
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
    let mut writer = Some(WriterGuard {
        control: control_tx,
        thread: Some(writer),
    });
    let started = started_rx.recv_timeout(START_BOUND).map_err(|error| {
        refusal(
            "door-workspace-protocol-refusal",
            format!("start was not sent: {error}"),
        )
    })?;
    if let Some(error) = started {
        let no_stop = AtomicBool::new(false);
        if let Ok(frame) = read_frame_before(
            output,
            bounds.lifetime.min(Instant::now() + START_BOUND),
            &no_stop,
        ) && frame["type"] == "terminal"
        {
            return WorkspaceResult::from_terminal(call, frame, build);
        }
        return Err(refusal("door-workspace-protocol-refusal", error));
    }
    let terminal_deadline = bounds.lifetime.min(
        Instant::now()
            + Duration::from_millis(call.frame.envelope["deadline_ms"].as_u64().unwrap_or(0))
            + NODE_DRAIN_AND_WRITE
            + FINAL_BOUND,
    );
    let mut forwarded = 0_usize;
    let mut sent_stop = false;
    let mut stop_deadline = None;
    let mut frame_fault = None;
    let never_stop = AtomicBool::new(false);
    let terminal = loop {
        let check_stop = if sent_stop { &never_stop } else { stop.flag };
        let frame = match read_frame_before(
            output,
            stop_deadline.unwrap_or(terminal_deadline),
            check_stop,
        ) {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && !sent_stop => {
                if let Some(writer) = writer.take() {
                    writer.stop();
                    drop(writer);
                }
                sent_stop = true;
                stop_deadline = Some(terminal_deadline.min(Instant::now() + STOP_TERMINAL_BOUND));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                frame_fault = Some("node output frame is malformed");
                break None;
            }
            Err(_) => {
                if !sent_stop && let Some(writer) = &writer {
                    writer.stop();
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
                if forwarded > bounds.output_limit {
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
                let channel = if frame["type"] == "stdout" {
                    OutputChannel::Stdout
                } else {
                    OutputChannel::Stderr
                };
                sink.forward(channel, &bytes, bounds.lifetime)?;
            }
            _ => {
                frame_fault = Some("node frame kind differs");
                break None;
            }
        }
    };
    drop(writer);
    if let Some(detail) = frame_fault {
        return Err(refusal("door-workspace-protocol-refusal", detail));
    }
    let Some(terminal) = terminal else {
        if forwarded > bounds.output_limit {
            return Err(refusal(
                "door-output-limit-refusal",
                "door output exceeded its forwarding ceiling",
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
            child_started: None,
            start_failure: None,
            build,
            door_cause: sent_stop.then_some(stop.cause),
        });
    };
    let mut result = WorkspaceResult::from_terminal(call, terminal, build)?;
    if result.output_bytes != forwarded {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "node output count differs from forwarded bytes",
        ));
    }
    if sent_stop {
        result.door_cause = Some(stop.cause);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use execute_command::workspace::Execution;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    #[derive(Default)]
    struct Collected {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }
    impl WorkspaceOutputSink for Collected {
        fn forward(
            &mut self,
            channel: OutputChannel,
            bytes: &[u8],
            _deadline: Instant,
        ) -> Result<(), LaneError> {
            match channel {
                OutputChannel::Stdout => self.stdout.extend_from_slice(bytes),
                OutputChannel::Stderr => self.stderr.extend_from_slice(bytes),
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum MockOutput {
        Ceiling,
        CountMismatch,
        Malformed,
        TerminalBeforeStart,
    }

    fn mock_output(case: MockOutput) -> (Result<WorkspaceResult, LaneError>, Collected) {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let (door_input, mut node_input) = UnixStream::pair().unwrap();
        let (mut node_output, mut door_output) = UnixStream::pair().unwrap();
        let ack = json!({"schema":1,"type":"ack","request_id":call.frame.request_id,
            "nonce":call.frame.nonce,"frame_handle":call.handle,
            "entry_version":env!("CARGO_PKG_VERSION")});
        let terminal = json!({"schema":1,"type":"terminal",
            "request_id":call.frame.request_id,"nonce":call.frame.nonce,
            "result":{"outcome":{"kind":"Exited","code":0},"wall_seconds":0.0,
                "user_cpu_seconds":null,"system_cpu_seconds":null},
            "steps":[{"outcome":{"kind":"Exited","code":0},"wall_seconds":0.0,
                "user_cpu_seconds":null,"system_cpu_seconds":null}],
            "output_bytes":1,"reason":"node-complete","output_incomplete":false});
        let node = thread::spawn(move || {
            let _call = crate::workspace_node::read_frame(&mut node_input).unwrap();
            if matches!(case, MockOutput::TerminalBeforeStart) {
                drop(node_input);
                crate::workspace_node::write_frame(&mut node_output, &ack).unwrap();
                let terminal = json!({"schema":1,"type":"terminal",
                    "request_id":ack["request_id"],"nonce":ack["nonce"],
                    "result":{"outcome":{"kind":"TimedOut"},"wall_seconds":0.0,
                        "user_cpu_seconds":null,"system_cpu_seconds":null},
                    "steps":[],"output_bytes":0,"reason":"node-stopped",
                    "output_incomplete":false,"child_started":false});
                crate::workspace_node::write_frame(&mut node_output, &terminal).unwrap();
                return;
            }
            crate::workspace_node::write_frame(&mut node_output, &ack).unwrap();
            let _start = crate::workspace_node::read_frame(&mut node_input).unwrap();
            let output = match case {
                MockOutput::Ceiling => json!({"schema":1,"type":"stdout","bytes":[1,2,3,4,5]}),
                MockOutput::CountMismatch => {
                    json!({"schema":1,"type":"stdout","bytes":[1,2]})
                }
                MockOutput::Malformed => json!({"schema":1,"type":"stdout","bytes":"bad"}),
                MockOutput::TerminalBeforeStart => unreachable!(),
            };
            crate::workspace_node::write_frame(&mut node_output, &output).unwrap();
            if matches!(case, MockOutput::CountMismatch) {
                crate::workspace_node::write_frame(&mut node_output, &terminal).unwrap();
            }
        });
        let mut collected = Collected::default();
        let answer = run_stream(
            &call,
            door_input,
            &mut door_output,
            &mut collected,
            WorkspaceStop {
                flag: &AtomicBool::new(false),
                cause: "fixture-stop",
            },
            DriverBounds {
                lifetime: Instant::now() + Duration::from_secs(5),
                acknowledgement: ACK_BOUND,
                heartbeat_interval: Duration::from_secs(1),
                output_limit: 4,
            },
            &mut false,
        );
        node.join().unwrap();
        (answer, collected)
    }

    /// ´test:unit:workspace-adapter-refuses-output-ceiling-count-and-frame´
    #[test]
    fn workspace_adapter_refuses_output_ceiling_count_and_frame() {
        for (case, kind) in [
            (MockOutput::Ceiling, "door-output-limit-refusal"),
            (MockOutput::CountMismatch, "door-workspace-protocol-refusal"),
            (MockOutput::Malformed, "door-workspace-protocol-refusal"),
        ] {
            let (answer, collected) = mock_output(case);
            assert_eq!(answer.err().unwrap().kind, kind);
            if matches!(case, MockOutput::Ceiling) {
                assert_eq!(collected.stdout, [] as [u8; 0]);
            }
        }
    }

    /// ´test:unit:workspace-adapter-terminal-precedes-closed-start-write´
    #[test]
    fn workspace_adapter_terminal_precedes_closed_start_write() {
        let (answer, collected) = mock_output(MockOutput::TerminalBeforeStart);
        let result = answer.expect("terminal frame wins over closed control channel");
        assert_eq!(result.ending, Ending::NothingRan("stop"));
        assert_eq!(collected.stdout, [] as [u8; 0]);
    }

    fn process_fixture(
        identity: &std::path::Path,
        silence: Duration,
    ) -> (UnixStream, UnixStream, ChildGuard) {
        process_fixture_with_start(identity, silence, Duration::from_secs(10))
    }

    #[allow(unsafe_code)]
    fn process_fixture_with_start(
        identity: &std::path::Path,
        silence: Duration,
        start_wait: Duration,
    ) -> (UnixStream, UnixStream, ChildGuard) {
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
            .env(
                "SUPERLOOP_NODE_PROCESS_SILENCE_MS",
                silence.as_millis().to_string(),
            )
            .env(
                "SUPERLOOP_NODE_PROCESS_START_MS",
                start_wait.as_millis().to_string(),
            )
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
        let (input, mut output, mut child) =
            process_fixture(&fixture.identity, Duration::from_secs(2));
        let mut collected = Collected::default();
        let result = run_stream(
            &call,
            input,
            &mut output,
            &mut collected,
            WorkspaceStop {
                flag: &AtomicBool::new(false),
                cause: "fixture-stop",
            },
            DriverBounds {
                lifetime: Instant::now() + Duration::from_secs(15),
                acknowledgement: ACK_BOUND,
                heartbeat_interval: Duration::from_millis(100),
                output_limit: crate::workspace_node::MAX_OUTPUT_BYTES,
            },
            &mut false,
        )
        .expect("node call");
        assert_eq!(result.ending, Ending::Complete);
        assert_eq!(collected.stdout, b"answer");
        assert_eq!(collected.stderr, b"warning");
        assert!(!result.build.differs);
        assert!(child.0.wait().expect("node exit").success());
    }

    /// ´test:unit:workspace-adapter-driver-sends-stop-after-stream-event´
    #[test]
    fn workspace_adapter_driver_sends_stop_after_stream_event() {
        struct StopOnOutput {
            seen: Vec<u8>,
            stop: Arc<AtomicBool>,
        }
        impl WorkspaceOutputSink for StopOnOutput {
            fn forward(
                &mut self,
                _channel: OutputChannel,
                bytes: &[u8],
                _deadline: Instant,
            ) -> Result<(), LaneError> {
                self.seen.extend_from_slice(bytes);
                self.stop.store(true, Ordering::Release);
                Ok(())
            }
        }
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
        let (input, mut output, mut child) =
            process_fixture(&fixture.identity, Duration::from_secs(10));
        let stop = Arc::new(AtomicBool::new(false));
        let mut sink = StopOnOutput {
            seen: Vec::new(),
            stop: Arc::clone(&stop),
        };
        let result = run_stream(
            &call,
            input,
            &mut output,
            &mut sink,
            WorkspaceStop {
                flag: &stop,
                cause: "worker-disconnected",
            },
            DriverBounds {
                lifetime: Instant::now() + Duration::from_secs(15),
                acknowledgement: ACK_BOUND,
                heartbeat_interval: Duration::from_millis(100),
                output_limit: crate::workspace_node::MAX_OUTPUT_BYTES,
            },
            &mut false,
        )
        .unwrap();
        assert_eq!(sink.seen, b"ready");
        assert_eq!(result.ending, Ending::Interrupted("stop"));
        assert_eq!(result.door_cause, Some("worker-disconnected"));
        assert_eq!(result.evidence()["door_cause"], "worker-disconnected");
        assert!(child.0.wait().unwrap().success());
    }

    /// ´test:unit:workspace-adapter-acknowledged-stop-closes-input-before-terminal´
    #[test]
    fn workspace_adapter_acknowledged_stop_closes_input_before_terminal() {
        struct StopOnChunk(Arc<AtomicBool>);
        impl WorkspaceOutputSink for StopOnChunk {
            fn forward(
                &mut self,
                _channel: OutputChannel,
                _bytes: &[u8],
                _deadline: Instant,
            ) -> Result<(), LaneError> {
                self.0.store(true, Ordering::Release);
                Ok(())
            }
        }
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let (door_input, mut node_input) = UnixStream::pair().unwrap();
        let (mut node_output, mut door_output) = UnixStream::pair().unwrap();
        node_input
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let ack = json!({"schema":1,"type":"ack","request_id":call.frame.request_id,
            "nonce":call.frame.nonce,"frame_handle":call.handle,
            "entry_version":env!("CARGO_PKG_VERSION")});
        let node = thread::spawn(move || {
            let _call = crate::workspace_node::read_frame(&mut node_input).unwrap();
            crate::workspace_node::write_frame(&mut node_output, &ack).unwrap();
            assert_eq!(
                crate::workspace_node::read_frame(&mut node_input).unwrap()["type"],
                "start"
            );
            crate::workspace_node::write_frame(
                &mut node_output,
                &json!({"schema":1,"type":"stdout","bytes":[1]}),
            )
            .unwrap();
            assert_eq!(
                crate::workspace_node::read_frame(&mut node_input).unwrap()["type"],
                "stop"
            );
            let mut byte = [0_u8; 1];
            assert_eq!(
                node_input.read(&mut byte).unwrap(),
                0,
                "input closes after stop"
            );
            crate::workspace_node::write_frame(
                &mut node_output,
                &json!({"schema":1,"type":"terminal","request_id":ack["request_id"],
                    "nonce":ack["nonce"],"result":{"outcome":{"kind":"Signalled","signal":15},
                    "wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null},
                    "steps":[],"output_bytes":1,"reason":"node-stopped",
                    "output_incomplete":false}),
            )
            .unwrap();
        });
        let stop = Arc::new(AtomicBool::new(false));
        let result = run_stream(
            &call,
            door_input,
            &mut door_output,
            &mut StopOnChunk(Arc::clone(&stop)),
            WorkspaceStop {
                flag: &stop,
                cause: "worker-disconnected",
            },
            DriverBounds {
                lifetime: Instant::now() + Duration::from_secs(60),
                acknowledgement: ACK_BOUND,
                heartbeat_interval: Duration::from_secs(30),
                output_limit: crate::workspace_node::MAX_OUTPUT_BYTES,
            },
            &mut false,
        )
        .unwrap();
        node.join().unwrap();
        assert_eq!(result.ending, Ending::Interrupted("stop"));
        assert_eq!(result.door_cause, Some("worker-disconnected"));
    }

    /// ´test:unit:workspace-adapter-first-frame-exit-wait-is-five-seconds´
    #[test]
    fn workspace_adapter_first_frame_exit_wait_is_five_seconds() {
        let now = Instant::now();
        assert_eq!(
            first_frame_exit_deadline(now + Duration::from_secs(60), now),
            now + Duration::from_secs(5)
        );
        assert_eq!(
            first_frame_exit_deadline(now + Duration::from_secs(2), now),
            now + Duration::from_secs(2)
        );
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
        let error = WorkspaceCall::compose(
            &request,
            WorkspaceAdmission::Allowance(&allowance),
            &foreign,
            "R:1",
        )
        .err()
        .expect("node mismatch");
        assert_eq!(error.kind, "door-workspace-context-differs");
        assert!(error.detail.contains("register-door-node --node"));
        let own = super::super::transport::fixture_node(&fixture.grant.node);
        let call = WorkspaceCall::compose(
            &request,
            WorkspaceAdmission::Allowance(&allowance),
            &own,
            "R:1",
        )
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
            let (mut input, mut output, mut child) = process_fixture_with_start(
                &fixture.identity,
                Duration::from_secs(2),
                Duration::from_secs(1),
            );
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
            assert_eq!(result.ending, Ending::NothingRan(cause));
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
            let (mut input, mut output, mut child) =
                process_fixture(&fixture.identity, Duration::from_secs(10));
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
            let (mut input, mut output, mut child) =
                process_fixture(&fixture.identity, Duration::from_secs(2));
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
            &mut Collected::default(),
            WorkspaceStop {
                flag: &AtomicBool::new(false),
                cause: "fixture-stop",
            },
            Instant::now() + Duration::from_secs(5),
        )
        .err()
        .expect("absent entry");
        assert_eq!(error.kind, "door-compute-tool-refusal");
        assert!(error.detail.contains("install superloop-lane-node-exec"));
    }

    /// ´test:unit:workspace-adapter-drains-route-diagnostics-before-missing-tool´
    #[test]
    fn workspace_adapter_drains_route_diagnostics_before_missing_tool() {
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
            .arg("head -c 131072 /dev/zero >&2; exit 127")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error = run_command(
            &call,
            command,
            &mut Collected::default(),
            WorkspaceStop {
                flag: &AtomicBool::new(false),
                cause: "fixture-stop",
            },
            Instant::now() + Duration::from_secs(5),
        )
        .err()
        .expect("absent entry after bounded stderr drain");
        assert_eq!(error.kind, "door-compute-tool-refusal");
    }

    /// ´test:unit:workspace-adapter-acknowledgement-has-a-driver-bound´
    #[test]
    fn workspace_adapter_acknowledgement_has_a_driver_bound() {
        let fixture = crate::workspace_node::tests::Fixture::new();
        let frame = fixture.call(Execution::Argv {
            words: vec![b"/bin/true".to_vec()],
        });
        let digest = canonical_digest(&frame).unwrap();
        let call = WorkspaceCall {
            frame,
            handle: digest[..16].to_owned(),
        };
        let (door_input, _node_input) = UnixStream::pair().unwrap();
        let (node_output, mut door_output) = UnixStream::pair().unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = run_stream(
                &call,
                door_input,
                &mut door_output,
                &mut Collected::default(),
                WorkspaceStop {
                    flag: &AtomicBool::new(false),
                    cause: "fixture-stop",
                },
                DriverBounds {
                    lifetime: Instant::now() + Duration::from_secs(60),
                    acknowledgement: Duration::from_millis(100),
                    heartbeat_interval: Duration::from_secs(30),
                    output_limit: crate::workspace_node::MAX_OUTPUT_BYTES,
                },
                &mut false,
            );
            sender.send(result.err().map(|error| error.kind)).unwrap();
        });
        let completed = receiver.recv_timeout(Duration::from_secs(5));
        if completed.is_err() {
            node_output.shutdown(std::net::Shutdown::Both).unwrap();
        }
        worker.join().unwrap();
        assert_eq!(
            completed.expect("driver bound ended stalled route"),
            Some("door-workspace-protocol-refusal")
        );
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
            &mut Collected::default(),
            WorkspaceStop {
                flag: &AtomicBool::new(false),
                cause: "fixture-stop",
            },
            Instant::now() + Duration::from_millis(100),
        )
        .err()
        .expect("stalled route");
        assert_eq!(error.kind, "door-workspace-protocol-refusal");
        let group = nix::unistd::Pid::from_raw(LAST_ROUTE_GROUP.get());
        assert_eq!(
            nix::sys::signal::killpg(group, None).unwrap_err(),
            nix::errno::Errno::ESRCH,
            "a stalled route must leave no child group"
        );
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
            (
                "node-input-closed",
                true,
                Ending::Interrupted("input-closed"),
            ),
            ("node-stopped", true, Ending::Interrupted("stop")),
            ("node-output-limit", false, Ending::OutputLimit),
            ("node-output-incomplete", true, Ending::OutputIncomplete),
        ] {
            let terminal = json!({"schema":1,"type":"terminal",
                "request_id":call.frame.request_id,"nonce":call.frame.nonce,
                "result":{"outcome":{"kind":"TimedOut"},"wall_seconds":0.0,
                    "user_cpu_seconds":null,"system_cpu_seconds":null},
                "steps":[{"outcome":{"kind":"TimedOut"},"wall_seconds":0.0,
                    "user_cpu_seconds":null,"system_cpu_seconds":null}],
                "output_bytes":0,"reason":reason,
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
