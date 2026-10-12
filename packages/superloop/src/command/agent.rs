//! Invoke the door's bounded profile directly under the entered loop identity.

use super::*;
use execute_command::request::Verdict;
use execute_command::snapshot::PolicySnapshot;
use execute_command::triage::{Profile, RunnerOutcome};
use nix::fcntl::{FcntlArg, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn failure(request: &Request, status: VerdictStatus, reason: &str) -> Result<Verdict, Error> {
    Ok(execute_command::triage::judge(
        request.binding(),
        Profile::DoorVerdict,
        &RunnerOutcome::Failure {
            status,
            reason: text(reason)?,
        },
        Scope::Loop,
    ))
}

fn drain(
    reader: &mut impl std::io::Read,
    target: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<()> {
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if target.len() + count > limit {
                    return Err(std::io::Error::other("agent output limit"));
                }
                target.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn rubric_text(policy: &PolicySnapshot) -> Result<String, Error> {
    let rubric = &policy.rubric.value;
    let bytes = if let Some(text) = rubric["text"].as_str() {
        text.as_bytes().to_vec()
    } else {
        let path = rubric["path"].as_str().ok_or_else(|| {
            Error::named("door-rubric-unavailable", "published rubric path is absent")
        })?;
        let root = open(
            Path::new("/"),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(Error::storage)?;
        let relative = Path::new(path).strip_prefix("/").map_err(Error::storage)?;
        let fd = nix::fcntl::openat2(
            &root,
            relative,
            nix::fcntl::OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
        .map_err(Error::storage)?;
        let file = File::from(fd);
        if !file.metadata().map_err(Error::storage)?.is_file() {
            return Err(Error::named(
                "door-rubric-unavailable",
                "published rubric is not a regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(Error::storage)?;
        bytes
    };
    if bytes.len() > 65_536 || rubric["sha256"] != execute_command::rubric::sha256_digest(&bytes) {
        return Err(Error::named(
            "door-rubric-unavailable",
            "published rubric changed; run superloop-lane requests publish-snapshot LOOP",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| Error::named("door-rubric-unavailable", "published rubric is not UTF-8"))
}

// Every transport error retains cleanup ownership until the profile has exited.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.0.id()) {
            let _terminated = killpg(Pid::from_raw(pid), Signal::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.0.try_wait().is_ok_and(|status| status.is_some()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

fn capture(child: Child, input: &[u8], budget: Duration) -> Result<Option<Vec<u8>>, Error> {
    let mut child = Reap(child);
    let started = Instant::now();
    let stdin = child
        .0
        .stdin
        .take()
        .ok_or_else(|| Error::storage("agent stdin absent"))?;
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| Error::storage("agent stdout absent"))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| Error::storage("agent stderr absent"))?;
    for descriptor in [&stdin as &dyn std::os::fd::AsFd, &stdout, &stderr] {
        fcntl(descriptor, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(Error::storage)?;
    }
    let (mut written, mut output, mut errors) = (0, Vec::new(), Vec::new());
    let mut input_pipe = Some(stdin);
    loop {
        if let Some(pipe) = &mut input_pipe {
            match pipe.write(&input[written..]) {
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    return Err(Error::named(
                        "door-agent-input",
                        "bounded profile input failed",
                    ));
                }
            }
            if written == input.len() {
                input_pipe = None;
            }
        }
        drain(&mut stdout, &mut output, 262_144)
            .and_then(|()| drain(&mut stderr, &mut errors, 4096))
            .map_err(|_| {
                Error::named("door-agent-output-limit", "bounded profile output failed")
            })?;
        if started.elapsed() >= budget {
            return Ok(None);
        }
        if child.0.try_wait().map_err(Error::storage)?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drain(&mut stdout, &mut output, 262_144)
        .map_err(|_| Error::named("door-agent-output-limit", "bounded profile output failed"))?;
    Ok(Some(output))
}

pub(super) fn judge(
    policy: &PolicySnapshot,
    request: &Request,
    class: &str,
    history: &Value,
) -> Result<Verdict, Error> {
    let started = Instant::now();
    let mut verdict = judge_profile(policy, request, class, history)?;
    let mut evidence: Vec<Text> = serde_json::from_value(
        serde_json::to_value(&verdict.evidence).map_err(|_| Error::shape())?,
    )
    .map_err(|_| Error::shape())?;
    for value in [
        format!(
            "rubric:{}",
            policy.rubric.value["sha256"].as_str().unwrap_or("absent")
        ),
        "observed-model:unknown".into(),
        format!("judgement-wall-ms:{}", started.elapsed().as_millis()),
    ] {
        let prefix = value.split_once(':').ok_or_else(Error::shape)?.0;
        if !evidence.iter().any(|item| {
            item.as_str()
                .split_once(':')
                .is_some_and(|(key, _)| key == prefix)
        }) {
            evidence.push(text(&value)?);
        }
    }
    verdict.evidence = evidence.try_into().map_err(|_| Error::shape())?;
    Ok(verdict)
}

fn judge_profile(
    policy: &PolicySnapshot,
    request: &Request,
    class: &str,
    history: &Value,
) -> Result<Verdict, Error> {
    let rubric = &policy.rubric.value;
    let config = &rubric["agent"];
    let Some(program) = config["executable"]
        .as_str()
        .filter(|program| Path::new(program).is_absolute())
    else {
        return failure(
            request,
            VerdictStatus::AgentFailure,
            "door-agent-unconfigured",
        );
    };
    let Some(model) = config["model"]
        .as_str()
        .filter(|model| !model.trim().is_empty())
    else {
        return failure(
            request,
            VerdictStatus::AgentFailure,
            "door-agent-unconfigured",
        );
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Error::storage)?;
    let remaining = Duration::from_millis(request.context().deadline_unix_ms).saturating_sub(now);
    let Some(budget) = execute_command::triage::budget(
        remaining,
        Duration::from_millis(config["cap_ms"].as_u64().unwrap_or(30_000).min(120_000)),
        Duration::from_secs(2),
    ) else {
        return failure(request, VerdictStatus::Timeout, "door-agent-no-budget");
    };
    let trusted_rubric = match rubric_text(policy) {
        Ok(text) => text,
        Err(error) => return failure(request, VerdictStatus::AgentFailure, &error.rule),
    };
    let input = execute_command::rubric::DoorInput {
        request: serde_json::to_value(request).map_err(|_| Error::shape())?,
        class: class.into(),
        shape_record: if history.is_null() {
            json!([])
        } else {
            history.clone()
        },
        rubric: trusted_rubric,
    }
    .encode()
    .map_err(|error| Error::named(error.0, "bounded agent input"))?;
    let started = Instant::now();
    let root = Path::new(
        policy.registry.value["root"]
            .as_str()
            .ok_or_else(Error::shape)?,
    );
    let child = Command::new("/usr/bin/python3")
        .env("HOME", root.join("private"))
        .env("TMPDIR", root.join("direct"))
        .args(["-I", "-c", loop_home::runner::DOOR_AGENT_PROGRAM])
        .arg(program)
        .arg(model)
        .arg(config["effort"].as_str().unwrap_or("medium"))
        .arg(budget.as_millis().to_string())
        .arg("snapshot-input")
        .arg((now + budget).as_secs_f64().to_string())
        .arg(&policy.loop_name)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(child) = child else {
        return failure(request, VerdictStatus::AgentFailure, "door-agent-call");
    };
    let output = match capture(child, &input, budget) {
        Ok(Some(output)) => output,
        Ok(None) => return failure(request, VerdictStatus::Timeout, "door-agent-timeout"),
        Err(error) => {
            return failure(
                request,
                if error.rule == "door-agent-output-limit" {
                    VerdictStatus::InvalidOutput
                } else {
                    VerdictStatus::AgentFailure
                },
                &error.rule,
            );
        }
    };
    verdict(request, rubric, &output, started.elapsed())
}

fn verdict(
    request: &Request,
    rubric: &Value,
    output: &[u8],
    wall: Duration,
) -> Result<Verdict, Error> {
    let envelope: Value = match serde_json::from_slice(output) {
        Ok(value) => value,
        Err(_) => return failure(request, VerdictStatus::InvalidOutput, "door-agent-envelope"),
    };
    if let Some(reason) = envelope["reason"].as_str() {
        let status = match envelope["service_status"].as_str() {
            Some("timeout") => VerdictStatus::Timeout,
            Some("invalid-output") => VerdictStatus::InvalidOutput,
            _ => VerdictStatus::AgentFailure,
        };
        return failure(request, status, reason);
    }
    if envelope["rubric_digest"] != rubric["sha256"] {
        return failure(
            request,
            VerdictStatus::InvalidOutput,
            "door-rubric-digest-mismatch",
        );
    }
    let Some(answer) = envelope["text"].as_str() else {
        return failure(request, VerdictStatus::InvalidOutput, "door-agent-envelope");
    };
    let mut verdict = execute_command::triage::judge(
        request.binding(),
        Profile::DoorVerdict,
        &RunnerOutcome::Output(answer.as_bytes().to_vec()),
        Scope::Loop,
    );
    let mut evidence: Vec<Text> = serde_json::from_value(
        serde_json::to_value(&verdict.evidence).map_err(|_| Error::shape())?,
    )
    .map_err(|_| Error::shape())?;
    evidence.extend([
        text(&format!(
            "rubric:{}",
            rubric["sha256"].as_str().unwrap_or_default()
        ))?,
        text(&format!(
            "observed-model:{}",
            envelope["model"].as_str().unwrap_or("unknown")
        ))?,
        text(&format!("judgement-wall-ms:{}", wall.as_millis()))?,
    ]);
    verdict.evidence = evidence.try_into().map_err(|_| Error::shape())?;
    Ok(verdict)
}
