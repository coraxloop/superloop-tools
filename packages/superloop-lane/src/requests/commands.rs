//! Owner commands for reading and resolving door requests.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::store::{ReadFailure, Store};
use super::{Mode, modes::ModeTarget};
use crate::error::LaneError;

#[path = "channel_commands.rs"]
mod collection;

const MAX_BATCH_BYTES: usize = 65_536;
const WAIT_POLL: Duration = Duration::from_millis(200);
const WAIT_READ_BACKOFF_MULTIPLE: u32 = 2;
#[cfg(test)]
type WaitPause = Box<dyn FnOnce(Duration)>;

#[cfg(test)]
thread_local! {
    pub(super) static WAIT_TEST_HOLD: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    pub(super) static WAIT_TEST_PAUSE: std::cell::RefCell<Option<WaitPause>> = const { std::cell::RefCell::new(None) };
}
const WAIT_DEFAULT_SECONDS: u64 = 60;
const WAIT_MAX_SECONDS: u64 = 600;

pub const REQUESTS_USAGE: &str = "publish-snapshot LOOP|provision-registry LOOP [--state-root DIR] [--dry-run]|rewrite LOOP {--dry-run|--expect-digest HEX}|rebuild-index LOOP|status LOOP [--pending]|list LOOP [--pending] [--state waiting|observed|marked|adjudicated]|wait LOOP [--state waiting|observed|marked|adjudicated] [--run RUN] [--timeout SECONDS (default 60, maximum 600; 200 ms minimum pause, twice shared-hold wall after slow reads; timeout exits 1 and names lock contention if unread; other record refusals exit 2)]|triage LOOP [RUN (compatibility array)] (stdin cap 65,536 bytes; about 100 typical 600-byte label lines)|review LOOP REQUEST_ID|adjudicate LOOP (JSON on stdin)|modes LOOP|set-mode LOOP {loop MODE|class CLASS MODE} SETTER EVIDENCE [REQUEST_ID ...]|correct-mode LOOP CLASS REQUEST_ID SETTER";

fn usage() -> LaneError {
    LaneError::input(
        "requests-usage",
        format!(
            "requests {{{REQUESTS_USAGE}}}; triage and adjudicate read schema-one JSON documents from stdin"
        ),
    )
}

fn stamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos())
        .to_string()
}

fn emit(output: &mut impl io::Write, value: &Value) -> Result<(), LaneError> {
    writeln!(output, "{value}").map_err(|error| LaneError::operation("stdout", error.to_string()))
}

fn list_response(
    loop_name: &str,
    requests: &[super::RequestRecord],
    stale: bool,
) -> Result<Value, LaneError> {
    let decisions = requests
        .iter()
        .map(|row| -> Result<Value, LaneError> {
            Ok(
                json!({"id":row.id(),"verdict":super::command::retained_decision(row.value())?,
                "outcome":super::command::retained_outcome(row.value())?}),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"schema":2,"loop":loop_name,"shape_record":if stale {"stale"} else {"current"},
        "decisions":decisions,
        "requests":requests.iter().map(super::RequestRecord::value).collect::<Vec<_>>(),
        "referrals":requests.iter().filter(|row| row.value()["agent_verdict"] == "refer").map(|row|
            json!({"id":row.id(),"target":if row.value()["agent_scope"] == "estate" {"estate"} else {loop_name},
                "reason":row.value()["agent_reason"],"status":row.value()["agent_status"]})).collect::<Vec<_>>()}),
    )
}

fn wait_options(args: &[String]) -> Result<(&str, Option<&str>, Duration), LaneError> {
    let (mut state, mut run, mut timeout) = ("waiting", None, WAIT_DEFAULT_SECONDS);
    let (mut seen_state, mut seen_run, mut seen_timeout) = (false, false, false);
    let (pairs, remainder) = args.as_chunks::<2>();
    for pair in pairs {
        match (pair[0].as_str(), pair[1].as_str()) {
            ("--state", word)
                if !seen_state
                    && matches!(word, "waiting" | "observed" | "marked" | "adjudicated") =>
            {
                state = word;
                seen_state = true;
            }
            ("--run", word) if !seen_run && crate::valid_run_name(word) => {
                run = Some(word);
                seen_run = true;
            }
            ("--timeout", word) if !seen_timeout => {
                timeout = word.parse().map_err(|_| usage())?;
                if timeout > WAIT_MAX_SECONDS {
                    return Err(usage());
                }
                seen_timeout = true;
            }
            _ => return Err(usage()),
        }
    }
    if !remainder.is_empty() {
        return Err(usage());
    }
    Ok((state, run, Duration::from_secs(timeout)))
}

fn run_wait(
    owner_home: &Path,
    loop_name: &str,
    args: &[String],
    output: &mut impl io::Write,
) -> Result<(), LaneError> {
    let (state, run, timeout) = wait_options(args)?;
    let deadline = Instant::now() + timeout;
    let store = Store::open(owner_home, loop_name, false)?.with_reader_deadline(deadline);
    let mut completed_reads = 0_usize;
    let mut last_contention = String::new();
    loop {
        let read = (|| -> Result<_, ReadFailure> {
            if let Some(run) = run {
                let (rows, hold) = store.list_run_for_wait(run)?;
                if rows.iter().any(|request| request.value()["state"] == state) {
                    let (all, _, shape_stale, second_hold) = store.list_with_status_for_wait()?;
                    Ok((all, shape_stale, hold.saturating_add(second_hold)))
                } else {
                    Ok((rows, false, hold))
                }
            } else {
                let (rows, _, shape_stale, hold) = store.list_with_status_for_wait()?;
                Ok((rows, shape_stale, hold))
            }
        })();
        let mut read_wall = Duration::ZERO;
        match read {
            Ok((requests, shape_stale, hold)) => {
                read_wall = hold;
                completed_reads += 1;
                let matching = requests
                    .into_iter()
                    .filter(|request| {
                        request.value()["state"] == state
                            && run.is_none_or(|run| request.value()["run"] == run)
                    })
                    .collect::<Vec<_>>();
                if !matching.is_empty() {
                    return emit(output, &list_response(loop_name, &matching, shape_stale)?);
                }
            }
            Err(error) if error.is_contention() => {
                last_contention = error.into_error().detail;
            }
            Err(error) => return Err(error.into_error()),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(LaneError::operation(
                "requests-wait-timeout",
                if completed_reads == 0 {
                    format!("no read completed before timeout: {last_contention}")
                } else {
                    format!("no {state} requests before timeout")
                },
            ));
        }
        // A completed read occupies at most one third of its cadence, leaving
        // a writer a gap even when two loop-wide readers run out of phase.
        #[cfg(test)]
        let read_wall = WAIT_TEST_HOLD.with(|hold| hold.get().unwrap_or(read_wall));
        let pause = WAIT_POLL.max(read_wall.saturating_mul(WAIT_READ_BACKOFF_MULTIPLE));
        #[cfg(test)]
        if WAIT_TEST_PAUSE.with(|hook| {
            hook.borrow_mut().take().is_some_and(|action| {
                action(pause);
                true
            })
        }) {
            continue;
        }
        std::thread::sleep(pause.min(deadline - now));
    }
}

/// Execute one owner-facing request command.
///
/// # Errors
///
/// Refuses malformed arguments, a malformed batch, or a changed protected record.
#[allow(clippy::too_many_lines)]
pub fn run(
    owner_home: &Path,
    args: &[String],
    input: &mut impl io::Read,
    output: &mut impl io::Write,
) -> Result<(), LaneError> {
    if args.first().is_some_and(|action| {
        matches!(
            action.as_str(),
            "status" | "list" | "triage" | "review" | "adjudicate"
        )
    }) {
        return collection::run(owner_home, args, input, output);
    }
    match args {
        [action, loop_name, rest @ ..] if action == "provision-registry" => {
            let (state, dry) = match rest {
                [] => (None, false),
                [flag] if flag == "--dry-run" => (None, true),
                [flag, path] if flag == "--state-root" => (Some(Path::new(path)), false),
                [flag, path, dry] if flag == "--state-root" && dry == "--dry-run" => {
                    (Some(Path::new(path)), true)
                }
                _ => return Err(usage()),
            };
            emit(
                output,
                &super::provision::run(owner_home, loop_name, state, dry)?,
            )
        }
        [action, loop_name, flag] if action == "rewrite" && flag == "--dry-run" => {
            let config = owner_home.join(".config/loops").join(loop_name);
            let _configuration = crate::install::lock_loop_config(&config, false)?;
            emit(
                output,
                &Store::open(owner_home, loop_name, false)?.rewrite(None)?,
            )
        }
        [action, loop_name, flag, digest] if action == "rewrite" && flag == "--expect-digest" => {
            let config = owner_home.join(".config/loops").join(loop_name);
            let _configuration = crate::install::lock_loop_config(&config, false)?;
            let settings = crate::settings::Settings::read(&config.join("workers.toml"))?;
            let socket = settings.socket_dir.ok_or_else(|| {
                LaneError::input("requests-rewrite-idle", "socket directory absent")
            })?;
            let door = crate::home::pin_parent(
                &socket.join("door"),
                nix::unistd::Uid::effective().as_raw(),
            )?;
            let _stopped = nix::fcntl::Flock::lock(
                std::fs::File::from(door),
                nix::fcntl::FlockArg::LockExclusiveNonblock,
            )
            .map_err(|(_, error)| {
                LaneError::input(
                    "requests-rewrite-idle",
                    format!("stop the door service: {error}"),
                )
            })?;
            emit(
                output,
                &Store::open(owner_home, loop_name, true)?.rewrite(Some(digest))?,
            )
        }
        [action, loop_name] if action == "publish-snapshot" => emit(
            output,
            &Store::open_for_snapshot(owner_home, loop_name)?.publish_snapshot()?,
        ),
        [action, loop_name] if action == "rebuild-index" => emit(
            output,
            &Store::open(owner_home, loop_name, true)?.rebuild_index()?,
        ),
        [action, loop_name, rest @ ..] if action == "wait" => {
            run_wait(owner_home, loop_name, rest, output)
        }
        [action, loop_name] if action == "modes" => {
            let store = Store::open(owner_home, loop_name, false)?;
            emit(output, &store.modes()?)
        }
        [action, loop_name, rest @ ..] if action == "set-mode" => {
            run_set_mode(owner_home, loop_name, rest, output)
        }
        [action, loop_name, class, id, setter] if action == "correct-mode" => {
            let store = Store::open(owner_home, loop_name, true)?;
            emit(output, &store.correct_mode(class, id, setter, &stamp())?)
        }
        _ => Err(usage()),
    }
}

fn run_set_mode(
    owner_home: &Path,
    loop_name: &str,
    args: &[String],
    output: &mut impl io::Write,
) -> Result<(), LaneError> {
    let (target, mode, setter, evidence, citations) = match args {
        [scope, mode, setter, evidence, citations @ ..] if scope == "loop" => {
            (ModeTarget::Loop, mode, setter, evidence, citations)
        }
        [scope, class, mode, setter, evidence, citations @ ..] if scope == "class" => {
            (ModeTarget::class(class)?, mode, setter, evidence, citations)
        }
        _ => return Err(usage()),
    };
    let mode = Mode::parse(mode)
        .ok_or_else(|| LaneError::input("door-mode-setting-refusal", "mode is invalid"))?;
    let store = Store::open(owner_home, loop_name, true)?;
    emit(
        output,
        &store.set_mode(&target, mode, setter, evidence, &stamp(), citations)?,
    )
}
