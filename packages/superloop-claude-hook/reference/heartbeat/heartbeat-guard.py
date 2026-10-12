#!/usr/bin/env python3
"""Stop-hook heartbeat guard for superloop sessions.

Design (the owner, 2026-08-21/22): the agent never arms ScheduleWakeup
unprompted - it works, replies in text, and tries to end its turn.
This hook then checks whether a wakeup is CURRENTLY pending. If none
is and the per-project heartbeat toggle is ON, the stop is blocked
with a prompt to arm (or to run `heartbeat off` = blocked-on-user).
The agent arms at the prompt and the turn ends naturally on the arm's
own result - correct, because the reply text already exists.

Armed-state detection is fully structural - no result-text parsing:
scan the transcript backwards for the most recent completed
ScheduleWakeup call and decide from its INPUT and the entry
timestamps: `stop: true` disarms; otherwise the wakeup is pending iff
result_timestamp + clamp(delaySeconds) + slack is still in the
future. Timestamps are the transcript's own UTC stamps, so there is
no midnight or timezone arithmetic. The scan ends at the first entry
older than the maximum possible pending window.

There is deliberately NO silent-turn text check (removed 2026-08-21,
the owner's ruling): the silent-turn failure mode required an
unprompted trailing arm, which this protocol abolishes.

The guard is a state machine (the owner's rulings 2026-08-22). Each
stop evaluation resolves to exactly one state, each state to exactly
one verdict. The regular states:

    OFF        toggle off - the stop-heartbeat exit; allow, no read
    FAIL_OPEN  guard cannot judge (bad stdin, unreadable transcript);
               allow - a broken guard must never wedge a session
    ARMED      a wakeup is pending and was legitimately armed (at a
               guard prompt, or in a previous turn); allow
    PROMPT     unarmed, block cap not drained, no violation; BLOCK -
               this is the prompt, and it has exactly three
               out-paths: the agent re-arms ScheduleWakeup (-> ARMED
               next evaluation), stops the heartbeat (`heartbeat off`
               -> OFF), or anything else, which drains the cap into
               the lapse exceptions below.

The EXCEPTION FAMILY enumerates the violation configurations - the
cross product of the unprompted-arm violation with the machine's
armed/unarmed/lapsed configuration:

    EXCEPTION_UNPROMPTED_ARMED
               an unprompted arm was made this turn and is still
               pending. Block ONCE with the violation as the reason
               (agent-visible); the armed pulse passes the next stop.
    EXCEPTION_UNPROMPTED_UNARMED
               an unprompted arm was made this turn but is no longer
               pending. Block; the violation is prepended to the
               block reason so the agent reads it with the protocol.
    EXCEPTION_LAPSE
               prompted, neither legal exit taken (cap drained);
               allow so the session never wedges, + `systemMessage`
               lapse alarm to the user.
    EXCEPTION_UNPROMPTED_LAPSE
               the lapse with the arm also
               unprompted; allow + both messages to the user (the one
               corner where the violation cannot block).

The violation notice fires once per user turn, always to the AGENT
via a block reason except in the lapse corner (user ruling
2026-08-22: agent-visible, not user-visible). The
blocked-on-user exit and legitimate at any point. The violation
`systemMessage` fires once per user turn; the block/allow verdict of
the state always applies.

EVERY EXCEPTION STATE HAS A RESOLUTION PATH (the owner's ruling
2026-08-22) - none is absorbing. The violation, warning marker, and
block cap are all scoped to the user turn, while armed-ness persists
across turns, so:

    EXCEPTION_UNPROMPTED_ARMED   resolves at the turn boundary: next
        turn the same pending wakeup is a previous turn's arm ->
        ARMED (the rogue arm is ratified); or the agent cancels it
        (`stop: true`) into the unarmed family.
    EXCEPTION_UNPROMPTED_UNARMED blocks, so it inherits the prompt's
        three out-paths: re-arm -> EXCEPTION_UNPROMPTED_ARMED (->
        ARMED next turn); `heartbeat off` -> OFF; anything else ->
        EXCEPTION_UNPROMPTED_LAPSE.
    EXCEPTION_LAPSE and EXCEPTION_UNPROMPTED_LAPSE resolve at the
        next user turn: the cap and violation reset with the turn
        marker, so the next stop evaluation re-enters PROMPT and the
        pulse can be restored.

Safety posture: fail open everywhere (a broken guard must never wedge
a session); at most MAX_BLOCKS_PER_TURN blocks per user turn; one
short grace retry absorbs transcript flush races.

Docs and path audit: heartbeat-guard.md next to this file.
Tests: heartbeat-guard-test.py next to this file (run with python3).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time

# The ScheduleWakeup runtime clamps delaySeconds to this range.
MIN_DELAY_SECONDS = 60
MAX_DELAY_SECONDS = 3600
# The scheduler rounds firing up to a minute boundary (observed:
# requested 1800 -> "in 1853s"), so allow this much overshoot before
# calling a wakeup expired.
SCHEDULE_SLACK_SECONDS = 120
# No arm older than this can still be pending; ends the backward scan.
SEARCH_HORIZON_SECONDS = MAX_DELAY_SECONDS + SCHEDULE_SLACK_SECONDS
MAX_BLOCKS_PER_TURN = 3
GRACE_RETRY_SECONDS = 1.0
STATE_DIR = os.path.expanduser("~/.local/state/superloop-tools/hook")
FEEDBACK_PREFIX = "Stop hook feedback:"

BLOCK_REASON = (
    "HEARTBEAT GUARD: no wakeup is currently armed and the heartbeat "
    "toggle is ON. Please set the ScheduleWakeup now (the turn then ends "
    "naturally on its result), or - if this turn genuinely ends blocked "
    "on the user with nothing in flight - run "
    "`~/.claude/hooks/heartbeat off` first, then end the turn."
)

UNPROMPTED_MESSAGE = (
    "HEARTBEAT GUARD EXCEPTION (unprompted arm): ScheduleWakeup was "
    "armed UNPROMPTED this turn (before any guard block). Protocol: "
    "never arm unprompted - work, reply in text, and arm only when "
    "this hook prompts (or run `heartbeat off` when genuinely blocked "
    "on the user)."
)

LAPSE_MESSAGE = (
    "HEARTBEAT GUARD EXCEPTION (lapse): the guard prompted {} times "
    "this turn and the agent took neither legal exit (re-arm "
    "ScheduleWakeup / stop the heartbeat). The stop is allowed and the "
    "heartbeat has LAPSED - no wakeup is armed.".format(
        MAX_BLOCKS_PER_TURN
    )
)

# States of the machine. Each stop evaluation resolves to exactly one.
# Transition contract (the owner, 2026-08-22): a PROMPT has exactly
# three out-paths - the agent re-arms ScheduleWakeup (next evaluation
# lands in ARMED), stops the heartbeat (`heartbeat off` -> OFF), or
# anything else, which drains the block cap into a lapse exception.
# The exception family enumerates the violation configurations.
STATE_OFF = "OFF"  # toggle off: the stop-heartbeat exit; nothing enforced
STATE_FAIL_OPEN = "FAIL_OPEN"  # guard cannot judge: never wedge a session
STATE_ARMED = "ARMED"  # legitimately armed pulse: allow silently
STATE_PROMPT = "PROMPT"  # unarmed, no violation: block = the prompt
STATE_EXC_UNPROMPTED_ARMED = "EXCEPTION_UNPROMPTED_ARMED"
STATE_EXC_UNPROMPTED_UNARMED = "EXCEPTION_UNPROMPTED_UNARMED"
STATE_EXC_LAPSE = "EXCEPTION_LAPSE"
STATE_EXC_UNPROMPTED_LAPSE = "EXCEPTION_UNPROMPTED_LAPSE"


def toggle_path(cwd: str) -> str:
    """Flag-file path for a project's heartbeat toggle (mirrors the
    `heartbeat` shell script: $PWD with '/' folded to '-')."""
    return os.path.join(STATE_DIR, "heartbeat" + cwd.replace("/", "-"))


def load_entries(path: str) -> list[dict]:
    """Parse a transcript JSONL; unparsable lines are skipped."""
    entries: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
    return entries


def entry_timestamp(entry: dict) -> dt.datetime | None:
    """The entry's own UTC timestamp, or None if absent/unparsable."""
    raw = entry.get("timestamp")
    if not isinstance(raw, str):
        return None
    if not raw.endswith("Z"):
        offset = re.search(r"[+-].*$", raw[10:])
        found = f"offset {offset.group()}" if offset else "naive"
        if len(raw) >= 19:
            print(f"heartbeat timestamp refused: {found}; expected an explicit UTC instant ending in Z", file=sys.stderr)
        return None
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", raw):
        return None
    try:
        stamp = dt.datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError:
        return None
    return stamp


def message_content(entry: dict) -> list:
    content = (entry.get("message") or {}).get("content")
    return content if isinstance(content, list) else []


def is_real_user_turn(entry: dict) -> bool:
    """A user entry that is an actual conversational turn.

    Tool results and this hook's own "Stop hook feedback:" injections
    do not count - otherwise every block would reset the turn marker
    and defeat the loop cap (observed live 2026-08-21).
    """
    if entry.get("type") != "user" or entry.get("isSidechain"):
        return False
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, list):
        return not any(
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in content
        )
    return isinstance(content, str) and not content.startswith(FEEDBACK_PREFIX)


def heartbeat_armed(entries: list[dict], now: dt.datetime) -> bool:
    """Whether a ScheduleWakeup wakeup is still pending at `now`.

    Backward scan. Verdict comes from the most recent ScheduleWakeup
    call that COMPLETED successfully (has a non-error tool result):
    `stop: true` -> disarmed; an arm -> pending iff
    result_time + clamp(delaySeconds) + slack > now. Calls without a
    result, failed calls, and malformed delays are no evidence and the
    scan continues. Any entry older than the search horizon ends the
    scan: nothing beyond it can still be pending.
    """
    results: dict[str, tuple[bool, dt.datetime | None]] = {}
    for entry in reversed(entries):
        if entry.get("isSidechain"):
            continue
        stamp = entry_timestamp(entry)
        if (
            stamp is not None
            and (now - stamp).total_seconds() > SEARCH_HORIZON_SECONDS
        ):
            return False
        entry_type = entry.get("type")
        if entry_type == "user":
            for block in message_content(entry):
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    results[block.get("tool_use_id")] = (
                        not block.get("is_error"),
                        stamp,
                    )
        elif entry_type == "assistant":
            for block in reversed(message_content(entry)):
                if (
                    not isinstance(block, dict)
                    or block.get("type") != "tool_use"
                    or block.get("name") != "ScheduleWakeup"
                ):
                    continue
                completed = results.get(block.get("id"))
                if completed is None or not completed[0]:
                    continue  # in-flight or failed call: no evidence
                params = block.get("input") or {}
                if params.get("stop"):
                    return False  # explicit disarm is the latest word
                try:
                    delay = float(params.get("delaySeconds"))
                except (TypeError, ValueError):
                    continue  # malformed arm: no evidence
                delay = min(max(delay, MIN_DELAY_SECONDS), MAX_DELAY_SECONDS)
                scheduled_at = completed[1] or stamp
                if scheduled_at is None:
                    continue  # no timestamp anywhere: no evidence
                fire = scheduled_at + dt.timedelta(
                    seconds=delay + SCHEDULE_SLACK_SECONDS
                )
                return now < fire
    return False


def is_guard_feedback(entry: dict) -> bool:
    """A user entry carrying this guard's own block feedback."""
    if entry.get("type") != "user" or entry.get("isSidechain"):
        return False
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, str):
        return content.startswith(FEEDBACK_PREFIX)
    if isinstance(content, list):
        return any(
            isinstance(b, dict)
            and b.get("type") == "text"
            and isinstance(b.get("text"), str)
            and b["text"].startswith(FEEDBACK_PREFIX)
            for b in content
        )
    return False


def unprompted_arm_in_turn(entries: list[dict]) -> bool:
    """Whether the current user turn contains an UNPROMPTED arm.

    An arm is prompted only if it follows this guard's own block
    feedback within the same user turn - that is the protocol's sole
    arming trigger. Any successful non-stop ScheduleWakeup call that
    precedes the first feedback entry (or when none exists) violates
    it. `stop: true` disarms are exempt: cancelling is the mandated
    blocked-on-user exit. Calls without a successful result are no
    evidence, matching the armed-scan's discipline.
    """
    start = last_user_turn_index(entries)
    turn = entries[start + 1 :] if start is not None else entries
    ok_results = set()
    for entry in turn:
        if entry.get("isSidechain") or entry.get("type") != "user":
            continue
        for block in message_content(entry):
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_result"
                and not block.get("is_error")
            ):
                ok_results.add(block.get("tool_use_id"))
    prompted = False
    for entry in turn:
        if entry.get("isSidechain"):
            continue
        if is_guard_feedback(entry):
            prompted = True
            continue
        if entry.get("type") != "assistant" or prompted:
            continue
        for block in message_content(entry):
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("name") == "ScheduleWakeup"
                and not (block.get("input") or {}).get("stop")
                and block.get("id") in ok_results
            ):
                return True
    return False


def last_user_turn_index(entries: list[dict]) -> int | None:
    index = None
    for i, entry in enumerate(entries):
        if is_real_user_turn(entry):
            index = i
    return index


def blocks_so_far(session: str, marker: str) -> int:
    """How many times this user turn has already been blocked."""
    try:
        with open(
            os.path.join(STATE_DIR, "guard-count-" + session), encoding="utf-8"
        ) as fh:
            prev_marker, prev_count = fh.read().split()
        return int(prev_count) if prev_marker == marker else 0
    except (OSError, ValueError):
        return 0


def record_block(session: str, marker: str, count: int) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(
            os.path.join(STATE_DIR, "guard-count-" + session),
            "w",
            encoding="utf-8",
        ) as fh:
            fh.write("{} {}".format(marker, count))
    except OSError:
        pass  # unpersisted count only risks extra blocks, never a wedge


def warned_already(session: str, marker: str) -> bool:
    """Whether this user turn's unprompted-arm warning already fired."""
    try:
        with open(
            os.path.join(STATE_DIR, "guard-warn-" + session), encoding="utf-8"
        ) as fh:
            return fh.read().strip() == marker
    except OSError:
        return False


def record_warning(session: str, marker: str) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(
            os.path.join(STATE_DIR, "guard-warn-" + session),
            "w",
            encoding="utf-8",
        ) as fh:
            fh.write(marker)
    except OSError:
        pass  # unpersisted marker only risks a repeated warning


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return  # STATE_FAIL_OPEN
    if not isinstance(payload, dict):
        return  # STATE_FAIL_OPEN

    cwd = payload.get("cwd") or ""
    if not os.path.exists(toggle_path(cwd)):
        return  # STATE_OFF: the stop-heartbeat exit; nothing to enforce

    transcript = payload.get("transcript_path") or ""
    session = payload.get("session_id") or "unknown"
    try:
        entries = load_entries(transcript)
        armed = heartbeat_armed(entries, dt.datetime.now(dt.timezone.utc))
        # The flush race exists in exactly one place: after this hook
        # blocks, the agent arms at the prompt and the very next stop
        # evaluation may read the transcript before that arm's entries
        # hit disk (observed live 2026-08-21). stop_hook_active marks
        # those post-block evaluations. On a first evaluation the
        # protocol guarantees no fresh arm exists (arming is never
        # unprompted), so no grace is needed and the block is instant.
        if not armed and payload.get("stop_hook_active"):
            time.sleep(GRACE_RETRY_SECONDS)
            entries = load_entries(transcript)
            armed = heartbeat_armed(entries, dt.datetime.now(dt.timezone.utc))
    except OSError:
        return  # STATE_FAIL_OPEN

    # -- state resolution: violation x configuration ---------------------
    marker = str(last_user_turn_index(entries))
    count = blocks_so_far(session, marker)
    violated = unprompted_arm_in_turn(entries)
    if armed:
        state = STATE_EXC_UNPROMPTED_ARMED if violated else STATE_ARMED
    elif count < MAX_BLOCKS_PER_TURN:
        state = STATE_EXC_UNPROMPTED_UNARMED if violated else STATE_PROMPT
    else:
        state = STATE_EXC_UNPROMPTED_LAPSE if violated else STATE_EXC_LAPSE

    # -- one verdict per state -------------------------------------------
    # The violation systemMessage fires once per user turn; the state's
    # block/allow verdict always applies.
    # Violation notices are delivered to the AGENT via block reasons
    # (user ruling 2026-08-22) - systemMessage reaches only the user
    # and cannot correct behavior. systemMessage now carries only the
    # lapse alarm (a human-facing "agent unresponsive" signal) and, in
    # the lapse corner where blocking is forbidden, the violation too.
    messages = []
    first_warning = violated and not warned_already(session, marker)
    if first_warning:
        record_warning(session, marker)

    verdict: dict = {}
    if state in (STATE_PROMPT, STATE_EXC_UNPROMPTED_UNARMED):
        record_block(session, marker, count + 1)
        reason = BLOCK_REASON
        if first_warning:
            reason = UNPROMPTED_MESSAGE + "\n\n" + reason
        verdict = {"decision": "block", "reason": reason}
    elif state == STATE_EXC_UNPROMPTED_ARMED and first_warning:
        # Teach once, agent-visible: block with the violation as the
        # reason. The pulse is armed, so the very next stop resolves
        # to STATE_EXC_UNPROMPTED_ARMED already-warned and allows.
        verdict = {"decision": "block", "reason": UNPROMPTED_MESSAGE}
    elif state in (STATE_EXC_LAPSE, STATE_EXC_UNPROMPTED_LAPSE):
        messages.append(LAPSE_MESSAGE)  # anti-wedge allow; alarm the user
        if first_warning:
            messages.append(UNPROMPTED_MESSAGE)  # cannot block here
    # STATE_ARMED allows silently; STATE_EXC_UNPROMPTED_ARMED with the
    # warning already delivered allows silently.

    if messages:
        verdict["systemMessage"] = "\n".join(messages)
    if verdict:
        print(json.dumps(verdict))


if __name__ == "__main__":
    main()
