#!/bin/sh
set -eu

capture=${PERMISSION_TRIAGE_FAKE_CAPTURE:?}
response=${PERMISSION_TRIAGE_FAKE_RESPONSE:?}
scope=${PERMISSION_TRIAGE_FAKE_SCOPE:-estate}

printf '%s\000' "$@" > "${capture}.argv"
pwd -P > "${capture}.cwd"
printf '%s\n' "${PERMISSION_TRIAGE_NESTED-}" > "${capture}.nested"
printf '%s\n' "${PERMISSION_TRIAGE_TEST_SECRET-}" > "${capture}.secret"
printf '%s\n' "$$" > "${capture}.pid"

case "$response" in
    stdin-gate-deadline)
        sleep 2
        : > "${capture}.deadline"
        exit 0
        ;;
    never-read)
        : > "${capture}.stdin"
        sleep 10 >/dev/null 2>&1 &
        descendant=$!
        printf '%s\n' "$descendant" > "${capture}.child-pid"
        wait "$descendant"
        ;;
    never-read-direct)
        : > "${capture}.stdin"
        exec sleep 10
        ;;
    never-read-short-descendant)
        : > "${capture}.stdin"
        sleep 30 &
        descendant=$!
        printf '%s\n' "$descendant" > "${capture}.child-pid"
        wait "$descendant"
        ;;
    never-read-double-fork)
        : > "${capture}.stdin"
        if [ -x /usr/bin/setsid ]; then
            setsid_program=/usr/bin/setsid
        elif setsid_program=$(command -v setsid 2>/dev/null); then
            :
        else
            printf '%s\n' 'setsid is unavailable at /usr/bin/setsid and on PATH' > "${capture}.double-fork-skip"
            cat > "${capture}.stdin"
            printf '%s\n' '{"structured_output":{"scope":"estate","classification":"safe","reason":"double-fork fixture skipped"}}'
            exit 0
        fi
        "$setsid_program" -f sh -c 'printf "%s\n" "$$" > "$1"; exec sleep 30' sh "${capture}.child-pid"
        sleep 10 >/dev/null 2>&1
        ;;
    nested-probe)
        nested_hook=${PERMISSION_TRIAGE_FAKE_HOOK:?}
        printf '%s\n' '{"session_id":"nested-fixture","cwd":"/workspace/project","permission_mode":"manual","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf nested"},"tool_use_id":"nested-use"}' | exec "$nested_hook" hook > "${capture}.nested-output"
        ;;
esac

if [ "$response" = nested-probe-grandchild ]; then
    nested_hook=${PERMISSION_TRIAGE_FAKE_HOOK:?}
    cat > "${capture}.stdin"
    sh -c 'printf "%s\n" "$$" > "$3"; printf "%s\n" '\''{"session_id":"nested-fixture","cwd":"/workspace/project","permission_mode":"manual","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf nested"},"tool_use_id":"nested-use"}'\'' | "$1" hook > "$2" & printf "%s\n" "$!" > "$4"; wait' \
        sh "$nested_hook" "${capture}.nested-output" "${capture}.shell-pid" \
        "${capture}.nested-pid"
    printf '%s\n' '{"structured_output":{"scope":"estate","classification":"safe","reason":"grandchild fixture"}}'
    exit 0
fi

cat > "${capture}.stdin"

case "$response" in
    scope-fixture)
        printf '%s\n' "${PERMISSION_TRIAGE_FAKE_ENVELOPE:?}"
        ;;
    routine-general|routine-superloop|safe|advanced-read-only|agent-error|suspicious)
        printf '{"result":"{\\"scope\\":\\"%s\\",\\"classification\\":\\"%s\\",\\"reason\\":\\"fixture reason\\"}"}\n' "$scope" "$response"
        ;;
    suspicious-stderr)
        printf '%s\n' 'fake-cli-stderr-sentinel' >&2
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"suspicious","reason":"fixture reason"}}'
        ;;
    structured)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"safe","reason":"structured fixture reason"}}'
        ;;
    dual-field-safe)
        printf '%s\n' '{"result":"{\"reason\":\"The request is a single Bash `printf acceptance-probe`, which only emits a literal string to stdout. There is no redirect, mutation, credential access, remote contact, privileged path, or external side effect, and no owner rubric exists to make it an installation-specific routine action. Its effect is fully explicit and contained, so under the conservative tie-break between the bounded-effect classes it is `safe` rather than `routine-general`.\",\"scope\":\"estate\",\"classification\":\"safe\"}","structured_output":{"reason":"The request is a single Bash `printf acceptance-probe`, which only emits a literal string to stdout. There is no redirect, mutation, credential access, remote contact, privileged path, or external side effect, and no owner rubric exists to make it an installation-specific routine action. Its effect is fully explicit and contained, so under the conservative tie-break between the bounded-effect classes it is `safe` rather than `routine-general`.","scope":"estate","classification":"safe"}}'
        ;;
    trailing)
        printf '%s\n' '{"result":"{\"scope\":\"estate\",\"classification\":\"safe\",\"reason\":\"fixture reason\"}"} trailing'
        ;;
    nonzero)
        exit 17
        ;;
    oversized)
        printf '%s' '{"result":"'
        head -c 70000 /dev/zero | tr '\000' x
        printf '%s\n' '"}'
        ;;
    reaped-oversized)
        (
            sleep 0.05
            head -c 70000 /dev/zero | tr '\000' x
            sleep 30
        ) &
        descendant=$!
        printf '%s\n' "$descendant" > "${capture}.child-pid"
        exit 0
        ;;
    sleep)
        sleep 10 >/dev/null 2>&1
        ;;
    unknown)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"unknown","reason":"fixture reason"}}'
        ;;
    both-payloads)
        printf '%s\n' '{"result":"{\"scope\":\"estate\",\"classification\":\"safe\",\"reason\":\"fixture reason\"}","structured_output":{"scope":"estate","classification":"suspicious","reason":"fixture reason"}}'
        ;;
    dual-field-non-string-result)
        printf '%s\n' '{"result":{},"structured_output":{"scope":"estate","classification":"safe","reason":"fixture reason"}}'
        ;;
    dual-field-malformed-result)
        printf '%s\n' '{"result":"not JSON","structured_output":{"scope":"estate","classification":"safe","reason":"fixture reason"}}'
        ;;
    neither-payload)
        printf '%s\n' '{"type":"result"}'
        ;;
    malformed-result)
        printf '%s\n' '{"result":"not JSON"}'
        ;;
    command-reason)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"suspicious","reason":"triage-command-echo-sentinel"}}'
        ;;
    allow-command-reason)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"safe","reason":"triage-command-echo-sentinel"}}'
        ;;
    webfetch-url-reason)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"safe","reason":"https://example.invalid/private"}}'
        ;;
    write-path-reason)
        printf '%s\n' '{"structured_output":{"scope":"estate","classification":"suspicious","reason":"docs/private.txt"}}'
        ;;
    prompt-shaped)
        printf '%s\n' 'Permission required: allow Bash(printf fixture)? [y/n]'
        printf '%s\n' 'The harness raised a permission prompt instead of classifying.'
        ;;
    long-reason)
        printf '%s' '{"structured_output":{"scope":"estate","classification":"safe","reason":"'
        head -c 1000 /dev/zero | tr '\000' x
        printf '%s\n' '"}}'
        ;;
    *)
        exit 18
        ;;
esac
