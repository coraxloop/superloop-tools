# Ordinary inbox waiting · `guide:superloopclaudehook:ordinary-inbox-waiting`

At session start the loop starts or resumes its Sonnet inbox watcher independently of heartbeat and lane watchers. Stop a dead watcher before replacing it. Run the recipe below through the ordinary loop entry, with the loop inbox as the first argument and a bounded listing interval of 30 seconds as the second: `superloop enter LOOP -- /bin/bash -s -- HOST_LOOP_HOME/mail/inbox 30`. Supply the recipe on standard input. A worker uses its own `/mail/inbox` instead. The entry supplies the actor's identity and mailbox group.

The watcher hands back only `You've got mail.` and waits for the session to resume it. On that resume it runs the recipe again; a repeated notice is harmless. The session chooses whether to use ordinary `ls`, `cat` and `mv` to read or move a letter into `read`. A notice does not authorize a lane resume, provide sender authority, or create a HOLD/RELEASE queue. Journal verification remains required for steering.

The watch arms before the first listing. Every event, including overflow, triggers a fresh listing; directory replacement stops the old watch before rearming. When inotify is unavailable or refuses the directory, bounded ordinary listings supply the fallback. The recipe observes only directory presence and filesystem identity, never letter contents, subjects, sender lists, timestamps or counts. It keeps no delivery receipt and ignores read history.

A missing or unreadable inbox at start, or an unreadable one later, ends the recipe with status 3 and a stderr line, which the watcher hands back as a failure rather than as mail.

```bash
#!/bin/bash
# Ordinary filesystem waiting for a session-owned inbox watcher.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf '%s\n' 'usage: inbox-watch INBOX [WAIT_SECONDS]' >&2
    exit 2
fi
inbox=$1
if [ ! -d "$inbox" ] || [ ! -r "$inbox" ] || [ ! -x "$inbox" ]; then
    printf '%s\n' 'inbox-watch: inbox is missing or unreadable' >&2
    exit 3
fi
case "$inbox" in /*) ;; *) exit 2;; esac
interval=${2:-30}
case "$interval" in ''|*[!0-9]*|0) exit 2;; esac
if [ "$interval" -gt 60 ]; then exit 2; fi
scratch=$(mktemp -d)
child=
stop_watch() {
    if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
        child=
    fi
}
close_events() { if [ -n "${events-}" ]; then exec {events}>&-; unset events; fi; }
cleanup() { stop_watch; close_events; rm -rf -- "$scratch"; }
trap cleanup EXIT
trap 'exit 0' TERM INT HUP
notice() {
    if [ -e "$inbox" ] && { [ ! -r "$inbox" ] || [ ! -x "$inbox" ]; }; then
        printf '%s\n' 'inbox-watch: inbox is unreadable' >&2
        exit 3
    fi
    if [ "$(find "$inbox" -mindepth 1 -maxdepth 1 -printf x -quit 2>/dev/null)" = x ]; then
        printf '%s\n' "You've got mail."
        exit 0
    fi
}
identity() { stat -Lc '%d:%i' -- "$inbox" 2>/dev/null || true; }
while :; do
    armed=false
    candidate=$(identity)
    if command -v inotifywait >/dev/null 2>&1; then
        rm -f -- "$scratch/events"
        mkfifo "$scratch/events"
        exec {events}<>"$scratch/events"
        LC_ALL=C inotifywait -m --format '%e' -e create -e moved_to -e delete_self -e move_self -e unmount -- "$inbox" >&"$events" 2>"$scratch/ready" &
        child=$!
        for ((attempt=0; attempt<100; attempt++)); do
            if grep -Fq 'Watches established.' "$scratch/ready"; then armed=true; break; fi
            kill -0 "$child" 2>/dev/null || break
            sleep 0.02
        done
    fi
    if "$armed"; then
        watched=$candidate
        # The watch is armed before this first listing, closing the arrival gap.
        notice
        if [ "$(identity)" != "$watched" ]; then stop_watch; close_events; continue; fi
        while kill -0 "$child" 2>/dev/null; do
            IFS= read -r -t "$interval" event <&"$events" || true
            # Every event, including overflow, is only a hint to list again.
            notice
            [ "$(identity)" = "$watched" ] || break
        done
        stop_watch
        close_events
    else
        stop_watch
        close_events
        notice
        sleep "$interval"
    fi
    # Stop the old watch before arming its replacement; no delivery receipt persists.
done
```
