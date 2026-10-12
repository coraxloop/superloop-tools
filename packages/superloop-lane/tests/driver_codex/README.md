## Integration test matrix · `tab:codexlane:integration-test-matrix`

**Table (Integration test matrix)**

|Test|Area|Claim|
|----|----|-----|
|(`test:integration:codex-fresh-step-records-utc-start`)|Subprocess|A fresh Codex step records its UTC start.|
|(`test:integration:a-fresh-codex-run-records-its-thread-id`)|Subprocess|A fresh Codex run records the thread id carried by its event stream.|
|(`test:integration:codex-fresh-launch-uses-lane-runs-root-and-reports-its-directory`)|Subprocess|The override allocates and reports the selected run directory, while invalid values retain the usage envelope.|
|(`test:integration:normal-completion-matches-shell-oracle`)|Subprocess|Normal completion matches the shell oracle.|
|(`test:integration:stdin-prompt-matches-shell-oracle-without-inventing-lf`)|Subprocess|The stdin prompt matches the shell oracle without an invented line feed.|
|(`test:integration:resume-matches-shell-invocation-and-preserves-step-history`)|Subprocess|Resume matches the shell invocation and preserves the prior step history.|
|(`test:integration:a-codex-resume-fills-a-missing-thread-id`)|Subprocess|A Codex resume records the matched event id when the run has no id file.|
|(`test:integration:a-codex-resume-tolerates-an-unwritable-thread-id-path`)|Subprocess|A Codex resume proceeds when the thread-id path cannot be written, rather than refusing as a mismatch.|
|(`test:integration:a-codex-rollback-removes-a-start-with-no-archived-marker`)|Subprocess|A Codex rollback removes a flipped start when the prior archive has none.|
|(`test:integration:fresh-follower-replays-from-zero-at-resume-boundary`)|Subprocess|A fresh capture invocation replays from zero at the resume boundary.|
|(`test:integration:empty-output-uses-last-nonempty-agent-message`)|Subprocess|Empty output uses the last nonempty agent message.|
|(`test:integration:growing-events-can-finish-over-budget-successfully`)|Subprocess|Growing events can finish successfully over budget.|
|(`test:integration:the-awake-clock-not-the-boot-clock-drives-step-budget`)|Subprocess|The awake clock drives the step budget.|
|(`test:integration:suspend-divergence-is-data-beside-the-earned-verdict`)|Subprocess|Suspend divergence is recorded beside the earned verdict.|
|(`test:integration:the-monitor-publishes-its-awake-accounting-in-the-run-directory`)|Subprocess|The monitor publishes awake accounting in the run directory.|
|(`test:integration:budget-expiry-leaves-codex-running-until-natural-completion`)|Subprocess|Budget expiry leaves Codex running until natural completion.|
|(`test:integration:an-approved-run-is-runaway-state-without-a-signal`)|Subprocess|An approved run is reported as runaway without a signal.|
|(`test:integration:an-audited-result-or-an-open-proposal-is-stalled-state`)|Subprocess|An audited result or open proposal is reported as stalled.|
|(`test:integration:runaway-is-a-live-state-without-a-signal`)|Subprocess|Runaway is a live state without a signal.|
|(`test:integration:a-finished-turn-can-idle-past-budget-and-exit-naturally`)|Subprocess|A finished turn can idle past budget and exit naturally.|
|(`test:integration:a-driver-asked-to-stop-takes-its-child-with-it`)|Subprocess|A driver asked to stop takes its child with it.|
|(`test:integration:a-lock-whose-child-is-alive-refuses-recovery`)|Subprocess|A lock whose child is alive refuses recovery.|
|(`test:integration:usage-error-matrix-returns-two-and-a-final-report`)|Subprocess|Usage errors return status two and a final report.|
|(`test:integration:retired-pure-resume-refuses-without-creating-home-or-starting-child`)|Subprocess|Retired pure mode refuses resumed steps without creating a home or starting a child.|
|(`test:integration:codex-start-and-resume-refuse-missing-home`)|Subprocess|Fresh and resumed host drivers refuse missing or empty CODEX_HOME before a vendor child starts.|
|(`test:integration:retired-pure-mode-refuses-without-creating-home-or-starting-child`)|Subprocess|Retired pure mode refuses without creating a home or starting a child.|
|(`test:integration:marker-publication-is-atomic`)|Subprocess|Marker publication is atomic.|
|(`test:integration:every-allocated-run-is-live-until-a-finished-marker-exists`)|Subprocess|Every allocated run is live until its finished marker exists.|
|(`test:integration:undeclared-child-status-is-mapped-to-shared-failure`)|Subprocess|An undeclared child status maps to the shared failure.|
|(`test:integration:two-codex-fresh-launches-in-one-second-own-separate-runs`)|Subprocess|Two fresh launches under the pinned UTC stamp own separate evidence.|
|(`test:integration:resume-refusal-names-missing-prior-report`)|Subprocess|A resume refusal names the missing prior report.|
|(`test:integration:resume-refusal-names-existing-step-input`)|Subprocess|A resume refusal names existing step input.|
|(`test:integration:resume-refusal-names-existing-step-history`)|Subprocess|A resume refusal names existing step history.|
|(`test:integration:resume-refusal-names-live-lock`)|Subprocess|A resume refusal names a live lock.|
|(`test:integration:resume-recovers-dead-pid-lock-and-archives-crash`)|Subprocess|Resume recovers a dead pid lock and archives the crash.|
|(`test:integration:resume-treats-recycled-pid-as-live`)|Subprocess|Resume treats a recycled pid as live.|
|(`test:integration:resume-refusal-names-missing-event-stream`)|Subprocess|A resume refusal names the missing event stream.|
|(`test:integration:resume-refusal-names-unreadable-event-stream`)|Subprocess|A resume refusal names the unreadable event stream.|
|(`test:integration:resume-refusal-names-thread-mismatch`)|Subprocess|A resume refusal names a thread mismatch.|
|(`test:integration:a-codex-resume-refuses-a-conflicting-thread-id-file`)|Subprocess|A Codex resume refuses an id file that disagrees with its matched events.|
|(`test:integration:custom-exec-flags-precede-resume-subcommand`)|Subprocess|Custom exec flags precede the resume subcommand.|
|(`test:integration:panic-before-argument-handling-is-suppressed-and-reported`)|Subprocess|A panic before argument handling is suppressed and reported.|
|(`test:integration:panic-after-argument-handling-is-suppressed-and-reported`)|Subprocess|A panic after argument handling is suppressed and reported.|
|(`test:integration:budget-is-only-a-reporting-threshold`)|Timing|Budget is only a reporting threshold.|
|(`test:integration:event-growth-resets-only-the-stall-basis`)|Timing|Event growth resets only the stall basis.|
|(`test:integration:an-awaited-run-resets-only-the-stall-basis`)|Timing|An awaited run resets only the stall basis.|
|(`test:integration:an-awaited-run-never-moves-the-runaway-bound`)|Timing|An awaited run never moves the runaway bound.|
|(`test:integration:the-stall-window-restarts-when-the-awaited-run-lands`)|Timing|The stall window restarts when an awaited run lands.|
|(`test:integration:stall-bounds-are-strict`)|Timing|Stall bounds are strict.|
|(`test:integration:runaway-bound-is-strict`)|Timing|The runaway bound is strict.|
|(`test:integration:stall-takes-priority-when-both-kill-bounds-cross`)|Timing|Stall takes priority when both kill bounds cross.|
|(`test:integration:a-monitor-stop-is-always-above-the-budget`)|Timing|A monitor stop is always above the budget.|
|(`test:integration:growth-decides-nothing-once-the-region-carries-a-result`)|Timing|Growth decides nothing once the region carries a result.|
|(`test:integration:boottime-elapsed-includes-suspend`)|Timing|Boot time elapsed includes suspend.|
|(`test:integration:suspend-divergence-threshold-is-strict`)|Timing|The suspend divergence threshold is strict.|
|(`test:integration:a-suspend-longer-than-the-stall-window-does-not-kill`)|Timing|A suspend longer than the stall window does not kill.|
|(`test:integration:boxed-codex-starts-without-host-home-and-retains-pool-record`)|Subprocess|A boxed driver starts without CODEX_HOME, uses the runtime child environment, and consults HOME/.codex/lane-pool.json.|
