## Integration test matrix · `tab:claudelane:integration-test-matrix`

**Table (Integration test matrix)**

|Test|Area|Claim|
|----|----|-----|
|(`test:integration:claude-fresh-step-records-utc-start`)|Subprocess|A fresh Claude step records its UTC start.|
|(`test:integration:a-fresh-claude-run-records-its-thread-id`)|Subprocess|A fresh Claude run records the session id carried by its init event.|
|(`test:integration:claude-fresh-launch-uses-lane-runs-root-and-reports-its-directory`)|Subprocess|The override allocates and reports the selected run directory, while invalid values retain the usage envelope.|
|(`test:integration:two-claude-fresh-launches-in-one-second-own-separate-runs`)|Subprocess|Two fresh launches under the pinned UTC stamp own separate evidence.|
|(`test:integration:usage-error-diagnostic-uses-claude-lane-prefix`)|Subprocess|The usage error diagnostic uses the Claude lane prefix.|
|(`test:integration:fresh-workspace-write-has-exact-argv-and-result`)|Subprocess|Fresh workspace write has exact arguments and result.|
|(`test:integration:empty-result-recovers-assistant-text`)|Subprocess|An empty result recovers assistant text.|
|(`test:integration:a-host-suspend-leaves-the-child-alive-and-names-its-gap`)|Subprocess|A host suspend leaves the child alive and names its gap.|
|(`test:integration:a-silent-resume-step-publishes-no-message-of-its-own`)|Subprocess|A silent resume step publishes no message of its own.|
|(`test:integration:a-failed-message-write-names-its-path-and-error`)|Subprocess|A failed message write names its path and error.|
|(`test:integration:a-rejected-dispatch-reports-rate-limited-with-its-reset-time`)|Subprocess|A rejected dispatch reports rate limited with its reset time.|
|(`test:integration:a-recorded-warning-refuses-the-next-dispatch-until-the-window-resets`)|Subprocess|A recorded warning refuses the next dispatch until the window resets.|
|(`test:integration:a-reset-window-dispatches-and-rewrites-the-pool-state`)|Subprocess|A reset window dispatches and rewrites the pool state.|
|(`test:integration:a-refused-resume-names-its-run-directory`)|Subprocess|A refused resume names its run directory.|
|(`test:integration:a-prior-steps-rejection-leaves-a-natural-failure-failed`)|Subprocess|A prior step rejection leaves a natural failure failed.|
|(`test:integration:resume-has-exact-argv-and-refuses-thread-mismatch`)|Subprocess|Resume has exact arguments and refuses a thread mismatch.|
|(`test:integration:a-claude-resume-fills-a-missing-thread-id`)|Subprocess|A Claude resume records the matched event id when the run has no id file.|
|(`test:integration:a-claude-resume-tolerates-an-unwritable-thread-id-path`)|Subprocess|A Claude resume proceeds when the thread-id path cannot be written, rather than refusing as a mismatch.|
|(`test:integration:a-claude-resume-refuses-a-conflicting-thread-id-file`)|Subprocess|A Claude resume refuses an id file that disagrees with its matched events.|
|(`test:integration:missing-report-resume-refusal-uses-claude-lane-prefix`)|Subprocess|The missing report resume refusal uses the Claude lane prefix.|
|(`test:integration:crash-recovery-diagnostic-uses-claude-lane-prefix`)|Subprocess|The crash recovery diagnostic uses the Claude lane prefix.|
|(`test:integration:an-interrupted-finish-is-reconstructed-at-the-next-resume`)|Subprocess|An interrupted finish is reconstructed at the next resume.|
|(`test:integration:an-errored-terminal-result-reconstructs-as-exit-one`)|Subprocess|An errored terminal result reconstructs as exit one.|
|(`test:integration:a-terminal-result-before-the-step-start-is-not-reconstructed`)|Subprocess|A terminal result before the step start is not reconstructed.|
|(`test:integration:a-stale-reconstruction-record-is-cleared-by-a-crash-report`)|Subprocess|A stale reconstruction record is cleared by a crash report.|
|(`test:integration:a-settled-report-survives-a-dead-lock`)|Subprocess|A settled report survives a dead lock.|
|(`test:integration:a-kill-inside-the-preparation-window-restores-the-prior-step`)|Subprocess|A kill inside the preparation window restores the prior step.|
|(`test:integration:an-unfinished-preparation-without-a-lock-restores-the-prior-step`)|Subprocess|An unfinished preparation without a lock restores the prior step.|
|(`test:integration:a-kill-after-the-sidecar-removal-keeps-the-prior-steps-answer`)|Subprocess|A kill after sidecar removal keeps the prior step answer.|
|(`test:integration:a-claude-rollback-removes-a-start-with-no-archived-marker`)|Subprocess|A Claude rollback removes a flipped start when the prior archive has none.|
|(`test:integration:an-untimed-terminal-result-reconstructs-at-wall-zero`)|Subprocess|An untimed terminal result reconstructs at wall zero.|
|(`test:integration:a-live-lock-holder-refuses-the-resume-without-reconstructing`)|Subprocess|A live lock holder refuses resume without reconstructing.|
|(`test:integration:a-trailing-non-result-event-keeps-the-crashed-report`)|Subprocess|A trailing event without a result keeps the crashed report.|
|(`test:integration:synthetic-clocks-publish-stall-and-runaway-without-killing`)|Subprocess|Synthetic clocks publish stall and runaway without killing.|
|(`test:integration:gateway-credit-affects-the-published-growth-state`)|Subprocess|Gateway credit affects the published growth state.|
|(`test:integration:a-finished-turn-can-idle-past-budget-and-exit-naturally`)|Subprocess|A finished turn can idle past budget and exit naturally.|
|(`test:integration:a-driver-asked-to-stop-takes-its-child-with-it`)|Subprocess|A driver asked to stop takes its child with it.|
|(`test:integration:a-lock-whose-child-is-alive-refuses-recovery`)|Subprocess|A lock whose child is alive refuses recovery.|
|(`test:integration:stdin-prompt-bytes-are-exact`)|Subprocess|The stdin prompt bytes are exact.|
|(`test:integration:permission-mode-mappings-are-exact`)|Subprocess|The permission mode mappings are exact.|
|(`test:integration:environment-scrubs-markers-and-keeps-config-directory`)|Subprocess|The environment scrubs markers and keeps the config directory.|
|(`test:integration:pure-mode-constructs-and-refuses-contaminated-homes`)|Subprocess|Pure mode constructs and refuses contaminated homes.|
