# `superloop-run-report` · `guide:runreport:superloop-run-report`

`superloop-run-report` executes one child command and appends the server-first run report used by worker-lane gates. Child standard output and standard error pass through unchanged before the wrapper-owned report line.

## Command line and mounts · `sec:runreport:command-line-and-mounts`

```text
superloop-run-report COMMAND [ARG]...
```

A sole `--version` emits the wrapper's JSON version record on standard error, leaves standard output empty and exits zero, or one if emission fails. It launches no child and appends no terminal report. Every other argument vector belongs to the child command. Mount configuration uses environment variables: `RUN_REPORT_ROOTFS_TMP_MOUNT` defaults to `/tmp`, and `RUN_REPORT_WORKSPACE_MOUNT` defaults to `/workspace`. An absent, unreadable, or otherwise unreportable mount yields `n/a` for that availability field and never prevents the child from running or the final report from being attempted.

## Report contract · `sec:runreport:report-contract`

The wrapper appends exactly one line to standard error after the child finishes:

```text
RUN-REPORT exit=STATUS wall=SECONDSs rootfs_tmp_left=AVAILABLE workspace_left=AVAILABLE
```

Availability uses the deployed script's `df -h --output=avail` representation. Wall duration has one decimal place and comes from Linux's suspend-inclusive boottime exposed by `/proc/uptime`, so server suspend while the child runs remains part of `wall=`. The monotonic process clock is used only as an explicit fallback if the Linux boottime source cannot be read; the instance registry names the supported environments.

## Exit behavior · `sec:runreport:exit-behavior`

An ordinary child exit is passed through unchanged, including status 1 and 2. Following the workspace `superloop-execwrap` foundation, signal death is represented honestly as `128 + signal`; for example, `SIGTERM` produces report status and wrapper status 143. A missing executable has no child status and returns the conventional spawn status 127, while other spawn failures return 126. An empty command is wrapper usage status 2, and an otherwise unclassifiable wrapper setup failure is status 125. Every one of these paths attempts the same terminal report line.

`superloop-execwrap` is used only for child launch, stream relay, wait, and signal normalization. Its routing features remain disabled, which preserves the deployed wrapper's direct child streams and avoids duplicating the workspace's subprocess semantics.

The complete command surface is `--version` or `COMMAND [ARG]...`. This package remains a separate tier 2 consumer of `superloop-execwrap`; its executable is available in the build tree. Installing the gate submitter does not replace any configured server wrapper.
