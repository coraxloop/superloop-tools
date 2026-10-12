# `superloop-execwrap` · `guide:execwrap:execwrap`

`superloop-execwrap` runs a child process and routes its stdout and stderr to log files. It is the workspace's subprocess-execution wrapper: build steps that shell out to an external toolchain (notably the TeX pipeline) run through it so their output is captured deterministically instead of scrolling past.

The package is a library. Its callers own their argument parsing, control-plane output and exit policy; the package ships no command.

## Execution trust boundary · `sec:execwrap:execution-trust-boundary`

`superloop-execwrap` is **not a sandbox**. Read this before using it on anything you do not already trust:

- The caller authorizes the selected child executable to run with the operating-system authority of this process. Nothing is dropped, filtered, or confined.
- Child argv is omitted from wrapper diagnostics, but it is still present in process memory and visible through ordinary operating-system interfaces. Omission from logs is not secrecy.
- Relayed and captured child output is **unsanitized child result data** (ADR-015). The wrapper does not inspect it, redact it, or vouch for it. In raw routing it is written byte-for-byte.
- The wrapper's own diagnostics never carry argv or the program path, even with debug tracing enabled: command lines routinely carry tokens, passwords, and credential URLs, so only the argument *count* and the child pid are recorded.

## Routing model · `sec:execwrap:routing-model`

Four destinations, each optional:

|Target|Captures|
|------|--------|
|`redirect`|stdout and stderr, merged, raw|
|`redirect_output`|stdout only|
|`redirect_error`|stderr only|
|`redirect_prefixed`|both streams, with line prefixes|

A stream with **no** file subscriber is relayed verbatim to the parent's corresponding stream — pipe, file, or terminal alike. The wrapper never silently discards child output; discarding a stream is data loss, not a default.

Two routes that resolve to the same file are refused before anything is opened. Resolution is by filesystem identity — device and inode for an existing file, resolved parent plus file name for one that does not exist yet, with dangling symlinks followed to their ultimate target — because two routes opened independently with truncation and written concurrently would interleave and overwrite each other's bytes without any I/O call failing. This is a package-local preflight guard against configuration mistakes; it does not close a time-of-check/time-of-use window, and it is not a filesystem security claim.

## Quickstart · `sec:execwrap:quickstart`

Validate a configuration, then run a child and route its streams:

```rust,no_run
// Spawns a real child process and writes log files, so this compiles
// but is not run as a doctest.
use std::ffi::OsString;

use superloop_execwrap::{Notification, RoutingConfig, preflight_routing, run};

fn main() -> Result<(), superloop_execwrap::ExecError> {
    let config = RoutingConfig {
        redirect_output: Some("build/tool-stdout.log".into()),
        redirect_error: Some("build/tool-stderr.log".into()),
        notify_on_write: true,
        ..RoutingConfig::default()
    };

    // Refuses an ambiguous routing configuration before any file is
    // opened, created, or truncated.
    preflight_routing(&config)?;

    let command: Vec<OsString> = vec!["echo".into(), "hello".into()];
    let outcome = run(&command, &config, |notification| match notification {
        Notification::WritingToLog { path, stream } => {
            println!("writing {} to {}", stream.label(), path.display());
        }
        Notification::WroteToLog { path } => {
            println!("wrote {}", path.display());
        }
    })?;

    // Losing captured output is a failure even when the child succeeded.
    if outcome.data_loss {
        return Err(superloop_execwrap::ExecError::EmptyCommand);
    }
    println!("child exited {}", outcome.exit_code);
    Ok(())
}
```

Preflight alone needs no child process, so it can be exercised directly:

```rust
use superloop_execwrap::{RoutingConfig, Stream, preflight_routing};

let config = RoutingConfig {
    redirect_output: Some("build/out.log".into()),
    ..RoutingConfig::default()
};

assert!(config.is_stream_redirected(Stream::Stdout));
assert!(!config.is_stream_redirected(Stream::Stderr));
preflight_routing(&config).expect("a single target is unambiguous");
```

## Public API tour · `sec:execwrap:public-api-tour`

### Root module · `sec:execwrap:root-module`

- `struct RoutingConfig { redirect, redirect_output, redirect_error, redirect_prefixed, notify_on_write, debug, quiet }` — all four targets are `Option<PathBuf>`; the rest are `bool`. `Default` gives no redirection at all, meaning both streams pass through to the parent.
- `RoutingConfig::is_stream_redirected(&self, stream: Stream) -> bool` — true when that stream has a file subscriber.
- `enum Stream { Stdout, Stderr }` — `label(self) -> &'static str` yields the uppercase name used in diagnostics.
- `preflight_routing(cfg: &RoutingConfig) -> Result<(), ExecError>` — stat-only validation. Returns `ExecError::AmbiguousRedirection` when one file is configured for multiple routing kinds.
- `run(command: &[OsString], cfg: &RoutingConfig, notify: impl FnMut(&Notification)) -> Result<ExecOutcome, ExecError>` — spawn, capture both pipes on reader threads, fan the bytes out to every subscribed writer, relay unsubscribed streams to the parent, and wait. `notify` is called only when `notify_on_write` is set.
- `struct ExecOutcome { exit_code: i32, data_loss: bool }` — a signal termination is reported as `128 + signal`. `data_loss` is true when a log write, a child-stream read, a reader thread, a parent flush, or a writer finalization failed.
- `enum Notification { WritingToLog { path, stream }, WroteToLog { path } }` — the immediate and deferred forms of the write notice.
- `enum ExecError { Io, Spawn { source }, EmptyCommand, AmbiguousRedirection { path } }` — `Spawn` deliberately omits the failing program path, which is caller-controlled argv.
- `safe_open(path: &Path) -> io::Result<File>` — open for writing, creating parent directories as needed.

### `writer` module · `sec:execwrap:writer-module`

- `struct Writer` — `Writer::new(file: impl Write + Send + 'static, add_prefix: bool, wrap_length: usize, props: StreamProps, debug: bool)`, `write(&mut self, stream: Stream, raw: &[u8]) -> io::Result<()>`, `finalize(&mut self) -> io::Result<()>`.
- `struct StreamProps { line1_prefix_stdout, wrap_prefix_stdout, line1_prefix_stderr, wrap_prefix_stderr }` — all `String`, used only in prefixed mode.

The writer has two modes, and the distinction is load-bearing:

- **raw mode** (`add_prefix = false`) writes the child's bytes **unchanged**: no text conversion, no control-byte replacement, no truncation. Raw redirection must be byte-exact.
- **prefixed mode** (`add_prefix = true`) is a text presentation. It buffers per stream, splits on newline bytes, converts each *complete* line lossily, replaces control bytes other than newline, tab, and carriage return with `?`, and re-wraps with the per-stream prefix. Sanitisation runs on complete lines, never on read chunks, so a multibyte code point split across two pipe reads survives intact and the output does not depend on operating-system chunk boundaries.

`finalize` flushes any partial buffered line before flushing the file; skipping it loses a trailing unterminated line.

## Error handling · `sec:execwrap:error-handling`

`run` returns `ExecError` for setup failures only — pipe or file preparation (`Io`), an empty command vector (`EmptyCommand`), a spawn failure (`Spawn`), or ambiguous routing (`AmbiguousRedirection`). A non-zero child status is **not** an error; it arrives through `ExecOutcome::exit_code`.

Per-stream failures during the run do not abort it. A failed log write, read error, panicked reader thread, parent flush failure, or writer finalization error is logged through `tracing` and sets `ExecOutcome::data_loss`. Callers must treat a run with `data_loss` as failed even when the child exited 0.

## What this package deliberately does not do · `sec:execwrap:what-this-package-deliberately-does-not-do`

- **It does not confine the child.** No sandbox, no privilege drop, no environment scrubbing, no argument filtering. Choosing the executable is authorizing it.
- **It does not sanitise child output.** In raw routing the bytes are written exactly as produced. The lossy conversion in prefixed mode is a presentation choice for a human-readable log, not a safety measure.
- **It does not discard a stream.** A stream with no file subscriber is always relayed to the parent.
- **It does not log argv or the program path**, at any verbosity.
- **It does not merge streams except where asked.** Only `redirect` and `redirect_prefixed` combine them.
- **It does not claim atomic or race-free logging.** The identity preflight catches configuration aliases; it does not survive a host replacing a path between the check and the open.
- **It does not decide freshness or emit build metadata.** It is a process wrapper, not a build step.

## Consumers · `sec:execwrap:consumers`

`superloop-run-report` calls the library to launch, relay and wait for its child. Library tests exercise real child processes, capture bytes, signal outcomes, refusal before file creation and data-loss reporting without a command wrapper.
