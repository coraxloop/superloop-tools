#![allow(dead_code)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, PoisonError};

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// For output callers with unconfigured streams, library/std/src/process.rs documents inherited stdio for spawn and noninherited stdin for output (lines 1063, 1095-1096, 1103, 1138-1139), library/std/src/sys/process/mod.rs selects `MakePipe` (lines 54-57), and library/std/src/sys/process/unix/common.rs selects null stdin (lines 358-365).
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

pub fn write_executable(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

pub fn spawn_serialized(command: &mut Command) -> std::io::Result<Child> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

pub trait SerializedCommand {
    fn spawn_serialized(&mut self) -> std::io::Result<Child>;
    fn output_serialized(&mut self) -> std::io::Result<Output>;
    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output>;
    fn status_serialized(&mut self) -> std::io::Result<ExitStatus>;
}

impl SerializedCommand for Command {
    fn spawn_serialized(&mut self) -> std::io::Result<Child> {
        spawn_serialized(self)
    }

    fn output_serialized(&mut self) -> std::io::Result<Output> {
        self.output_serialized_with_stdin(Stdio::null())
    }

    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output> {
        self.stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_serialized(self)?.wait_with_output()
    }

    fn status_serialized(&mut self) -> std::io::Result<ExitStatus> {
        spawn_serialized(self)?.wait()
    }
}

/// Hand a payload to a spawned child, accepting a child that exits before reading.
///
/// A child is entitled to exit without draining its stdin: the wrapper denies a
/// missing instance file or a missing binary before it ever execs the hook, an argv
/// that is not the hook command never reads at all, and a payload past the hook's
/// input ceiling leaves the reader finished while bytes are still queued. The write
/// then fails with `BrokenPipe` whatever the payload's size, and that failure says
/// nothing about the case — the child's exit status, streams, and journal remain the
/// verdict. Any other write failure is a fault of the harness itself and must be
/// seen. Taking the pipe by value keeps the close where the caller expects it, so the
/// child still reads end-of-file the moment the payload is complete.
///
/// # Panics
///
/// Panics with the context and the error for every write failure other than a read
/// end the child has already closed.
pub fn write_payload(mut stdin: ChildStdin, payload: &[u8], context: &str) {
    if let Err(error) = stdin.write_all(payload) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "{context}: {error}"
        );
    }
}
