use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Gid, Pid, Uid};

use super::{publish_letter, stage_letter};

// One possible worker-chosen callback, not an installed mechanism or a Codex stub.
// SCAN is fixture instrumentation: it lets the test establish a silent poll without
// treating elapsed time as proof that the watcher inspected a staging file.
const WATCHER: &str = r#"
set -eu
inbox=$1
seen='|'
paused=false
control_prefix=''
printf 'READY\n'
while :; do
    # Bash's timed read is a builtin: neither the delay nor the scan forks.
    control=''
    if IFS= read -r -t 0.02 control; then
        control=$control_prefix$control
        control_prefix=''
        case "$control" in
            pause) paused=true; printf 'PAUSED\n' ;;
            resume) paused=false ;;
        esac
    else
        status=$?
        [ "$status" -ne 1 ] || exit 0
        # A timeout above 128 can leave a partial line in control. The next
        # read supplies its suffix, so keep the prefix across scan cycles.
        if [ "$status" -gt 128 ] && [ -n "$control" ]; then
            control_prefix=$control_prefix$control
            # A descheduled read can retain even the prefix in pieces. Only
            # acknowledge the complete fragment whose suffix the test holds.
            case "$control_prefix" in
                pau|res) printf 'PARTIAL %s\n' "$control_prefix" ;;
            esac
        fi
    fi
    [ "$paused" = false ] || continue
    names=''
    for file in "$inbox"/*.md; do
        [ -f "$file" ] || continue
        name=${file##*/}
        case "$seen" in *"|$name|"*) continue ;; esac
        seen="$seen$name|"
        names="$names $name"
    done
    if [ -n "$names" ]; then printf 'WAKE%s\n' "$names"; fi
    printf 'SCAN\n'
done
"#;

// The watcher reads one control line with a 20 ms timer and scans once per
// active cycle. Scheduling and filesystem work can delay those cycles on a
// loaded node, so each awaited line, named event and cleanup gets 120 seconds.
// WAKE and PAUSED must still arrive by name, even if SCAN lines continue.
const CALLBACK_LIMIT: Duration = Duration::from_secs(120);

struct Watcher {
    child: Child,
    stdout: ChildStdout,
    pending: Vec<u8>,
    last_lines: VecDeque<String>,
}

fn next_line(
    output: &mut impl std::io::Read,
    pending: &mut Vec<u8>,
    deadline: Instant,
    last_lines: &mut VecDeque<String>,
) -> Result<String, String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "worker-inbox-callback timeout: last lines={last_lines:?}"
            ));
        }
        if let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line = String::from_utf8_lossy(&pending[..end]).into_owned();
            pending.drain(..=end);
            if last_lines.len() == 16 {
                last_lines.pop_front();
            }
            last_lines.push_back(line.clone());
            return Ok(line);
        }
        let mut bytes = [0; 4096];
        match output.read(&mut bytes) {
            Ok(0) => {
                return Err(format!(
                    "worker-inbox-callback output closed: last lines={last_lines:?}"
                ));
            }
            Ok(count) => pending.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(remaining.min(Duration::from_millis(5)));
            }
            Err(error) => {
                return Err(format!(
                    "worker-inbox-callback output failed: {error}; last lines={last_lines:?}"
                ));
            }
        }
    }
}

impl Watcher {
    fn start(inbox: &std::path::Path) -> Self {
        let mut command = Command::new("/bin/bash");
        command
            .args(["--noprofile", "--norc", "-c", WATCHER, "inbox-callback"])
            .arg(inbox)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("BASH_ENV");
        let mut child = crate::fixture_exec::spawn(&mut command).expect("shell callback");
        let stdout = child.stdout.take().expect("callback output");
        fcntl(&stdout, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("nonblocking callback output");
        fcntl(
            child.stdin.as_ref().expect("callback control"),
            FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
        )
        .expect("nonblocking callback control");
        let mut watcher = Self {
            child,
            stdout,
            pending: Vec::new(),
            last_lines: VecDeque::new(),
        };
        assert_eq!(watcher.line(Instant::now() + CALLBACK_LIMIT), "READY");
        watcher
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.child.id()).expect("callback pid"))
    }

    fn line(&mut self, deadline: Instant) -> String {
        next_line(
            &mut self.stdout,
            &mut self.pending,
            deadline,
            &mut self.last_lines,
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn wake(&mut self, expected: &str) -> String {
        let deadline = Instant::now() + CALLBACK_LIMIT;
        loop {
            let line = next_line(
                &mut self.stdout,
                &mut self.pending,
                deadline,
                &mut self.last_lines,
            )
            .unwrap_or_else(|error| panic!("worker-inbox-callback missed {expected}: {error}"));
            if line == expected {
                return line;
            }
            assert_eq!(line, "SCAN", "worker-inbox-callback missed {expected}");
        }
    }

    fn pause(&mut self) {
        // PARTIAL proves the watcher retained the prefix across a read timeout;
        // a sleep cannot establish that precondition on a descheduled watcher.
        self.control(b"pau");
        assert_eq!(self.wake("PARTIAL pau"), "PARTIAL pau");
        self.control(b"se\n");
        assert_eq!(self.wake("PAUSED"), "PAUSED");
    }

    fn resume(&mut self) {
        self.control(b"res");
        assert_eq!(self.wake("PARTIAL res"), "PARTIAL res");
        self.control(b"ume\n");
    }

    fn control(&mut self, message: &[u8]) {
        // Only four short writes in the fixture; the pipe cannot fill.
        self.child
            .stdin
            .as_mut()
            .expect("callback control")
            .write_all(message)
            .expect("callback control write");
    }

    fn stop(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + CALLBACK_LIMIT;
        let _ = killpg(self.pid(), Signal::SIGKILL);
        loop {
            let exited = self
                .child
                .try_wait()
                .map_err(|error| {
                    format!(
                        "worker-inbox-callback reap failed: {error}; last lines={:?}",
                        self.last_lines
                    )
                })?
                .is_some();
            if exited {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "worker-inbox-callback cleanup timeout: exited={exited}; last lines={:?}",
                    self.last_lines
                ));
            }
            thread::sleep(remaining.min(Duration::from_millis(5)));
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            if thread::panicking() {
                drop(writeln!(std::io::stderr(), "{error}"));
            } else {
                panic!("{error}");
            }
        }
    }
}

/// ´test:unit:worker-inbox-callback-deadline-names-last-lines´
#[test]
fn worker_inbox_callback_deadline_names_last_lines() {
    let mut output = std::io::empty();
    let mut pending = b"SCAN\n".to_vec();
    let mut last_lines = VecDeque::from(["READY".to_owned()]);
    // Even queued output cannot extend an expired line deadline.
    let error = next_line(&mut output, &mut pending, Instant::now(), &mut last_lines)
        .expect_err("deadline");
    assert!(error.contains("worker-inbox-callback timeout"), "{error}");
    assert!(error.contains("READY"), "{error}");
    pending.clear();
    let error = next_line(
        &mut output,
        &mut pending,
        Instant::now() + CALLBACK_LIMIT,
        &mut last_lines,
    )
    .expect_err("closed callback");
    assert!(
        error.contains("worker-inbox-callback output closed"),
        "{error}"
    );
    assert!(error.contains("READY"), "{error}");
}

/// The injected watcher proves publication and listing, not live Codex-turn delivery.
/// ´test:unit:worker-inbox-callback-lists-atomic-publications´
#[test]
fn worker_inbox_callback_lists_atomic_publications() {
    let fixture = tempfile::tempdir().expect("TMPDIR callback fixture");
    let inbox = fixture.path().join("inbox");
    std::fs::create_dir(&inbox).expect("inbox");
    let directory: OwnedFd = File::open(&inbox).expect("held inbox").into();
    let owner = Uid::effective().as_raw();
    let group = Gid::effective().as_raw();
    // Hidden staging is present before the first poll, so each measured scan sees it.
    stage_letter(
        &directory,
        ".placing-first",
        b"First letter.\n",
        owner,
        group,
    )
    .expect("real owner staging and sync");
    let mut watcher = Watcher::start(&inbox);
    for _ in 0..3 {
        assert_eq!(watcher.line(Instant::now() + CALLBACK_LIMIT), "SCAN");
    }
    assert!(!inbox.join("work-1.md").exists());

    // Publication by the owner's rename makes the complete letter visible.
    publish_letter(&directory, &inbox, ".placing-first", "work-1.md")
        .expect("real owner publication");
    assert_eq!(watcher.wake("WAKE work-1.md"), "WAKE work-1.md");
    assert_eq!(
        std::fs::read(inbox.join("work-1.md")).expect("letter"),
        b"First letter.\n"
    );

    // Establish both publications between polls, as one burst, without a timing race.
    watcher.pause();
    for (temp, name) in [
        (".placing-second", "work-2.md"),
        (".placing-third", "work-3.md"),
    ] {
        stage_letter(&directory, temp, b"Burst letter.\n", owner, group).expect("burst staging");
        publish_letter(&directory, &inbox, temp, name).expect("burst publication");
    }
    watcher.resume();
    assert_eq!(
        watcher.wake("WAKE work-2.md work-3.md"),
        "WAKE work-2.md work-3.md"
    );

    // A publication after the hand-back remains eligible for the next wake.
    stage_letter(
        &directory,
        ".placing-later",
        b"Later letter.\n",
        owner,
        group,
    )
    .expect("later staging");
    publish_letter(&directory, &inbox, ".placing-later", "work-4.md").expect("later publication");
    assert_eq!(watcher.wake("WAKE work-4.md"), "WAKE work-4.md");
    for _ in 0..3 {
        assert_eq!(watcher.line(Instant::now() + CALLBACK_LIMIT), "SCAN");
    }
}
