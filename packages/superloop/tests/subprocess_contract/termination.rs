//! Termination crosses the entry's production runner and namespace relay.

use super::support;

use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use support::{SerializedCommand as _, TestDir};

struct Cleanup {
    entry: Pid,
    private: Option<Pid>,
}

// This controller supplies a shell's session, job group and foreground handoff.
// Every stop is observed before the next handoff; sleeps only yield while
// polling for the private command's readiness record or its stopped state.
const JOB_SHELL: &str = r"
import fcntl, os, pathlib, signal, sys, termios, time
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
shell = os.getpgrp()
ready = pathlib.Path(os.environ['ENTRY_JOB_READY'])
mode = os.environ['ENTRY_JOB_MODE']
release, start = os.pipe()
entry = os.fork()
if entry == 0:
    os.close(start)
    os.setpgid(0, 0)
    os.read(release, 1)
    os.close(release)
    if mode == 'timeout':
        os.execvp('timeout', ['timeout', '2', *sys.argv[1:]])
    os.execv(sys.argv[1], sys.argv[1:])
os.close(release)
os.setpgid(entry, entry)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
def interrupted(number, frame):
    raise RuntimeError('controller interrupted: ' + str(number))
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGALRM, interrupted)
def stopped(expected):
    signal.alarm(5)
    pid, status = os.waitpid(entry, os.WUNTRACED)
    signal.alarm(0)
    assert pid == entry and os.WIFSTOPPED(status), ('entry did not stop', status)
    assert os.WSTOPSIG(status) == expected, ('wrong stop signal', status, expected)
private = None
reaped = False
try:
    if mode in ('bg', 'stop'):
        os.tcsetpgrp(0, entry)
    os.write(start, b'x')
    os.close(start)
    signal.alarm(30)
    while not ready.exists():
        time.sleep(0.01)
    private = int(ready.read_text())
    signal.alarm(0)
    if mode == 'timeout':
        signal.alarm(5)
        while pathlib.Path('/proc/' + str(private) + '/stat').read_text().rsplit(') ', 1)[1].split()[0] != 'T':
            time.sleep(0.01)
        pid, status = os.waitpid(entry, os.WUNTRACED)
        reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 124, ('timeout did not fire', status)
        assert os.tcgetpgrp(0) == shell, 'timeout background job stole terminal'
        print('TIMEOUT-DONE', flush=True)
        sys.exit(0)
    expected = signal.SIGTTIN
    if mode in ('bg', 'stop'):
        expected = signal.SIGSTOP if mode == 'stop' else signal.SIGTSTP
        os.killpg(private, expected)
    stopped(expected)
    os.tcsetpgrp(0, shell)
    if mode == 'bg':
        os.killpg(entry, signal.SIGCONT)
        stopped(signal.SIGTTIN)
        assert os.tcgetpgrp(0) == shell, 'bg stole the shell terminal'
    os.tcsetpgrp(0, entry)
    os.killpg(entry, signal.SIGCONT)
    print('INPUT', flush=True)
    signal.alarm(5)
    pid, status = os.waitpid(entry, 0)
    reaped = True
    signal.alarm(0)
    assert os.waitstatus_to_exitcode(status) == 0, status
    print('JOB-DONE', flush=True)
finally:
    signal.alarm(0)
    for group, number in [(private, signal.SIGKILL), (entry, signal.SIGTERM), (entry, signal.SIGCONT)]:
        if group is not None:
            try:
                os.killpg(group, number)
            except ProcessLookupError:
                pass
    if not reaped:
        os.waitpid(entry, 0)
";

/// # Panics
/// Panics only if fixture setup fails or a background resume takes the terminal.
/// ´claim:entry:background-resume-keeps-shell-terminal´
/// ´test:integration:background-resume-keeps-shell-terminal´
#[test]
fn background_resume_keeps_shell_terminal() {
    job_control_case("bg");
}

/// # Panics
/// Panics only if fixture setup fails or a foregrounded background job cannot read.
/// ´claim:entry:background-start-foreground-resume-reads-terminal´
/// ´test:integration:background-start-foreground-resume-reads-terminal´
#[test]
fn background_start_foreground_resume_reads_terminal() {
    job_control_case("fg");
}

/// # Panics
/// Panics only if fixture setup fails or an explicit private SIGSTOP is lost.
/// ´claim:entry:explicit-stop-reaches-caller´
/// ´test:integration:explicit-stop-reaches-caller´
#[test]
fn explicit_stop_reaches_caller() {
    job_control_case("stop");
}

/// # Panics
/// Panics only if fixture setup fails or a terminal stop prevents timeout expiry.
/// ´claim:entry:terminal-stop-does-not-stop-timeout´
/// ´test:integration:terminal-stop-does-not-stop-timeout´
#[test]
fn terminal_stop_does_not_stop_timeout() {
    job_control_case("timeout");
}

fn job_control_case(mode: &str) {
    let directory = TestDir::new_safe("job-control");
    let ready_path = directory.path().join("job-ready");
    let script = format!(
        "printf '%s\\n' \"$$\" > '{0}.tmp'; mv '{0}.tmp' '{0}'; printf 'READY %s\\n' \"$$\"; read -r word; printf 'READ %s\\n' \"$word\"",
        ready_path.display()
    );
    let pty = nix::pty::openpty(None, None).expect("job terminal");
    let mut master = fs::File::from(pty.master);
    let mut command = fixture_wrapped_command(&directory, false, &script, Some(JOB_SHELL));
    let diagnostics = directory.path().join("job.stderr");
    command
        .stdin(fs::File::from(pty.slave))
        .stderr(fs::File::create(&diagnostics).expect("job diagnostics"))
        .env("ENTRY_JOB_READY", &ready_path)
        .env("ENTRY_JOB_MODE", mode);
    let mut child = command.spawn_serialized().expect("job shell");
    let mut cleanup = Cleanup {
        entry: Pid::from_raw(i32::try_from(child.id()).expect("controller pid")),
        private: None,
    };
    let stdout = child.stdout.take().expect("job stdout");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut transcript = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("job output");
            if let Some(pid) = line.strip_prefix("READY ") {
                ready_tx.send(pid.to_owned()).expect("readiness receiver");
            }
            if line == "INPUT" {
                writeln!(master, "hello").expect("foreground input");
            }
            writeln!(transcript, "{line}").expect("transcript");
        }
        let output = child.wait_with_output().expect("controller exit");
        let _sent = done_tx.send((transcript, output));
    });
    let pid = ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("private ready");
    cleanup.private = Some(Pid::from_raw(pid.parse().expect("private pid")));
    let started = Instant::now();
    let (transcript, output) =
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| {
                panic!(
                    "job handoffs finish in five seconds: {error}; {}",
                    fs::read_to_string(&diagnostics).expect("job diagnostics")
                );
            });
    let stderr = fs::read_to_string(&diagnostics).expect("job diagnostics");
    assert!(output.status.success(), "{transcript}\n{stderr}");
    if mode == "timeout" {
        assert!(transcript.contains("TIMEOUT-DONE\n"), "{transcript}");
        assert!(stderr.contains("signal=SIGTERM"), "{stderr}");
    } else {
        assert!(transcript.contains("READ hello\n"), "{transcript}");
        assert!(transcript.contains("JOB-DONE\n"), "{transcript}");
    }
    cleanup.private = None;
    reader.join().expect("job reader");
    writeln!(
        std::io::stderr(),
        "entry job mode={mode}: completed in {:?}",
        started.elapsed()
    )
    .expect("job measurement");
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(group) = self.private {
            let _kill = killpg(group, Signal::SIGKILL);
        }
        let _stop = kill(self.entry, Signal::SIGTERM);
        let _resume = kill(self.entry, Signal::SIGCONT);
    }
}

/// # Panics
/// Panics only if setup fails or entry termination leaves a child or pipe alive.
/// ´claim:entry:external-term-reaps-private-group-and-closes-pipe´
/// ´test:integration:external-term-reaps-private-group-and-closes-pipe´
#[test]
fn external_term_reaps_private_group_and_closes_pipe() {
    for signal in [
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGHUP,
    ] {
        for json in [false, true] {
            termination_case(json, signal);
        }
    }
}

const LONG_CHILD: &str = r#"
trap 'wait "$child"; exit 0' TERM INT QUIT HUP
python3 -c '
import os, signal, time
for number in (signal.SIGINT, signal.SIGQUIT):
    signal.signal(number, signal.SIG_DFL)
print("READY", os.getppid(), os.getpid(), flush=True)
time.sleep(290)
' &
child=$!
wait "$child"
"#;

fn fixture_command(directory: &TestDir, json: bool, script: &str) -> Command {
    fixture_wrapped_command(directory, json, script, None)
}

#[allow(unsafe_code)]
fn fixture_wrapped_command(
    directory: &TestDir,
    json: bool,
    script: &str,
    controller: Option<&str>,
) -> Command {
    let (_, podman) = directory.prepare();
    let root = directory.path();
    let executable = fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("entry binary");
    let entry_stub = root.join("entry-stub");
    // Model podman's rootless parent: catch every catchable signal except
    // SIGTSTP and forward it to the namespace child, in the same process group.
    // SIGSTOP therefore stops the proxy too; TTIN/TTOU alone do not. Namespace,
    // mounts and credentials remain simulated; this is not a real podman run.
    support::write_executable(
        &podman,
        br"#!/usr/bin/python3
import os, signal, sys
args = sys.argv[4:]
script = args[0].replace(os.environ['ENTRY_REAL'], os.environ['ENTRY_STUB'])
release, start = os.pipe()
child = os.fork()
if child == 0:
    os.close(start)
    os.read(release, 1)
    os.close(release)
    os.execv('/bin/sh', ['sh', '-c', script] + args[1:])
os.close(release)
def forward(number, frame):
    try:
        os.kill(child, number)
    except ProcessLookupError:
        pass
for number in signal.valid_signals():
    if number not in (signal.SIGKILL, signal.SIGSTOP, signal.SIGTSTP):
        signal.signal(number, forward)
os.write(start, b'x')
os.close(start)
_, status = os.waitpid(child, 0)
code = os.waitstatus_to_exitcode(status)
sys.exit(code if code >= 0 else 128 - code)
",
        0o755,
    )
    .expect("podman proxy fixture");
    support::write_executable(
        &entry_stub,
        br#"#!/bin/sh
set -eu
if [ "$1" = ensure-roots ]; then
    printf 'wall 0\n' >> "$5"
else
    exec "$ENTRY_REAL" "$@"
fi
"#,
        0o755,
    )
    .expect("entry fixture");
    for (name, script) in [
        ("unshare", "#!/bin/sh\nshift\nexec \"$@\"\n"),
        ("mount", "#!/bin/sh\nexit 0\n"),
        ("setpriv", "#!/bin/sh\nshift 3\nexec \"$@\"\n"),
    ] {
        support::write_executable(&root.join(name), script.as_bytes(), 0o755)
            .expect("namespace fixture");
    }
    let mut command = controller.map_or_else(
        || Command::new(&executable),
        |controller| {
            let mut command = Command::new("python3");
            command.args(["-c", controller]).arg(&executable);
            command
        },
    );
    command.arg("enter");
    if json {
        command.arg("--json");
    }
    command
        .args(["alpha", "--", "/bin/sh", "-c", script])
        .env("ENTER_LOOP_REGISTRY", root.join("registry.toml"))
        .env("ENTER_LOOP_PODMAN", &podman)
        .env("ENTRY_REAL", &executable)
        .env("ENTRY_STUB", &entry_stub)
        .env("HOME", root)
        .env("TMPDIR", root)
        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe disposition and mask syscalls run after fork.
    unsafe {
        command.pre_exec(|| {
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
                if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            nix::sys::signal::pthread_sigmask(
                nix::sys::signal::SigmaskHow::SIG_SETMASK,
                Some(&nix::sys::signal::SigSet::empty()),
                None,
            )
            .map_err(std::io::Error::other)
        });
    }
    command
}

/// # Panics
/// Panics only if fixture setup fails or the entry overrides an ignored hangup.
/// ´claim:entry:ignored-hangup-survives-private-exec´
/// ´test:integration:ignored-hangup-survives-private-exec´
#[test]
#[allow(unsafe_code)]
fn ignored_hangup_survives_private_exec() {
    let directory = TestDir::new_safe("ignored-hangup");
    let mut command = fixture_command(
        &directory,
        false,
        r#"
exec python3 -c '
import os, signal, sys
assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
print("READY", os.getpid(), flush=True)
sys.stdin.readline()
print("SURVIVED", flush=True)
'
"#,
    );
    command.stdin(Stdio::piped());
    // SAFETY: signal changes only the forked child's disposition before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn_serialized().expect("ignored-hangup entry");
    let mut cleanup = Cleanup {
        entry: Pid::from_raw(i32::try_from(child.id()).expect("entry pid")),
        private: None,
    };
    let mut input = child.stdin.take().expect("input pipe");
    let stdout = child.stdout.take().expect("stdout pipe");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut ready = String::new();
        stdout.read_line(&mut ready).expect("readiness");
        ready_tx.send(ready).expect("readiness receiver");
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).expect("EOF");
        let output = child.wait_with_output().expect("entry exit");
        let _sent = done_tx.send((rest, output));
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("private readiness");
    let private = Pid::from_raw(
        ready
            .strip_prefix("READY ")
            .expect("ready prefix")
            .trim()
            .parse()
            .expect("private pid"),
    );
    cleanup.private = Some(private);
    kill(cleanup.entry, Signal::SIGHUP).expect("hangup entry");
    killpg(private, Signal::SIGHUP).expect("hangup private group");
    writeln!(input, "finish").expect("release private command");
    let (rest, output) = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("ignored hangup completes");
    assert_eq!(rest, "SURVIVED\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("exit=0 "));
    cleanup.private = None;
    reader.join().expect("reader");
}

fn termination_case(json: bool, signal: Signal) {
    let directory = TestDir::new_safe("termination");
    let mut child = fixture_command(&directory, json, LONG_CHILD)
        .spawn_serialized()
        .expect("production entry");
    let entry = Pid::from_raw(i32::try_from(child.id()).expect("entry pid"));
    let mut cleanup = Cleanup {
        entry,
        private: None,
    };
    let stdout = child.stdout.take().expect("pipe");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (eof_tx, eof_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut ready = String::new();
        stdout.read_line(&mut ready).expect("readiness line");
        ready_tx.send(ready).expect("readiness receiver");
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).expect("pipe EOF");
        let _sent = eof_tx.send(rest);
    });
    let (exit_tx, exit_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let output = child.wait_with_output().expect("entry exit");
        let _sent = exit_tx.send(output);
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("private readiness");
    if ready.is_empty() {
        let output = exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("failed entry report");
        panic!(
            "entry failed before readiness: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let words: Vec<_> = ready.split_whitespace().collect();
    assert_eq!(words.first(), Some(&"READY"), "{ready}");
    let private: i32 = words[1].parse().expect("private pid");
    let descendant: i32 = words[2].parse().expect("descendant pid");
    cleanup.private = Some(Pid::from_raw(private));
    let status = fs::read_to_string(format!("/proc/{private}/status")).expect("private status");
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:\t"))
        .expect("ignored signals");
    let mask = u64::from_str_radix(ignored, 16).expect("signal mask");
    let relevant = [Signal::SIGINT, Signal::SIGQUIT, Signal::SIGHUP]
        .into_iter()
        .fold(0_u64, |mask, signal| mask | (1 << (signal as u32 - 1)));
    assert_eq!(mask & relevant, 0, "private SigIgn={ignored}");
    let started = Instant::now();
    let bound = Duration::from_secs(5);
    kill(entry, signal).expect("external signal to entry only");
    let output = exit_rx
        .recv_timeout(bound)
        .expect("entry reaped within five seconds");
    let rest = eof_rx
        .recv_timeout(bound.saturating_sub(started.elapsed()))
        .expect("pipeline EOF within five seconds");
    assert_eq!(rest, [] as [u8; 0]);
    let expected = 128 + signal as i32;
    let name = signal.to_string();
    assert_eq!(output.status.code(), Some(expected));
    let report = String::from_utf8(output.stderr).expect("report text");
    if json {
        let report: serde_json::Value =
            serde_json::from_str(report.lines().last().expect("trailer")).expect("JSON report");
        assert_eq!(report["exit"], expected);
        assert_eq!(report["signal"], name);
    } else {
        assert!(
            report.contains(&format!(
                "ENTER-REPORT loop=alpha uid=41001 exit={expected} "
            )),
            "{report}"
        );
        assert!(report.contains(&format!(" signal={name}\n")), "{report}");
    }
    for pid in [private, descendant] {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "private process {pid} remains"
        );
    }
    assert!(
        started.elapsed() < bound,
        "fixed five-second termination bound"
    );
    writeln!(
        std::io::stderr(),
        "entry external {name} json={json}: SigIgn={ignored}, child gone and pipe EOF in {:?}",
        started.elapsed()
    )
    .expect("measurement");
    cleanup.private = None;
    reader.join().expect("pipe reader");
    waiter.join().expect("entry waiter");
}

/// # Panics
/// Panics only if setup fails, terminal stops do not propagate or input is lost.
/// ´claim:entry:private-command-group-retains-terminal-input´
/// ´test:integration:private-command-group-retains-terminal-input´
#[test]
#[allow(unsafe_code)]
fn private_command_group_retains_terminal_input() {
    let directory = TestDir::new_safe("termination-terminal");
    let pty = nix::pty::openpty(None, None).expect("fixture terminal");
    let mut master = fs::File::from(pty.master);
    let mut command = fixture_command(
        &directory,
        false,
        "printf 'READY %s\\n' \"$$\"; read -r word; printf 'READ %s\\n' \"$word\"",
    );
    command.stdin(fs::File::from(pty.slave));
    // SAFETY: these post-fork syscalls only establish the fixture's private
    // session and controlling terminal, using its already-open stdin.
    unsafe {
        command.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn_serialized().expect("terminal entry");
    let mut cleanup = Cleanup {
        entry: Pid::from_raw(i32::try_from(child.id()).expect("entry pid")),
        private: None,
    };
    let stdout = child.stdout.take().expect("stdout pipe");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut ready = String::new();
        stdout.read_line(&mut ready).expect("terminal readiness");
        ready_tx.send(ready).expect("readiness receiver");
        let mut rest = String::new();
        stdout
            .read_to_string(&mut rest)
            .expect("terminal command EOF");
        let output = child.wait_with_output().expect("terminal entry exit");
        let _sent = done_tx.send((rest, output));
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("ready to read terminal");
    let private = ready
        .strip_prefix("READY ")
        .expect("private readiness")
        .trim()
        .parse()
        .expect("private pid");
    cleanup.private = Some(Pid::from_raw(private));
    let stopped_at = Instant::now();
    master.write_all(&[26]).expect("terminal Ctrl-Z");
    loop {
        use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
        if matches!(
            waitid(
                Id::Pid(cleanup.entry),
                WaitPidFlag::WSTOPPED | WaitPidFlag::WNOHANG
            )
            .expect("entry stop observation"),
            WaitStatus::Stopped(_, Signal::SIGSTOP)
        ) {
            break;
        }
        assert!(
            stopped_at.elapsed() < Duration::from_secs(5),
            "entry propagates terminal stop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        nix::unistd::tcgetpgrp(&master).expect("terminal owner"),
        cleanup.entry
    );
    let private_status =
        fs::read_to_string(format!("/proc/{private}/status")).expect("stopped private status");
    assert!(
        private_status
            .lines()
            .any(|line| line.starts_with("State:\tT")),
        "{private_status}"
    );
    writeln!(
        std::io::stderr(),
        "terminal Ctrl-Z: private and entry stopped, terminal returned in {:?}",
        stopped_at.elapsed()
    )
    .expect("stop measurement");
    kill(cleanup.entry, Signal::SIGCONT).expect("caller resumes entry");
    writeln!(master, "hello").expect("terminal input");
    let (rest, output) = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("terminal read finishes");
    assert_eq!(rest, "READ hello\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    cleanup.private = None;
    reader.join().expect("terminal reader");
}

/// # Panics
/// Panics only if the relay accepts an absent, malformed or unsupported set.
/// ´claim:entry:relay-signals-refusal´
/// ´test:integration:relay-signals-refusal´
#[test]
fn relay_signals_refusal() {
    for arguments in [vec![], vec![""], vec!["bad"], vec!["8"], vec!["+1"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop"))
            .arg("_supervise-command")
            .args(arguments)
            .output_serialized()
            .expect("relay refusal");
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("relay-signals:"));
    }
}

/// # Panics
/// Panics only if the environment-clearing route loses the watched set.
/// ´claim:entry:watched-set-survives-cleared-route´
/// ´test:integration:watched-set-survives-cleared-route´
#[test]
fn watched_set_survives_cleared_route() {
    let directory = TestDir::new_safe("cleared-route");
    let mut command = fixture_command(&directory, false, "printf 'CLEARED-ROUTE\\n'");
    let root = directory.path();
    let real = fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("entry");
    // Like flatpak-spawn's host transport, discard the caller's environment.
    // The retained values below are fixture executable pins, not entry metadata.
    let stub = format!(
        r#"#!/bin/bash
set -eu
shift 3
script=${{1//"$ENTRY_REAL"/"$ENTRY_STUB"}}
shift
exec /usr/bin/env -i PATH={root}:/usr/bin:/bin ENTRY_REAL={real} /bin/sh -c "$script" "$@"
"#,
        root = root.display(),
        real = real.display()
    );
    support::write_executable(&root.join("podman-stub"), stub.as_bytes(), 0o755)
        .expect("clearing route");
    let output = command.output_serialized().expect("entry");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"CLEARED-ROUTE\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("exit=0 "));
}

/// # Panics
/// Panics only if Capture fails to transport the watched set through the relay.
/// ´claim:entry:verify-capture-runs-real-relay´
/// ´test:integration:verify-capture-runs-real-relay´
#[test]
fn verify_capture_runs_real_relay() {
    let directory = TestDir::new_safe("verify-relay");
    let (root, podman) = directory.prepare();
    let real = fs::canonicalize(env!("CARGO_BIN_EXE_superloop")).expect("entry");
    let harness = std::env::current_exe().expect("test executable");
    for (name, script) in [
        ("unshare", "#!/bin/sh\nshift\nexec \"$@\"\n"),
        ("mount", "#!/bin/sh\nexit 0\n"),
        ("setpriv", "#!/bin/sh\nshift 3\nexec \"$@\"\n"),
        (
            "id",
            "#!/bin/sh\ncase $1 in -un) echo alpha;; *) echo 41001;; esac\n",
        ),
    ] {
        support::write_executable(&root.join(name), script.as_bytes(), 0o755)
            .expect("namespace fixture");
    }
    // Provisioning, mounts and credentials are simulated; the generated outer
    // script, ProcessRunner Capture, real relay and verification probe execute.
    let stub = format!(
        r"#!/usr/bin/python3
import os, sys
root = {root:?}
args = sys.argv[1:]
if args[2] == 'inspect-roots':
    with open(args[6], 'a') as report:
        report.write('inspection 0 0 0\n[]\n')
    sys.exit(0)
script = args[3]
if 'mounts_left=' in script:
    print('mounts_left=0\ntmp_left=0')
    sys.exit(0)
assert 'ENTER_LOOP_WATCHED_SIGNALS' not in os.environ
script = script.replace({harness:?}, {real:?})
for name in ('unshare', 'mount', 'setpriv', 'id'):
    script = script.replace('/usr/bin/' + name, root + '/' + name)
os.execv('/bin/sh', ['sh', '-c', script] + args[4:])
",
        root = root.to_str().expect("root"),
        harness = harness.to_str().expect("harness"),
        real = real.to_str().expect("real")
    );
    support::write_executable(&podman, stub.as_bytes(), 0o755).expect("verify route");
    let output = super::run_verify_fixture(
        &root,
        &root,
        &podman,
        &root.join("log"),
        0,
        &["verify", "alpha"],
        &[("LOOP_HOME_REAL_VERIFY_RELAY", "1".to_owned())],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
