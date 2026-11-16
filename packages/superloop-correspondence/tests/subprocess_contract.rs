use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::{Child, Command, Output, Stdio};

const FIXTURE_HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(120);

#[track_caller]
fn assert_child_success(output: &Output) {
    assert_child_success_with_stdout(output, &output.stdout);
}

#[track_caller]
fn assert_child_success_with_stdout(output: &Output, stdout: &[u8]) {
    let tail = &stdout[stdout.len().saturating_sub(512)..];
    assert!(
        output.status.success(),
        "child status={} stderr={} stdout_tail={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(tail)
    );
}

#[track_caller]
fn assert_child_failure(output: &Output) {
    let tail = &output.stdout[output.stdout.len().saturating_sub(512)..];
    assert!(
        !output.status.success(),
        "unexpected child success: status={} stderr={} stdout_tail={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(tail)
    );
}

#[track_caller]
fn assert_text_contains(text: &[u8], needle: &str) {
    let text = String::from_utf8_lossy(text);
    let head: String = text.chars().take(512).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(512)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    assert!(
        text.contains(needle),
        "missing {needle:?} in {} bytes: head={head:?} tail={tail:?}",
        text.len()
    );
}

#[track_caller]
fn assert_text_omits(text: &[u8], needle: &str) {
    let text = String::from_utf8_lossy(text);
    assert!(!text.contains(needle), "unexpected {needle:?} in {text:?}");
}

fn kill_and_capture(mut child: Child) -> Output {
    child.kill().expect("hung fixture is killed");
    child.wait_with_output().expect("hung fixture is reaped")
}

// Close our writer before any spawn; another test's fork can still hold its
// inherited descriptor until exec, so readiness retries only ETXTBSY.
fn write_executable(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut writer = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)?;
    writer.write_all(bytes)?;
    writer.sync_all()?;
    drop(writer);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

fn fixture_output(command: &mut Command) -> std::io::Result<std::process::Output> {
    fixture_output_after_busy(command, std::thread::yield_now)
}

fn fixture_output_after_busy(
    command: &mut Command,
    mut after_busy: impl FnMut(),
) -> std::io::Result<std::process::Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let started = std::time::Instant::now();
    loop {
        match command.spawn() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                if started.elapsed() >= FIXTURE_HANG_BOUND {
                    return Err(std::io::Error::other(
                        "fixture-exec-busy: ETXTBSY exceeded 120-second hang bound",
                    ));
                }
                after_busy();
            }
            Err(error) => return Err(error),
            Ok(child) => return child.wait_with_output(),
        }
    }
}

/// # Panics
/// Panics if the fixture cannot run, exceeds the 120-second hang bound, or exits without the named transport event.
fn output_after_exit_event(command: &mut Command, event: impl Fn() -> bool) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() >= FIXTURE_HANG_BOUND {
            let output = kill_and_capture(child);
            panic!(
                "fixture process exceeded 120 seconds: status={} stderr={} stdout_tail={}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout[output.stdout.len().saturating_sub(512)..])
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        event(),
        "fixture transport event absent: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// # Panics
/// Panics only if the hung child's output is lost when it is killed.
/// ´test:integration:killed-fixture-keeps-partial-output´
#[test]
fn killed_fixture_keeps_partial_output() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let printed = directory.path().join("printed");
    let mut child = Command::new("bash")
        .arg("-c")
        .arg("printf 'partial stderr\\n' >&2; printf 'ready\\npartial stdout\\n'; : > \"$PRINTED\"; read line")
        .env("PRINTED", &printed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fixture starts");
    let _held_stdin = child.stdin.take().expect("fixture stdin remains open");
    let mut ready = [0; 6];
    child
        .stdout
        .as_mut()
        .expect("fixture stdout")
        .read_exact(&mut ready)
        .expect("fixture readiness");
    assert_eq!(&ready, b"ready\n");
    let started = std::time::Instant::now();
    while !printed.exists() {
        assert!(
            started.elapsed() < FIXTURE_HANG_BOUND,
            "fixture did not record its partial output before the hang guard"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = kill_and_capture(child);
    assert_text_contains(&output.stdout, "partial stdout");
    assert_text_contains(&output.stderr, "partial stderr");
}

/// # Panics
/// Panics only if fixture setup, executable retry or readiness verification fails.
///
/// ´test:integration:fixture-readiness-retries-held-executable-writer´
#[test]
fn fixture_readiness_retries_held_executable_writer() {
    let f = Fixture::new();
    let stub = f.root.path().join("ssh");
    let mut writer = Some(fs::OpenOptions::new().write(true).open(&stub).unwrap());
    let mut retries = 0;
    let output = fixture_output_after_busy(
        Command::new(&stub)
            .arg("--fixture-ready")
            .env("FIXTURE", f.root.path()),
        || {
            retries += 1;
            drop(writer.take());
        },
    )
    .unwrap();
    assert!(retries > 0);
    assert_child_success(&output);
    assert_eq!(output.stdout, b"transport-ready\n");
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("config"),
            "Host alpha beta\n HostName fixture.invalid\n",
        )
        .unwrap();
        fs::write(root.path().join("keys"), "fixture host key\n").unwrap();
        let stub = root.path().join("ssh");
        // Materialize replies before the production client starts its clock.
        for (name, body) in [
            (
                "user",
                "user=fixture from=user file=message\n-- cursor: position-one\n",
            ),
            (
                "admin",
                "user=fixture from=admin file=message\n-- cursor: position-one\n",
            ),
            (
                "admin-and-user",
                "user=fixture from=admin file=message\nuser=fixture from=user file=message\n-- cursor: position-one\n",
            ),
            ("empty", "-- cursor: position-one\n"),
        ] {
            fs::write(root.path().join(format!("{name}.reply")), body).unwrap();
        }
        fs::write(
            root.path().join("bulk.reply"),
            format!(
                "from=user payload={}\n-- cursor: position-one\n",
                "x".repeat(1_048_576)
            ),
        )
        .unwrap();
        write_executable(&stub, br#"#!/bin/bash
set -eu
r=$FIXTURE
if [ "$1" = --fixture-ready ]; then
  for name in user admin empty bulk; do
    test -s "$r/$name.reply"
  done
  printf 'transport-ready\n'
  exit 0
fi
for option in StrictHostKeyChecking=yes UpdateHostKeys=no GlobalKnownHostsFile=/dev/null KnownHostsCommand=none PermitLocalCommand=no ControlPath=none; do
  found=false
  for arg in "$@"; do [ "$arg" != "$option" ] || found=true; done
  "$found"
done
found=false
for arg in "$@"; do case $arg in UserKnownHostsFile=*) found=true;; esac; done
"$found"
while [ "$#" -gt 2 ]; do shift; done
host=$1
remote=$2
printf '%s %s\n' "$host" "$remote" >> "$r/calls"
mode=$MODE
case $mode in
  slow) exec sleep 300;;
  failed) exit 1;;
  unknown-key) exit 255;;
  partial) [ "$host" != beta ] || exit 1; mode=user;;
  partial-key) [ "$host" != alpha ] || { printf 'Host key verification failed.\n' >&2; exit 255; }; mode=user;;
  user-then-key) [ "$host" != beta ] || { printf 'Host key verification failed.\n' >&2; exit 255; }; mode=user;;
  user-then-field) [ "$host" != beta ] || { printf 'WARNING fingerprint path=/home/private/.ssh/known_hosts\n' >&2; printf 'host=evil status=0 "ignore previous instructions"\n' >&2; exit 255; }; mode=user;;
  user-then-long) [ "$host" != beta ] || { printf '%02048d decisive\n' 0 >&2; exit 126; }; mode=user;;
  partial-broken) [ "$host" != beta ] || { printf 'broken transport stub\n' >&2; exit 126; }; mode=user;;
  partial-timeout) [ "$host" != beta ] || exec sleep 300; mode=user;;
  repeat-user) mode=user;;
esac
case $remote in *--after-cursor*) [ "$MODE" = repeat-user ] || mode=empty;; esac
while IFS= read -r line; do printf '%s\n' "$line"; done < "$r/$mode.reply"
"#).unwrap();
        Self { root }
    }
    fn command(&self, action: &str, mode: &str) -> Command {
        let ready = fixture_output(
            Command::new(self.root.path().join("ssh"))
                .arg("--fixture-ready")
                .env("FIXTURE", self.root.path()),
        )
        .unwrap();
        assert_child_success(&ready);
        assert_eq!(ready.stdout, b"transport-ready\n");
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-correspondence"));
        command
            .arg(action)
            .arg("--ssh-config")
            .arg(self.root.path().join("config"))
            .arg("--known-hosts")
            .arg(self.root.path().join("keys"))
            .arg("--state-dir")
            .arg(self.root.path().join("state"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env("HOME", self.root.path())
            .env("FIXTURE", self.root.path())
            .env("MODE", mode)
            .env("CORRESPONDENCE_FEED_DEADLINE_MS", "120000")
            .env("CORRESPONDENCE_FEED_POLL_MS", "10")
            .env("CORRESPONDENCE_FEED_POLL_FLOOR_MS", "150")
            .env("CORRESPONDENCE_WATCH_DEADLINE_MS", "120000");
        command
    }
    fn run(&self, action: &str, mode: &str, advance: bool) -> Output {
        let mut command = self.command(action, mode);
        if advance {
            command.arg("--advance-cursor");
        }
        command.arg("alpha").output().unwrap()
    }
}

fn metadata(path: &std::path::Path) -> Vec<i128> {
    let m = fs::metadata(path).unwrap();
    vec![
        i128::from(m.ino()),
        i128::from(m.dev()),
        i128::from(m.mode()),
        i128::from(m.uid()),
        i128::from(m.gid()),
        i128::from(m.len()),
        i128::from(m.atime()),
        i128::from(m.atime_nsec()),
        i128::from(m.mtime()),
        i128::from(m.mtime_nsec()),
        i128::from(m.ctime()),
        i128::from(m.ctime_nsec()),
    ]
}

/// ´test:integration:bare-reads-and-second-caller-preserve-and-resume-shared-cursor´
#[test]
fn bare_reads_and_second_caller_preserve_and_resume_shared_cursor() {
    let f = Fixture::new();
    assert_child_success(&f.run("poll", "user", false));
    assert!(!f.root.path().join("state").exists());
    assert_child_success(&f.run("watch", "user", false));
    assert!(!f.root.path().join("state").exists());
    assert_child_success(&f.run("poll", "user", true));
    let path = f.root.path().join("state/cursor-alpha");
    let before = metadata(&path);
    for action in ["poll", "watch"] {
        let output = f.run(action, "repeat-user", false);
        assert_child_success(&output);
        assert_eq!(before, metadata(&path));
        assert_text_contains(&output.stdout, "FEED-DURATION-MS ");
        assert_text_contains(&output.stdout, "file=message");
    }
    assert_eq!(fs::read(path).unwrap(), b"position-one");
    assert_text_contains(
        &fs::read(f.root.path().join("calls")).unwrap(),
        "--after-cursor 'position-one'",
    );
}

/// ´test:integration:failure-isolation-admin-publication-and-deadlines´
#[test]
fn failure_isolation_admin_publication_and_deadlines() {
    let f = Fixture::new();
    let output = f.run("watch", "admin-and-user", true);
    assert_child_success(&output);
    assert_text_contains(&output.stdout, "from=admin");
    let cursor = f.root.path().join("state/cursor-alpha");
    fs::write(f.root.path().join("state/cursor-beta"), "untouched").unwrap();
    let other = metadata(&f.root.path().join("state/cursor-beta"));
    assert_child_success(&f.run("poll", "repeat-user", true));
    assert_eq!(other, metadata(&f.root.path().join("state/cursor-beta")));
    assert_eq!(fs::read(&cursor).unwrap(), b"position-one");
    // Fresh alpha content ends the round after beta's failed transport is observed.
    fs::remove_file(&cursor).unwrap();
    let calls = f.root.path().join("calls");
    fs::remove_file(&calls).unwrap();
    let output = output_after_exit_event(
        f.command("poll", "partial")
            .env("CORRESPONDENCE_FEED_DEADLINE_MS", "120000")
            .args(["alpha", "beta"]),
        || {
            fs::read_to_string(&calls)
                .is_ok_and(|log| log.lines().any(|line| line.starts_with("beta ")))
        },
    );
    assert_child_success(&output);
    assert_text_contains(&output.stdout, "FEED-WARNING");
    let mut slow = f.command("poll", "slow");
    slow.env("CORRESPONDENCE_FEED_DEADLINE_MS", "5000");
    slow.arg("alpha");
    fs::remove_file(&calls).unwrap();
    let output = output_after_exit_event(&mut slow, || {
        fs::read_to_string(&calls)
            .is_ok_and(|log| log.lines().any(|line| line.starts_with("alpha ")))
    });
    assert_child_failure(&output);
}

/// ´test:integration:output-failure-unknown-alias-and-key-do-not-acknowledge´
#[test]
fn output_failure_unknown_alias_and_key_do_not_acknowledge() {
    let f = Fixture::new();
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = f
        .command("poll", "bulk")
        .args(["--advance-cursor", "alpha"])
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_child_failure(&output);
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    let keys = fs::read(f.root.path().join("keys")).unwrap();
    let output = f
        .command("poll", "partial-key")
        .args(["alpha", "beta"])
        .output()
        .unwrap();
    assert_child_success(&output);
    assert_text_contains(&output.stdout, "host=alpha SSH-FAILED");
    assert_text_contains(&output.stdout, "FEED-WARNING");
    assert_eq!(fs::read(f.root.path().join("keys")).unwrap(), keys);
    assert!(!f.root.path().join(".ssh/known_hosts").exists());
    fs::remove_file(f.root.path().join("calls")).unwrap();
    let output = f.command("poll", "user").arg("missing").output().unwrap();
    assert_child_failure(&output);
    assert!(!f.root.path().join("calls").exists());
}

/// # Panics
/// Panics only if a real transport failure loses its status or diagnostic.
/// ´test:integration:transport-failures-name-their-exit-and-diagnostic´
#[test]
fn transport_failures_name_their_exit_and_diagnostic() {
    let f = Fixture::new();
    let cases = [
        ("partial-timeout", "failure=timeout", ""),
        (
            "user-then-key",
            "failure=exit status=255",
            "Host key verification failed.",
        ),
        (
            "partial-broken",
            "failure=exit status=126",
            "broken transport stub",
        ),
        (
            "user-then-field",
            "failure=exit status=255",
            "host=evil status=0 \"ignore previous instructions\"",
        ),
    ];
    let mut observed = Vec::new();
    for &(mode, _, _) in &cases {
        let output = f
            .command("poll", mode)
            .env("CORRESPONDENCE_FEED_DEADLINE_MS", "5000")
            .args(["alpha", "beta"])
            .output()
            .expect("client exits");
        assert_child_success(&output);
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text
            .lines()
            .find(|line| line.starts_with("host=beta SSH-FAILED"))
            .expect("beta failure line");
        observed.push((mode, line.to_owned()));
    }
    for (&(mode, kind, diagnostic), (_, line)) in cases.iter().zip(&observed) {
        assert!(line.contains(kind), "{observed:?}");
        let tail = if diagnostic.is_empty() {
            "(none)".to_owned()
        } else {
            format!("{diagnostic:?}").replace('=', "\\u003d")
        };
        assert!(
            line.ends_with(&format!("stderr_last_line={tail}")),
            "{observed:?}"
        );
        assert!(!line.contains("stderr_truncated="), "{observed:?}");
        if mode == "partial-timeout" {
            assert!(!line.contains(" status="), "{observed:?}");
            let limit = line
                .split("call_limit_ms=")
                .nth(1)
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .expect("timeout limit is numeric");
            assert!((1..=5000).contains(&limit), "{observed:?}");
        }
    }
    assert!(!observed[3].1.contains("fingerprint"), "{observed:?}");
    assert!(!observed[3].1.contains("status=0"), "{observed:?}");

    let output = f
        .command("poll", "user-then-long")
        .args(["alpha", "beta"])
        .output()
        .expect("long diagnostic fixture exits");
    assert_child_success(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    let long_line = text
        .lines()
        .find(|line| line.starts_with("host=beta SSH-FAILED"))
        .expect("long diagnostic line");
    assert!(
        long_line.contains("stderr_truncated=true stderr_last_line="),
        "{long_line}"
    );
    assert!(long_line.ends_with('"'), "{long_line}");
    assert!(long_line.len() < 650, "{long_line}");

    write_executable(
        &f.root.path().join("timeout"),
        b"#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = beta ]; then kill -TERM \"$$\"; exit 99; fi\ndone\nexec /usr/bin/timeout \"$@\"\n",
    )
    .expect("signal fixture is executable");
    let output = f
        .command("poll", "user")
        .args(["alpha", "beta"])
        .output()
        .expect("signal fixture exits");
    assert_child_success(&output);
    assert_text_contains(
        &output.stdout,
        "host=beta SSH-FAILED failure=signal signal=SIGTERM stderr_last_line=(none)",
    );
}

/// ´test:integration:release-harness-keeps-all-correspondence-pins´
#[test]
fn release_harness_keeps_all_correspondence_pins() {
    let output = Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/run.sh"))
        .env(
            "CORRESPONDENCE_TEST_BINARY",
            env!("CARGO_BIN_EXE_superloop-correspondence"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_text_contains(&output.stdout, "PASS all 16 correspondence harness pins");
}

/// ´test:integration:empty-cursor-refuses-before-transport´
#[test]
fn empty_cursor_refuses_before_transport() {
    let f = Fixture::new();
    fs::create_dir(f.root.path().join("state")).unwrap();
    let path = f.root.path().join("state/cursor-alpha");
    fs::write(&path, []).unwrap();
    let before = metadata(&path);
    for action in ["poll", "watch"] {
        for advance in [false, true] {
            let output = f.run(action, "user", advance);
            assert_child_failure(&output);
            assert_text_contains(&output.stderr, &format!("empty cursor: {}", path.display()));
            assert_eq!(metadata(&path), before);
            assert!(!f.root.path().join("calls").exists());
        }
    }
}

/// # Panics
/// Panics only if fixture setup or lock, publication and recovery assertions fail.
/// ´test:integration:cursor-lock-contention-and-killed-holder-recovery´
#[test]
fn cursor_lock_contention_and_killed_holder_recovery() {
    let f = Fixture::new();
    fs::create_dir(f.root.path().join("state")).unwrap();
    let path = f.root.path().join("state/.cursor-alpha.lock");
    let mut holder = Command::new("python3").args(["-c", "import fcntl,sys; f=open(sys.argv[1],'w'); fcntl.flock(f,fcntl.LOCK_EX); print('x',flush=True); sys.stdin.read()"])
        .arg(&path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut byte = [0];
    holder.stdout.take().unwrap().read_exact(&mut byte).unwrap();
    let output = f.run("poll", "user", true);
    assert_child_failure(&output);
    assert_text_contains(&output.stderr, "cursor lock");
    assert!(!f.root.path().join("calls").exists());
    holder.kill().unwrap();
    holder.wait().unwrap();
    // Poller takes its guard before publishing and retains it through flush and
    // cursor save. Fix the pipe capacity before spawn: the bulk reply must not
    // fit, even after our prefix read, regardless of the host's pipe default.
    let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let capacity = nix::fcntl::fcntl(&read, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
    assert!(capacity > 0 && capacity < 1_048_576 - 1);
    let mut client = f
        .command("poll", "bulk")
        // Lock ordering is the subject; the client blocks in publication until it is killed below.
        .args(["--advance-cursor", "alpha"])
        .stdout(Stdio::from(write))
        .spawn()
        .unwrap();
    let mut pipe = fs::File::from(read);
    let expected = b"host=alpha from=user payload=";
    let mut prefix = vec![0; expected.len()];
    pipe.read_exact(&mut prefix).unwrap();
    assert!(usize::try_from(capacity).unwrap() < 1_048_576 - prefix.len());
    let file = fs::File::open(&path).unwrap();
    let held = match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
        Ok(guard) => {
            drop(guard);
            false
        }
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => true,
        Err((_, error)) => panic!("cursor lock probe: {error}"),
    };
    let contending = f.run("poll", "user", true);
    let inode = fs::metadata(&path).unwrap().ino();
    // Kill with publication still blocked: kernel cleanup must release the
    // lock even though no Rust destructor can run.
    client.kill().unwrap();
    client.wait().unwrap();
    assert_eq!(
        prefix, expected,
        "first publication must be the bulk payload"
    );
    assert!(
        held,
        "client did not retain the cursor lock during publication"
    );
    assert_child_failure(&contending);
    assert_text_contains(&contending.stderr, "cursor lock");
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    assert_child_success(&f.run("poll", "user", true));
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
}

/// ´test:integration:publication-is-visible-before-cursor-save´
#[test]
fn publication_is_visible_before_cursor_save() {
    let f = Fixture::new();
    let mut child = f
        .command("poll", "bulk")
        .args(["--advance-cursor", "alpha"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let mut first = [0];
    pipe.read_exact(&mut first).unwrap();
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_child_success_with_stdout(&output, &bytes);
    assert_text_contains(&bytes, "from=user");
    assert_eq!(
        fs::read(f.root.path().join("state/cursor-alpha")).unwrap(),
        b"position-one"
    );
}

/// ´test:integration:argument-validation-poll-floor-and-include-aliases´
#[test]
fn argument_validation_poll_floor_and_include_aliases() {
    let f = Fixture::new();
    for arguments in [
        vec![],
        vec![""],
        vec![" "],
        vec!["alpha", ""],
        vec!["alpha", "alpha"],
        vec!["-invalid"],
    ] {
        let output = f.command("poll", "user").args(arguments).output().unwrap();
        assert_child_failure(&output);
        assert!(!f.root.path().join("calls").exists());
    }
    for (variable, value) in [
        ("CORRESPONDENCE_FEED_DEADLINE_MS", "0"),
        ("CORRESPONDENCE_FEED_POLL_MS", "bad"),
        ("CORRESPONDENCE_WATCH_DEADLINE_MS", "0"),
    ] {
        let output = f
            .command("watch", "user")
            .env(variable, value)
            .arg("alpha")
            .output()
            .unwrap();
        assert_child_failure(&output);
    }
    let output = f
        .command("poll", "empty")
        .env("CORRESPONDENCE_FEED_DEADLINE_MS", "5")
        .arg("alpha")
        .output()
        .unwrap();
    assert_child_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).ends_with("FEED-EMPTY\n"));
    assert!(!f.root.path().join("calls").exists());
    fs::write(f.root.path().join("config"), "Include hosts-*\n").unwrap();
    fs::write(
        f.root.path().join("hosts-fixture"),
        "Host a* !absent\n HostName fixture.invalid\n",
    )
    .unwrap();
    let output = f.run("poll", "user", false);
    assert_child_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).ends_with("FEED-CONTENT\n"));
}

/// ´test:integration:usage-refuses-without-measuring-and-help-succeeds´
#[test]
fn usage_refuses_without_measuring_and_help_succeeds() {
    for args in [
        vec!["watch"],
        vec!["watch", "alpha"],
        vec!["watch", "--known-hosts", "fixture"],
        vec!["watch", "--known-hosts"],
        vec!["watch", "--unknown"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-correspondence"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ne!(output.stderr, [] as [u8; 0]);
        assert_text_omits(&output.stdout, "DURATION");
        assert_text_omits(&output.stderr, "DURATION");
    }
    for flag in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-correspondence"))
            .arg(flag)
            .output()
            .unwrap();
        assert_child_success(&output);
    }
}
