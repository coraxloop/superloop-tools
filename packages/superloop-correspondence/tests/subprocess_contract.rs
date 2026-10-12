use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::{Command, Output, Stdio};

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
                if started.elapsed() >= std::time::Duration::from_millis(500) {
                    return Err(std::io::Error::other(
                        "fixture-exec-busy: ETXTBSY exceeded readiness wall bound",
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
    assert!(output.status.success());
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
  slow) exec sleep 10;;
  failed) exit 1;;
  unknown-key) exit 255;;
  partial) [ "$host" != beta ] || exit 1; mode=user;;
esac
case $remote in *--after-cursor*) mode=empty;; esac
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
        assert!(ready.status.success(), "{ready:?}");
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
            .env("CORRESPONDENCE_FEED_DEADLINE_MS", "400")
            .env("CORRESPONDENCE_FEED_POLL_MS", "10")
            .env("CORRESPONDENCE_FEED_POLL_FLOOR_MS", "150")
            .env("CORRESPONDENCE_WATCH_DEADLINE_MS", "850");
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
    assert!(f.run("poll", "user", false).status.success());
    assert!(!f.root.path().join("state").exists());
    assert!(f.run("watch", "user", false).status.success());
    assert!(!f.root.path().join("state").exists());
    assert!(f.run("poll", "user", true).status.success());
    let path = f.root.path().join("state/cursor-alpha");
    let before = metadata(&path);
    for action in ["poll", "watch"] {
        let output = f.run(action, "user", false);
        assert_eq!(
            output.status.code(),
            Some(if action == "watch" { 2 } else { 0 })
        );
        assert_eq!(before, metadata(&path));
        assert!(String::from_utf8_lossy(&output.stdout).contains("FEED-DURATION-MS "));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("file=message"));
    }
    assert_eq!(fs::read(path).unwrap(), b"position-one");
    assert!(
        fs::read_to_string(f.root.path().join("calls"))
            .unwrap()
            .contains("--after-cursor 'position-one'")
    );
}

/// ´test:integration:failure-isolation-admin-publication-and-deadlines´
#[test]
fn failure_isolation_admin_publication_and_deadlines() {
    let f = Fixture::new();
    let output = f.run("watch", "admin", true);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("from=admin"));
    let cursor = f.root.path().join("state/cursor-alpha");
    let before = metadata(&cursor);
    assert!(!f.run("poll", "failed", true).status.success());
    assert_eq!(before, metadata(&cursor));
    fs::write(f.root.path().join("state/cursor-beta"), "untouched").unwrap();
    let other = metadata(&f.root.path().join("state/cursor-beta"));
    assert!(f.run("poll", "empty", true).status.success());
    assert_eq!(other, metadata(&f.root.path().join("state/cursor-beta")));
    let output = f
        .command("poll", "partial")
        .args(["alpha", "beta"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("FEED-WARNING"));
    let mut slow = f.command("poll", "slow");
    slow.arg("alpha");
    let start = std::time::Instant::now();
    assert!(!slow.output().unwrap().status.success());
    assert!(start.elapsed().as_secs() < 3);
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
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!output.success());
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    let keys = fs::read(f.root.path().join("keys")).unwrap();
    assert!(!f.run("poll", "unknown-key", false).status.success());
    assert_eq!(fs::read(f.root.path().join("keys")).unwrap(), keys);
    assert!(!f.root.path().join(".ssh/known_hosts").exists());
    fs::remove_file(f.root.path().join("calls")).unwrap();
    assert!(
        !f.command("poll", "user")
            .arg("missing")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!f.root.path().join("calls").exists());
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
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS all 22 correspondence harness pins")
    );
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
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains(&format!("empty cursor: {}", path.display()))
            );
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
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cursor lock"));
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
        // Lock ordering is the subject, not the fixture's 400 ms feed timeout.
        .env("CORRESPONDENCE_FEED_DEADLINE_MS", "30000")
        .args(["--advance-cursor", "alpha"])
        .stdout(Stdio::from(write))
        .spawn()
        .unwrap();
    let mut pipe = fs::File::from(read);
    let expected = b"host=alpha from=user payload=";
    let mut prefix = vec![0; expected.len()];
    pipe.read_exact(&mut prefix).unwrap();
    assert!(usize::try_from(capacity).unwrap() < 1_048_576 - prefix.len());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let held = loop {
        let file = fs::File::open(&path).unwrap();
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(guard) => drop(guard),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => break true,
            Err((_, error)) => panic!("cursor lock probe: {error}"),
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
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
    assert!(!contending.status.success());
    assert!(String::from_utf8_lossy(&contending.stderr).contains("cursor lock"));
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    assert!(f.run("poll", "user", true).status.success());
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
        .spawn()
        .unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let mut first = [0];
    pipe.read_exact(&mut first).unwrap();
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(String::from_utf8_lossy(&bytes).contains("from=user"));
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
        assert!(
            !f.command("poll", "user")
                .args(arguments)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!f.root.path().join("calls").exists());
    }
    for (variable, value) in [
        ("CORRESPONDENCE_FEED_DEADLINE_MS", "0"),
        ("CORRESPONDENCE_FEED_POLL_MS", "bad"),
        ("CORRESPONDENCE_WATCH_DEADLINE_MS", "0"),
    ] {
        assert!(
            !f.command("watch", "user")
                .env(variable, value)
                .arg("alpha")
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let output = f
        .command("poll", "empty")
        .env("CORRESPONDENCE_FEED_DEADLINE_MS", "5")
        .arg("alpha")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).ends_with("FEED-EMPTY\n"));
    assert!(!f.root.path().join("calls").exists());
    fs::write(f.root.path().join("config"), "Include hosts-*\n").unwrap();
    fs::write(
        f.root.path().join("hosts-fixture"),
        "Host a* !absent\n HostName fixture.invalid\n",
    )
    .unwrap();
    let output = f.run("poll", "user", false);
    assert!(output.status.success());
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
        assert_eq!(output.status.code(), Some(1));
        assert_ne!(output.stderr, [] as [u8; 0]);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("DURATION"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DURATION"));
    }
    for flag in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-correspondence"))
            .arg(flag)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
    }
}
