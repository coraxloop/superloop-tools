use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::{Command, Stdio};

/// ´test:integration:existing-exporter-and-client-protocol-contracts´
#[test]
fn existing_exporter_and_client_protocol_contracts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("bash")
        .arg(root.join("tests/steward-run.sh"))
        .env(
            "STEWARD_TEST_BINARY",
            env!("CARGO_BIN_EXE_superloop-steward"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
                std::thread::yield_now();
            }
            Err(error) => return Err(error),
            Ok(child) => return child.wait_with_output(),
        }
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("config"),
            "Host alpha-steward beta-steward\n HostName fixture.invalid\n",
        )
        .unwrap();
        fs::write(root.path().join("keys"), "fixture host key\n").unwrap();
        fs::write(
            root.path().join("data"),
            b"{\"type\":\"user\",\"message\":\"first\"}\n",
        )
        .unwrap();
        let script = root.path().join("ssh");
        write_executable(&script, br#"#!/bin/bash
set -eu
export LC_ALL=C
r=$FIXTURE
if [ "$1" = --fixture-ready ]; then
  IFS= read -r listing < "$r/list.reply"
  printf '%s\n' "$listing"
  exec dd if="$r/data.reply" iflag=skip_bytes,count_bytes skip=0 count="${2:?}" status=none
fi
for option in StrictHostKeyChecking=yes UpdateHostKeys=no KnownHostsCommand=none ControlPath=none; do
  found=false
  for arg in "$@"; do [ "$arg" != "$option" ] || found=true; done
  "$found"
done
while [ "$#" -gt 1 ]; do shift; done
remote=$1
printf '%s\n' "$remote" >> "$r/calls"
read -r exporter verb relative offset count <<< "$remote"
if [ "${MODE:-}" = slow-list ] && [ "$verb" = list ]; then exec sleep 10; fi
case $verb in
  list)
    IFS= read -r listing < "$r/list.reply"
    printf '%s\n' "$listing"
    ;;
  read)
    [ "$relative" = "'project/session.jsonl'" ]
    exec dd if="$r/data.reply" iflag=skip_bytes,count_bytes skip="$offset" count="$count" status=none
    ;;
  *) exit 95;;
esac
"#).unwrap();
        Self { root }
    }
    fn command(&self, verb: &str, advance: bool) -> Command {
        // Snapshot and exercise both reply paths before the client starts its clock.
        let data = fs::read(self.root.path().join("data")).unwrap();
        let listing = format!("project/session.jsonl\t{}\t1:1\t1:1\n", data.len());
        fs::write(self.root.path().join("list.reply"), &listing).unwrap();
        fs::write(self.root.path().join("data.reply"), &data).unwrap();
        let ready = fixture_output(
            Command::new(self.root.path().join("ssh"))
                .arg("--fixture-ready")
                .arg(data.len().to_string())
                .env("FIXTURE", self.root.path()),
        )
        .unwrap();
        assert!(ready.status.success(), "{ready:?}");
        let mut expected = listing.into_bytes();
        expected.extend_from_slice(&data);
        assert_eq!(ready.stdout, expected);
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-steward"));
        command
            .args(["transcript", verb])
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
            .env("STEWARD_TRANSCRIPT_FEED_DEADLINE_MS", "4000")
            .env("STEWARD_TRANSCRIPT_READ_TIMEOUT_MS", "1000")
            .env("STEWARD_TRANSCRIPT_WATCH_DEADLINE_MS", "300")
            .env("STEWARD_TRANSCRIPT_WATCH_POLL_MS", "300");
        if advance {
            command.arg("--advance-cursor");
        }
        command.arg("alpha");
        command
    }
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
            let output = f.command(action, advance).output().unwrap();
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
    let output = f.command("poll", true).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cursor lock"));
    assert!(!f.root.path().join("calls").exists());
    holder.kill().unwrap();
    holder.wait().unwrap();
    fs::write(
        f.root.path().join("data"),
        format!("{{\"message\":\"{}\"}}\n", "x".repeat(1_048_576)),
    )
    .unwrap();
    let mut client = f
        .command("poll", true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = client.stdout.take().unwrap();
    pipe.read_exact(&mut byte).unwrap();
    assert!(!f.command("poll", true).output().unwrap().status.success());
    let inode = fs::metadata(&path).unwrap().ino();
    client.kill().unwrap();
    client.wait().unwrap();
    assert!(!f.root.path().join("state/cursor-alpha").exists());
    let output = f.command("poll", true).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
}

/// ´test:integration:watch-expiry-during-transport-is-quiet-but-early-failure-is-loud´
#[test]
fn watch_expiry_during_transport_is_quiet_but_early_failure_is_loud() {
    let f = Fixture::new();
    let output = f.command("poll", true).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let path = f.root.path().join("state/cursor-alpha");
    let before = metadata(&path);
    for advance in [false, true] {
        let output = f
            .command("watch", advance)
            .env("MODE", "slow-list")
            .env("STEWARD_TRANSCRIPT_WATCH_DEADLINE_MS", "150")
            .env("STEWARD_TRANSCRIPT_READ_TIMEOUT_MS", "1000")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.starts_with("STEWARD-TRANSCRIPT-DURATION-MS "));
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert_eq!(metadata(&path), before);
    }
    let output = f
        .command("watch", false)
        .env("MODE", "slow-list")
        .env("STEWARD_TRANSCRIPT_WATCH_DEADLINE_MS", "2000")
        .env("STEWARD_TRANSCRIPT_READ_TIMEOUT_MS", "50")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("STEWARD-TRANSCRIPT-FAILED list server=alpha status=124")
    );
    assert_eq!(metadata(&path), before);
}

fn metadata(path: &std::path::Path) -> Vec<i128> {
    let m = fs::metadata(path).unwrap();
    vec![
        i128::from(m.ino()),
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

/// ´test:integration:bare-inspection-and-advancing-second-caller´
#[test]
fn bare_inspection_and_advancing_second_caller() {
    let f = Fixture::new();
    for verb in ["poll", "watch"] {
        let output = f.command(verb, false).output().unwrap();
        assert!(
            matches!(output.status.code(), Some(0))
                || (verb == "watch" && output.status.code() == Some(2)),
            "{verb}: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!f.root.path().join("state").exists());
    }
    let output = f.command("poll", true).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let path = f.root.path().join("state/cursor-alpha");
    let before = metadata(&path);
    for verb in ["poll", "watch"] {
        let output = f.command(verb, false).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if verb == "watch" { 2 } else { 0 })
        );
        assert_eq!(metadata(&path), before);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("STEWARD-TRANSCRIPT-DURATION-MS ")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("first"));
    }
    let mut data = fs::read(f.root.path().join("data")).unwrap();
    data.extend_from_slice(b"{\"message\":\"second\"}\npartial");
    fs::write(f.root.path().join("data"), data).unwrap();
    fs::write(f.root.path().join("state/cursor-beta"), "unrelated").unwrap();
    let other = metadata(&f.root.path().join("state/cursor-beta"));
    let output = f.command("poll", true).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("second"));
    assert!(!text.contains("first"));
    assert!(!text.contains("partial"));
    assert_eq!(metadata(&f.root.path().join("state/cursor-beta")), other);
}

/// ´test:integration:blocked-publication-and-failed-output-never-acknowledge´
#[test]
fn blocked_publication_and_failed_output_never_acknowledge() {
    let f = Fixture::new();
    let data = format!("{{\"message\":\"{}\"}}\n", "x".repeat(1_048_576));
    fs::write(f.root.path().join("data"), data).unwrap();
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    assert!(
        !f.command("poll", true)
            .stdout(full)
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let cursor = f.root.path().join("state/cursor-alpha");
    assert!(!cursor.exists());
    let mut child = f
        .command("poll", true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let mut first = [0];
    pipe.read_exact(&mut first).unwrap();
    assert!(!cursor.exists());
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(cursor.exists());
    assert!(bytes.len() > 1_048_576);
}

/// ´test:integration:usage-refuses-without-measuring-and-help-succeeds´
#[test]
fn usage_refuses_without_measuring_and_help_succeeds() {
    for args in [
        vec!["transcript", "watch"],
        vec!["transcript", "watch", "alpha"],
        vec!["transcript", "watch", "--known-hosts", "fixture"],
        vec!["transcript", "watch", "--known-hosts"],
        vec!["transcript", "watch", "--unknown"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-steward"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_ne!(output.stderr, [] as [u8; 0]);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("DURATION"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DURATION"));
    }
    for flag in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-steward"))
            .arg(flag)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
    }
}
