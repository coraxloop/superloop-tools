use std::env;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const DEADLINE: Duration = Duration::from_secs(5);

fn entry(home: &Path) -> PathBuf {
    let deployed = home.join(".local/bin/superloop");
    if !matches!(fs::metadata(&deployed), Err(error) if error.kind() == io::ErrorKind::NotFound) {
        return deployed;
    }
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join("superloop"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .unwrap_or(deployed)
}

/// Inspect inbox presence through an ordinary shell under the public loop entry.
///
/// # Errors
/// Returns a named failure when the entry cannot run or complete its listing.
pub fn run(home: &Path, loop_name: &str, inbox: &Path) -> Result<Output, String> {
    let path = entry(home);
    let started = Instant::now();
    // Inherit the hook's cwd. A distinct process group contains the entry chain.
    let mut child = Command::new(&path)
        .args(["enter", loop_name, "--", "/bin/sh", "-c",
            "for entry in \"$1\"/* \"$1\"/.[!.]* \"$1\"/..?*; do if [ -e \"$entry\" ] || [ -L \"$entry\" ]; then printf '1\\n'; exit; fi; done",
            "mail-notice"])
        .arg(inbox)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("entry unavailable: {}: {error}", path.display()))?;
    let result = collect(&mut child, started);
    if result.is_err() {
        let _killed = killpg(Pid::from_raw(child.id().cast_signed()), Signal::SIGKILL);
        let _reaped = child.wait();
    }
    let output = result.map_err(|error| format!("{error}; entry={}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "follower failed loop={loop_name} entry={} status={} detail={}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn collect(child: &mut Child, started: Instant) -> Result<Output, String> {
    let mut stdout = child.stdout.take().ok_or("listing stdout unavailable")?;
    let mut stderr = child.stderr.take().ok_or("listing stderr unavailable")?;
    for result in [
        fcntl(&stdout, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)),
        fcntl(&stderr, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)),
    ] {
        result.map_err(|error| format!("listing pipe failed: {error}"))?;
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_done = false;
    let mut err_done = false;
    loop {
        if started.elapsed() >= DEADLINE {
            return Err("listing timed out after 5 s".to_owned());
        }
        let previous = out.len() + err.len();
        out_done |= read_chunk(&mut stdout, &mut out)?;
        err_done |= read_chunk(&mut stderr, &mut err)?;
        if out_done && err_done {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("listing wait failed: {error}"))?
            {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            thread::sleep(Duration::from_millis(10));
        } else if previous == out.len() + err.len() {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn read_chunk(reader: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool, String> {
    let mut buffer = [0; 8192];
    match reader.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(size) => {
            if bytes.len() + size > 8192 {
                return Err("inbox presence output exceeds its bound".into());
            }
            bytes.extend_from_slice(&buffer[..size]);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(format!("listing pipe failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::waitpid;

    /// ´test:unit:letters-listing-refuses-unavailable-child-pipes´
    #[test]
    fn letters_listing_refuses_unavailable_child_pipes() {
        for missing_stdout in [true, false] {
            let mut command = Command::new("/bin/true");
            command.stderr(Stdio::null());
            if !missing_stdout {
                command.stdout(Stdio::piped());
            }
            let mut child = command.spawn().expect("child");
            let error = collect(&mut child, Instant::now()).expect_err("missing pipe");
            child.wait().expect("reap child");
            assert_eq!(
                error,
                if missing_stdout {
                    "listing stdout unavailable"
                } else {
                    "listing stderr unavailable"
                }
            );
        }
    }

    /// ´test:unit:letters-listing-pipe-read-errors-are-named-and-retryable-reads-wait´
    #[test]
    fn letters_listing_pipe_read_errors_are_named_and_retryable_reads_wait() {
        struct FailedRead(io::ErrorKind);
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "fixture pipe"))
            }
        }
        let mut bytes = Vec::new();
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            assert!(!read_chunk(&mut FailedRead(kind), &mut bytes).expect("retry"));
        }
        let error = read_chunk(&mut FailedRead(io::ErrorKind::BrokenPipe), &mut bytes)
            .expect_err("pipe failure");
        assert_eq!(error, "listing pipe failed: fixture pipe");
        assert_eq!(bytes, [] as [u8; 0]);
    }

    /// ´test:unit:letters-listing-child-wait-failure-is-named´
    #[test]
    fn letters_listing_child_wait_failure_is_named() {
        let mut child = Command::new("/bin/true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("child");
        waitpid(Pid::from_raw(child.id().cast_signed()), None).expect("external reap");
        let error = collect(&mut child, Instant::now()).expect_err("already reaped");
        assert!(error.starts_with("listing wait failed:"));
    }
}
