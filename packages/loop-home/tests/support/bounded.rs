//! Bounded subprocess ownership for namespace fixtures; never waits on inherited pipes forever.
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub struct Child {
    process: std::process::Child,
    deadline: Instant,
    name: String,
    finished: bool,
}

pub fn spawn(command: &mut Command, name: &str, limit: Duration) -> Result<Child, String> {
    let mut process = command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{name}: spawn: {error}"))?;
    let result = (|| {
        for fd in [
            process.stdout.as_ref().map(std::os::fd::AsFd::as_fd),
            process.stderr.as_ref().map(std::os::fd::AsFd::as_fd),
        ]
        .into_iter()
        .flatten()
        {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
            )
            .map_err(|error| format!("{name}: nonblocking output: {error}"))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        stop(&mut process, name);
        return Err(error);
    }
    Ok(Child {
        process,
        deadline: Instant::now() + limit,
        name: name.into(),
        finished: false,
    })
}

pub fn output(command: &mut Command, name: &str, limit: Duration) -> Result<Output, String> {
    spawn(command, name, limit)?.wait()
}

fn drain<R: std::io::Read>(pipe: &mut Option<R>, bytes: &mut Vec<u8>) -> Result<(), String> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0; 4096];
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                return Ok(());
            }
            Ok(count) => {
                if bytes.len() + count > 1_048_576 {
                    return Err("output exceeds 1 MiB".into());
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("read output: {error}")),
        }
    }
    Ok(())
}

impl Child {
    pub fn wait(mut self) -> Result<Output, String> {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        loop {
            drain(&mut self.process.stdout, &mut stdout)
                .and_then(|()| drain(&mut self.process.stderr, &mut stderr))
                .map_err(|error| format!("{}: {error}", self.name))?;
            // Do not reap while descendants may still hold the pipes: the child PID pins
            // its process-group identity until timeout cleanup has signalled the group.
            if self.process.stdout.is_none()
                && self.process.stderr.is_none()
                && let Some(status) = self
                    .process
                    .try_wait()
                    .map_err(|error| format!("{}: wait: {error}", self.name))?
            {
                self.finished = true;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            if Instant::now() >= self.deadline {
                return Err(format!(
                    "{}: fixture timeout; killing process group {}; stderr={}",
                    self.name,
                    self.process.id(),
                    String::from_utf8_lossy(&stderr)
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn stop(process: &mut std::process::Child, name: &str) {
    if let Ok(pid) = i32::try_from(process.id())
        && let Err(error) = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        )
        && error != nix::errno::Errno::ESRCH
    {
        let _reported = writeln!(
            std::io::stderr().lock(),
            "{name}: fixture process-group kill failed: {error}"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match process.try_wait() {
            Ok(Some(_)) => return,
            Err(error) => {
                let _reported = writeln!(
                    std::io::stderr().lock(),
                    "{name}: fixture reap failed: {error}"
                );
                return;
            }
            Ok(None) if Instant::now() >= deadline => {
                let _reported = writeln!(
                    std::io::stderr().lock(),
                    "{name}: fixture reap timed out; pid {} remains unmeasured",
                    process.id()
                );
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.finished {
            stop(&mut self.process, &self.name);
        }
    }
}

pub fn cleanup_failure(path: &std::path::Path, error: &str) {
    let _reported = writeln!(
        std::io::stderr().lock(),
        "fixture cleanup failed; retained {}: {error}",
        path.display()
    );
    assert!(std::thread::panicking(), "fixture cleanup failed: {error}");
}

pub trait CommandOutput {
    fn fixture_output(&mut self, name: &str, limit: Duration) -> Result<Output, String>;
    fn fixture_spawn(&mut self, name: &str, limit: Duration) -> Result<Child, String>;
}
impl CommandOutput for Command {
    fn fixture_output(&mut self, name: &str, limit: Duration) -> Result<Output, String> {
        output(self, name, limit)
    }
    fn fixture_spawn(&mut self, name: &str, limit: Duration) -> Result<Child, String> {
        spawn(self, name, limit)
    }
}

pub fn cleanup(path: &std::path::Path, result: Result<Output, String>) {
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => cleanup_failure(
            path,
            &format!(
                "{}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(error) => cleanup_failure(path, &error),
    }
}
#[cfg(test)]
mod tests {

    /// # Panics
    /// Panics unless deadlines reap the owned child and bound inherited output pipes.
    /// ´claim:loophome:fixture-deadlines-bound-child-and-pipe-waits´
    /// ´test:integration:deadlines-reap-children-and-bound-inherited-pipes´
    #[test]
    fn deadlines_reap_children_and_bound_inherited_pipes() {
        use super::*;
        fn python(script: &str) -> Command {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-I", "-c", script]);
            command
        }

        let child = spawn(
            &mut python("import time; time.sleep(30)"),
            "sleep",
            Duration::from_secs(1),
        )
        .expect("spawn sleeper");
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.process.id()).expect("pid"));
        let start = Instant::now();
        let error = child.wait().expect_err("sleep must time out");
        assert!(error.contains("sleep: fixture timeout"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(
            nix::sys::signal::kill(pid, None),
            Err(nix::errno::Errno::ESRCH)
        );
        let script = concat!(
            "import os,sys,time\n",
            "if os.fork() == 0:\n",
            " print('inherited pipe', file=sys.stderr, flush=True)\n",
            " time.sleep(30)\n",
            "else: os._exit(0)\n",
        );
        let start = Instant::now();
        let error = output(&mut python(script), "pipe", Duration::from_secs(2))
            .expect_err("descendant keeps pipes open after the parent exits");
        assert!(error.contains("pipe: fixture timeout"), "{error}");
        assert!(error.contains("inherited pipe"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(6));
    }

    /// # Panics
    /// Panics unless a failed cleanup is visible and makes an otherwise successful test fail.
    /// ´claim:loophome:fixture-cleanup-failure-is-visible´
    /// ´test:integration:cleanup-failure-is-visible´
    #[test]
    fn cleanup_failure_is_visible() {
        use super::*;
        const PHASE: &str = "LOOP_HOME_BOUNDED_CLEANUP_PROBE";
        if std::env::var_os(PHASE).is_some() {
            cleanup_failure(
                std::path::Path::new("parent-owned-fixture"),
                "injected cleanup failure",
            );
            return;
        }
        let mut command =
            Command::new(std::env::current_exe().expect("bounded fixture executable"));
        command
            .args([
                "mail::directory::tests::bounded::tests::cleanup_failure_is_visible",
                "--exact",
                "--nocapture",
            ])
            .env(PHASE, "1");
        let output = output(&mut command, "cleanup refusal", Duration::from_secs(10))
            .expect("bounded cleanup refusal");
        assert!(!output.status.success(), "cleanup failure cannot be silent");
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            report.contains(
                "fixture cleanup failed; retained parent-owned-fixture: injected cleanup failure"
            ),
            "{report}"
        );
        assert!(report.contains("1 failed"), "{report}");
    }
}
