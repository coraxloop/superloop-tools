use std::io;
use std::process::{Child, Command};

#[cfg(test)]
use std::process::{Output, Stdio};

#[cfg(test)]
pub struct SharedLauncher(Child);

#[cfg(test)]
impl SharedLauncher {
    pub fn start(config: &std::path::Path) -> Self {
        use std::io::{BufRead as _, Read as _};
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "fixture_exec::tests::shared_configuration_holder",
                "--nocapture",
            ])
            .env("SUPERLOOP_CONFIGURATION_HOLDER", config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("launcher fixture");
        let output = child.stdout.take().expect("ready output");
        let mut holder = Self(child);
        let mut reader = std::io::BufReader::new(output);
        let mut ready = false;
        for line in reader.by_ref().lines() {
            if line.expect("ready line").contains("configuration-held") {
                ready = true;
                break;
            }
        }
        holder.0.stdout = Some(reader.into_inner());
        assert!(ready, "launcher acquired its shared configuration lock");
        holder
    }

    pub fn identity(&self) -> (u32, u64) {
        let pid = self.0.id();
        (
            pid,
            crate::container_helper::process_start(pid).expect("launcher start"),
        )
    }
}

#[cfg(test)]
impl Drop for SharedLauncher {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _status = self.0.wait();
    }
}

#[cfg(test)]
pub fn fixture_socket_path(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let path = path.as_ref();
    let length = path.as_os_str().as_encoded_bytes().len();
    assert!(
        length < 108,
        "fixture TMPDIR socket path is {length} bytes; must be shorter than 108 bytes"
    );
    path.to_path_buf()
}

/// Spawn one child, retrying transient fixture script collisions in test builds.
///
/// # Errors
///
/// Returns the spawn error when it is not `ETXTBSY` or the retry bound is reached.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    #[cfg(not(test))]
    {
        command.spawn()
    }
    #[cfg(test)]
    {
        spawn_with_retry(command, std::time::Duration::from_millis(500), || {
            std::thread::sleep(std::time::Duration::from_millis(2));
        })
    }
}

#[cfg(test)]
/// Capture a fixture command after the bounded executable retry.
///
/// # Errors
///
/// Returns a spawn, wait, or bounded busy refusal.
pub fn output(command: &mut Command) -> io::Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn(command)?.wait_with_output()
}

/// Finish and close a fixture executable before any caller starts it.
///
/// # Errors
///
/// Returns a write, sync, or mode-setting failure.
pub fn write_executable(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut writer = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open(path)?;
    writer.write_all(bytes)?;
    writer.sync_all()?;
    drop(writer);
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
fn spawn_with_retry(
    command: &mut Command,
    limit: std::time::Duration,
    mut after_busy: impl FnMut(),
) -> io::Result<Child> {
    let started = std::time::Instant::now();
    loop {
        match command.spawn() {
            Err(error) if error.raw_os_error() == Some(nix::libc::ETXTBSY) => {
                if started.elapsed() >= limit {
                    return Err(io::Error::other(
                        "fixture-exec-busy: ETXTBSY exceeded wall bound",
                    ));
                }
                after_busy();
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::spawn_with_retry;
    use std::fs::{self, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    /// ´test:unit:shared-configuration-holder´
    #[test]
    fn shared_configuration_holder() {
        let Some(config) = std::env::var_os("SUPERLOOP_CONFIGURATION_HOLDER") else {
            return;
        };
        let _hold = crate::install::lock_loop_config(std::path::Path::new(&config), true)
            .expect("shared launcher hold");
        writeln!(std::io::stdout(), "configuration-held").expect("ready");
        let _end = std::io::stdin().read(&mut [0_u8; 1]).expect("release");
    }

    /// ´test:unit:fixture-spawn-retries-only-text-file-busy´
    #[test]
    fn fixture_spawn_retries_only_text_file_busy() {
        let Some(marker) = std::env::var_os("SUPERLOOP_HELD_WRITER_CASE") else {
            let fixture = tempfile::TempDir::new_in("/tmp").expect("isolated case");
            let marker = fixture.path().join("completed");
            let output = Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "fixture_exec::tests::fixture_spawn_retries_only_text_file_busy",
                ])
                .env("SUPERLOOP_HELD_WRITER_CASE", &marker)
                .output()
                .expect("isolated test process");
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read(marker).expect("isolated test ran"), b"done");
            return;
        };
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let program = fixture.path().join("stand-in");
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&program)
            .expect("writer");
        writer.write_all(b"#!/bin/sh\nexit 0\n").expect("script");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("mode");
        let mut held_writer = Some(writer);
        let mut command = Command::new(&program);
        let mut retries = 0;
        let mut child =
            spawn_with_retry(&mut command, std::time::Duration::from_millis(50), || {
                retries += 1;
                drop(held_writer.take());
            })
            .expect("text file busy is transient");
        assert!(child.wait().expect("child status").success());
        assert_eq!(retries, 1);
        let mut missing = Command::new(fixture.path().join("absent"));
        assert_eq!(
            spawn_with_retry(&mut missing, std::time::Duration::from_millis(50), || {
                panic!("other errors must not retry");
            })
            .expect_err("other spawn errors are returned")
            .kind(),
            std::io::ErrorKind::NotFound
        );
        fs::write(marker, b"done").expect("isolated case completed");
    }

    /// ´test:unit:fixture-exec-fork-during-write-is-bounded´
    #[test]
    #[allow(unsafe_code)]
    fn fixture_exec_fork_during_write_is_bounded() {
        if std::env::var_os("SUPERLOOP_FORKED_WRITER_CASE").is_none() {
            let output = Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "fixture_exec::tests::fixture_exec_fork_during_write_is_bounded",
                    "--test-threads=1",
                ])
                .env("SUPERLOOP_FORKED_WRITER_CASE", "1")
                .output()
                .expect("isolated test process");
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let program = fixture.path().join("stand-in");
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(nix::libc::O_CLOEXEC)
            .open(&program)
            .expect("close-on-exec writer");
        let (mut parent, child) = UnixStream::pair().expect("fork handoff");
        let child_fd = child.as_raw_fd();
        // SAFETY: the forked child uses only async-signal-safe syscalls before exec.
        let pid = unsafe { nix::libc::fork() };
        assert!(pid >= 0, "forked writer");
        if pid == 0 {
            let mut signal = [0_u8; 1];
            // SAFETY: both descriptors and the static executable pathname are valid here.
            unsafe {
                let _ready = nix::libc::write(child_fd, b"r".as_ptr().cast(), 1);
                let _released = nix::libc::read(child_fd, signal.as_mut_ptr().cast(), 1);
                let executable = c"/bin/sh";
                let _exec = nix::libc::execl(
                    executable.as_ptr(),
                    executable.as_ptr(),
                    c"-c".as_ptr(),
                    c":".as_ptr(),
                    std::ptr::null::<nix::libc::c_char>(),
                );
                nix::libc::_exit(127);
            }
        }
        drop(child);
        parent
            .read_exact(&mut [0_u8; 1])
            .expect("child holds writer");
        writer
            .write_all(b"#!/bin/sh\nexit 0\n")
            .expect("script written after fork");
        writer.sync_all().expect("script synced");
        drop(writer);
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("script mode");

        let error = spawn_with_retry(
            &mut Command::new(&program),
            std::time::Duration::from_millis(15),
            || std::thread::sleep(std::time::Duration::from_millis(2)),
        )
        .expect_err("inherited writer keeps exec busy");
        assert_eq!(
            error.to_string(),
            "fixture-exec-busy: ETXTBSY exceeded wall bound"
        );
        let mut released = false;
        let mut child = spawn_with_retry(
            &mut Command::new(&program),
            std::time::Duration::from_millis(500),
            || {
                if !released {
                    parent.write_all(b"x").expect("release forked child");
                    let mut status = 0;
                    // SAFETY: pid names this fixture's child and status is writable.
                    let waited = unsafe { nix::libc::waitpid(pid, &raw mut status, 0) };
                    assert_eq!(waited, pid);
                    assert_eq!(status, 0);
                    released = true;
                }
            },
        )
        .expect("retry after inherited writer closes");
        assert!(released);
        assert!(child.wait().expect("script status").success());
    }
}
