use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// Every stub write and every test-side spawn holds this lock; a child spawned under it cannot inherit a descriptor opened after its fork, so the binary's own stub spawns need no serialization.
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

#[allow(dead_code)]
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

pub struct Harness {
    root: PathBuf,
    worktree: PathBuf,
    tools: PathBuf,
    git_log: PathBuf,
    index_path: PathBuf,
    ssh_argv: PathBuf,
    ssh_stdin: PathBuf,
    ssh_output: PathBuf,
}

impl Harness {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "superloop-gate-submit-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        let worktree = root.join("worktree");
        let git_dir = worktree.join(".git");
        let tools = root.join("bin");
        fs::create_dir_all(&git_dir).expect("create synthetic Git directory");
        fs::create_dir(&tools).expect("create fake-tool directory");
        fs::write(git_dir.join("index"), b"oracle-index-bytes\n")
            .expect("write synthetic real index");
        write_executable(
            &tools.join("git"),
            include_bytes!("../fixtures/stubs/git"),
            0o755,
        )
        .expect("write fake executable");
        write_executable(
            &tools.join("ssh"),
            include_bytes!("../fixtures/stubs/ssh"),
            0o755,
        )
        .expect("write fake executable");

        let ssh_output = root.join("ssh.output");
        fs::write(&ssh_output, []).expect("initialize SSH output");
        Self {
            git_log: root.join("git.log"),
            index_path: root.join("index.path"),
            ssh_argv: root.join("ssh.argv"),
            ssh_stdin: root.join("ssh.stdin"),
            ssh_output,
            root,
            worktree,
            tools,
        }
    }

    #[must_use]
    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    #[must_use]
    pub fn real_index(&self) -> PathBuf {
        self.worktree.join(".git/index")
    }

    pub fn set_ssh_result(&self, output: &[u8], status: u8) {
        fs::write(&self.ssh_output, output).expect("write fake SSH output");
        fs::write(self.root.join("ssh.status"), status.to_string()).expect("write fake SSH status");
    }

    pub fn remote_execution_command(&self) -> Command {
        write_executable(&self.tools.join("cargo"), b"#!/bin/sh\nif [ \"${SAMPLE_FAIL_TEST:-}\" = 1 ] && [ \"$1\" = test ]; then exit 1; fi\nexit 0\n", 0o755)
            .expect("write fake Cargo executable");
        let mut command = self.command();
        command.env("ORACLE_SSH_EXECUTE_SCRIPT", "1");
        command
    }

    pub fn remove_tool(&self, name: &str) {
        fs::remove_file(self.tools.join(name)).expect("remove selected fake tool");
    }

    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-gate-submit"));
        command
            .env_clear()
            .env("PATH", &self.tools)
            .env("TMPDIR", &self.root)
            .env("ORACLE_WORKTREE", &self.worktree)
            .env("ORACLE_GIT_LOG", &self.git_log)
            .env("ORACLE_INDEX_PATH", &self.index_path)
            .env("ORACLE_SSH_ARGV", &self.ssh_argv)
            .env("ORACLE_SSH_STDIN", &self.ssh_stdin)
            .env("ORACLE_SSH_OUTPUT", &self.ssh_output)
            .env("ORACLE_SSH_RC_FILE", self.root.join("ssh.status"))
            .env("LANE_VERIFY_SSH", "sagofink-orchestration")
            .env("LANE_VERIFY_CLONE", "/srv/orchestration-pack/worktree")
            .env(
                "LANE_VERIFY_REMOTE_RUNNER",
                "/srv/orchestration-pack/bin/run-report bash -s",
            )
            .env(
                "LANE_VERIFY_RUST_ENV",
                "/srv/orchestration-pack/env/rust.sh",
            );
        command
    }

    #[must_use]
    pub fn read(&self, role: &str) -> Vec<u8> {
        let path = match role {
            "git" => &self.git_log,
            "ssh-argv" => &self.ssh_argv,
            "ssh-stdin" => &self.ssh_stdin,
            _ => panic!("unknown harness role"),
        };
        match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("read harness record: {error}"),
        }
    }

    #[must_use]
    pub fn temporary_index_is_clean(&self) -> bool {
        let Ok(path) = fs::read_to_string(&self.index_path) else {
            return true;
        };
        !Path::new(&path).exists()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "remove isolated test directory: {error}"
            );
        }
    }
}

pub fn argument(path: &Path) -> &OsStr {
    path.as_os_str()
}
