#[path = "../../support/temporary_root.rs"]
mod temporary_root;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

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
    repo: PathBuf,
    worktree: PathBuf,
    home: PathBuf,
    tools: PathBuf,
    argv: PathBuf,
    stdin: PathBuf,
    cwd: PathBuf,
    codex_home: PathBuf,
}

impl Harness {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = temporary_root::temporary_root().join(format!(
            "codex-lane-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let worktree = repo.join("worktree");
        let home = root.join("home");
        let tools = root.join("bin");
        fs::create_dir_all(&worktree).expect("create synthetic worktree");
        fs::create_dir_all(home.join(".codex")).expect("create synthetic Codex home");
        fs::create_dir(&tools).expect("create fake-tool directory");
        fs::write(home.join(".codex/auth.json"), b"oracle-auth\n").expect("write synthetic auth");
        write_executable(
            &tools.join("codex"),
            include_bytes!("../fixtures/stubs/codex"),
            0o755,
        )
        .expect("write fake executable");
        Self {
            argv: root.join("argv"),
            stdin: root.join("stdin"),
            cwd: root.join("cwd"),
            codex_home: root.join("codex-home"),
            root,
            repo,
            worktree,
            home,
            tools,
        }
    }

    #[must_use]
    pub fn command(&self) -> Command {
        self.command_at(Path::new(env!("CARGO_BIN_EXE_superloop-lane")))
    }

    pub fn resume_command(&self) -> Command {
        let command = self.command();
        self.command_for(Path::new(command.get_program()), "resume")
    }

    pub fn command_at(&self, driver: &Path) -> Command {
        self.command_for(driver, "start")
    }

    pub fn configure_boxed(command: &mut Command) {
        command
            .env_remove("CODEX_HOME")
            .env("LANE_BOXED_RUNTIME", "1");
    }

    fn command_for(&self, driver: &Path, action: &str) -> Command {
        let mut command = Command::new(driver);
        command.args(["driver", action, "--backend", "codex"]);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("CODEX_HOME", self.home.join(".codex"))
            .env("LANE_DRIVER_ARGV", serde_json::json!([driver]).to_string())
            .env("LANE_BACKEND_ARGV", serde_json::json!({"codex": [self.tools.join("codex")]}).to_string())
            .env("LANE_SETTINGS_EVIDENCE", serde_json::json!({"path":self.root.join("workers.toml"),"driver_argv":[driver],"backend_argv":{"codex":[self.tools.join("codex")]}}).to_string())
            .env("LANE_RUNS_ROOT", self.repo.join("runs"))
            .env("CODEX_LANE_TEST_UTC_STAMP", "20260828T120000Z")
            .env("CODEX_LANE_TEST_CLOCK", "0")
            .env("ORACLE_ARGV", &self.argv)
            .env("ORACLE_STDIN", &self.stdin)
            .env("ORACLE_CWD", &self.cwd)
            .env("ORACLE_CODEX_HOME", &self.codex_home)
            .env("ORACLE_MODE", "normal")
            .env("ORACLE_EXIT", "1")
            .env("ORACLE_RELEASE", self.root.join("release"))
            .env("ORACLE_ACK", self.root.join("ack"))
            .current_dir(&self.repo);
        command
    }

    pub fn configure_backend(&self, command: &mut Command, program: &Path) {
        let driver = Path::new(command.get_program());
        let driver_argv = serde_json::json!([driver]);
        let backend_argv = serde_json::json!({"codex":[program]});
        let evidence = serde_json::json!({"path":self.root.join("workers.toml"),"driver_argv":driver_argv,"backend_argv":backend_argv});
        command
            .env("LANE_DRIVER_ARGV", driver_argv.to_string())
            .env("LANE_BACKEND_ARGV", backend_argv.to_string())
            .env("LANE_SETTINGS_EVIDENCE", evidence.to_string());
    }

    #[must_use]
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    #[must_use]
    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[allow(dead_code)]
    pub fn seed_gateway(&self, audit_result: bool) -> PathBuf {
        let state = self.root.join("gateway");
        for directory in [
            state.join("registrations"),
            state.join("execution-budgets/gw"),
            state.join("proposal-verdicts/gw"),
            state.join("audit"),
        ] {
            fs::create_dir_all(directory).expect("create gateway fixture directory");
        }
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after the epoch")
                .as_millis(),
        )
        .expect("current unix millisecond fits u64");
        fs::write(
            state.join("registrations/gw.toml"),
            format!("worktree = \"{}\"\n", self.worktree.display()),
        )
        .expect("write gateway registration");
        fs::write(
            state.join("execution-budgets/gw/7.json"),
            format!(
                "{{\"schema\":1,\"lane\":\"gw\",\"seq\":7,\"argv\":[\"true\"],\"reason\":\"r\",\"queued_unix_ms\":{now},\"timeout_seconds\":3600}}"
            ),
        )
        .expect("write gateway proposal");
        fs::write(
            state.join("proposal-verdicts/gw/7.json"),
            format!(
                "{{\"schema\":1,\"actor\":\"orchestrator\",\"verdict\":{{\"seq\":7,\"decision\":\"approved\",\"wall_millis\":1}},\"resolved_unix_ms\":{now}}}"
            ),
        )
        .expect("write gateway verdict");
        let audit = if audit_result {
            format!(
                "{{\"schema\":2,\"timestamp_unix_ms\":{now},\"event\":{{\"kind\":\"result\",\"result\":{{\"seq\":7,\"operation\":\"run\",\"exit_code\":0,\"verdict\":\"ok\"}}}}}}\n"
            )
        } else {
            String::new()
        };
        fs::write(state.join("audit/gw.jsonl"), audit).expect("write gateway audit");
        state
    }

    #[must_use]
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.repo
            .join("runs")
            .join(format!("20260828T120000Z-{name}"))
    }

    pub fn run(&self, arguments: &[&OsStr]) -> Output {
        let action = if arguments.iter().any(|word| *word == OsStr::new("-r")) {
            "resume"
        } else {
            "start"
        };
        self.command_for(Path::new(env!("CARGO_BIN_EXE_superloop-lane")), action)
            .args(arguments)
            .output_serialized()
            .expect("codex-lane subprocess runs")
    }

    #[must_use]
    pub fn read(&self, role: &str) -> Vec<u8> {
        let path = match role {
            "argv" => &self.argv,
            "stdin" => &self.stdin,
            "cwd" => &self.cwd,
            "codex-home" => &self.codex_home,
            _ => panic!("unknown harness role"),
        };
        read_if_present(path)
    }

    pub fn seed_resume(&self, name: &str, offset: &[u8]) -> PathBuf {
        let run_dir = self.root.join(name);
        fs::create_dir(&run_dir).expect("create resume run directory");
        fs::write(
            run_dir.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"session-1\"}\n",
        )
        .expect("seed prior events");
        fs::write(run_dir.join("last-message.txt"), b"first").expect("seed prior message");
        fs::write(
            run_dir.join("run-report.txt"),
            format!(
                "RUN-REPORT lane=gate exit=0 wall=0s budget=60s verdict=ok dir={}\n",
                run_dir.display()
            ),
        )
        .expect("seed prior report");
        fs::write(run_dir.join(".step-name"), b"gate\n").expect("seed prior step name");
        fs::write(run_dir.join(".event-start"), b"0\n").expect("seed prior start");
        fs::write(run_dir.join(".feed-offset"), offset).expect("seed follower offset");
        run_dir
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

pub fn read_if_present(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read harness record: {error}"),
    }
}

pub fn argument(path: &Path) -> &OsStr {
    path.as_os_str()
}
