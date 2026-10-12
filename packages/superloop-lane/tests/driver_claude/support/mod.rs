#[path = "../../support/temporary_root.rs"]
mod temporary_root;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

pub struct FixtureChild {
    child: Option<Child>,
    group: nix::unistd::Pid,
}

impl std::ops::Deref for FixtureChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        self.child.as_ref().expect("fixture child is still owned")
    }
}

impl std::ops::DerefMut for FixtureChild {
    fn deref_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("fixture child is still owned")
    }
}

impl FixtureChild {
    pub fn wait_with_output(mut self) -> std::io::Result<Output> {
        self.child
            .take()
            .expect("fixture child is still owned")
            .wait_with_output()
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        use nix::sys::signal::{Signal, killpg};
        let _ = killpg(self.group, Signal::SIGTERM);
        if let Some(child) = &mut self.child {
            let deadline = Instant::now() + Duration::from_secs(2);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let _ = killpg(self.group, Signal::SIGKILL);
        if let Some(child) = &mut self.child {
            let _reaped = child.wait();
        }
    }
}

pub fn spawn_serialized(command: &mut Command) -> std::io::Result<FixtureChild> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let child = command.process_group(0).spawn()?;
    let group = nix::unistd::Pid::from_raw(child.id().cast_signed());
    Ok(FixtureChild {
        child: Some(child),
        group,
    })
}

#[allow(dead_code)]
pub trait SerializedCommand {
    fn spawn_serialized(&mut self) -> std::io::Result<FixtureChild>;
    fn output_serialized(&mut self) -> std::io::Result<Output>;
    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output>;
    fn status_serialized(&mut self) -> std::io::Result<ExitStatus>;
}

impl SerializedCommand for Command {
    fn spawn_serialized(&mut self) -> std::io::Result<FixtureChild> {
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
    temporary_root: PathBuf,
    root: PathBuf,
    repo: PathBuf,
    worktree: PathBuf,
    home: PathBuf,
    config: PathBuf,
    argv: PathBuf,
    stdin: PathBuf,
    cwd: PathBuf,
    environment: PathBuf,
}

impl Harness {
    #[must_use]
    /// # Panics
    /// Panics if TMPDIR is unset, inaccessible or resolves under /tmp, or fixture creation fails.
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let temporary_root = temporary_root::temporary_root();
        let root = temporary_root.join(format!(
            "claude-lane-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let worktree = repo.join("worktree");
        let home = root.join("home");
        let config = home.join(".config/loops/alpha/claude");
        let tools = root.join("bin");
        fs::create_dir_all(&worktree).expect("create synthetic worktree");
        fs::create_dir_all(&home).expect("create synthetic home");
        fs::create_dir_all(&config).expect("create synthetic Claude config");
        let runs = repo.join("runs");
        fs::write(home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"{}\" }}]\n", runs.display())).expect("registry");
        fs::create_dir(&tools).expect("create fake-tool directory");
        fs::write(config.join(".credentials.json"), b"oracle-credentials\n")
            .expect("write synthetic credentials");
        write_executable(
            &tools.join("claude"),
            include_bytes!("../fixtures/stubs/claude"),
            0o755,
        )
        .expect("write fake executable");
        Self {
            temporary_root,
            argv: root.join("argv"),
            stdin: root.join("stdin"),
            cwd: root.join("cwd"),
            environment: root.join("environment"),
            root,
            repo,
            worktree,
            home,
            config,
        }
    }

    #[must_use]
    pub fn command(&self) -> Command {
        self.command_at(Path::new(env!("CARGO_BIN_EXE_superloop-lane")))
    }

    pub fn command_at(&self, driver: &Path) -> Command {
        self.command_for(driver, "start")
    }

    fn command_for(&self, driver: &Path, action: &str) -> Command {
        let mut command = Command::new(driver);
        command.args(["driver", action, "--backend", "claude"]);
        command
            .env_clear()
            .env("TMPDIR", &self.temporary_root)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("CLAUDE_CONFIG_DIR", &self.config)
            .env("LANE_DRIVER_ARGV", serde_json::json!([driver]).to_string())
            .env("LANE_BACKEND_ARGV", serde_json::json!({"claude": [self.root.join("bin/claude")]}).to_string())
            .env("LANE_SETTINGS_EVIDENCE", serde_json::json!({"path":self.root.join("workers.toml"),"driver_argv":[driver],"backend_argv":{"claude":[self.root.join("bin/claude")]}}).to_string())
            .env("CLAUDECODE", "outer-session")
            .env("CLAUDE_CODE_ENTRYPOINT", "outer-entry")
            .env("LANE_RUNS_ROOT", self.repo.join("runs"))
            .env("CODEX_LANE_TEST_UTC_STAMP", "20260912T120000Z")
            .env("CODEX_LANE_TEST_CLOCK", "0")
            .env("ORACLE_ARGV", &self.argv)
            .env("ORACLE_STDIN", &self.stdin)
            .env("ORACLE_CWD", &self.cwd)
            .env("ORACLE_ENV", &self.environment)
            .env("ORACLE_MODE", "normal")
            .env("ORACLE_RESETS_AT", "1789820400")
            .current_dir(&self.repo);
        command
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
            .expect("claude-lane subprocess runs")
    }

    #[must_use]
    pub fn worktree(&self) -> &Path {
        &self.worktree
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
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// # Panics
    /// Panics only if the fixture registry cannot be written.
    pub fn register_runs(&self, root: &Path) {
        fs::write(self.home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"{}\" }}]\n", root.display())).expect("registry");
    }

    #[must_use]
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.repo
            .join("runs")
            .join(format!("20260912T120000Z-{name}"))
    }

    #[must_use]
    pub fn read(&self, role: &str) -> Vec<u8> {
        let path = match role {
            "argv" => &self.argv,
            "stdin" => &self.stdin,
            "cwd" => &self.cwd,
            "environment" => &self.environment,
            _ => panic!("unknown harness role"),
        };
        fs::read(path).unwrap_or_default()
    }

    pub fn seed_resume(&self, name: &str, session: &str) -> PathBuf {
        let run_dir = self.repo.join("runs").join(name);
        fs::create_dir_all(&run_dir).expect("create resume run directory");
        fs::write(
            run_dir.join("events.jsonl"),
            format!("{{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"{session}\"}}\n"),
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
        fs::write(run_dir.join(".feed-offset"), b"0\n").expect("seed follower offset");
        run_dir
    }

    /// Seed the state a driver killed inside a resume's preparation leaves.
    ///
    /// The preparation writes `.step-name` and `.event-start` for the step it
    /// is starting and only then removes the prior step's report, so a kill in
    /// that window leaves a run directory naming `step` while the report that
    /// survives it names `gate`. Everything here is what the preparation had
    /// already written at that instant: the prior step's history, the new
    /// step's input, and the flipped markers, with the sidecars still
    /// standing because their removal comes after the flip.
    pub fn seed_preparation_window(&self, name: &str, session: &str, step: &str) -> PathBuf {
        let run_dir = self.seed_resume(name, session);
        fs::write(run_dir.join(".started-at"), b"2026-09-24T21:35:27Z\n")
            .expect("seed prior step start");
        let history = run_dir.join("steps").join("gate");
        fs::create_dir_all(&history).expect("create the prior step's history");
        for file in ["run-report.txt", "last-message.txt"] {
            fs::copy(run_dir.join(file), history.join(file)).expect("archive the prior step");
        }
        fs::copy(
            run_dir.join(".feed-offset"),
            history.join("feed-offset.txt"),
        )
        .expect("archive the prior follower offset");
        fs::copy(run_dir.join(".started-at"), history.join("started-at.txt"))
            .expect("archive the prior step start");
        fs::write(history.join("event-start.txt"), b"0\n").expect("archive the prior start");
        let size = fs::metadata(run_dir.join("events.jsonl"))
            .expect("measure the seeded transcript")
            .len();
        fs::write(history.join("event-end.txt"), format!("{size}\n"))
            .expect("archive the prior end");
        fs::write(run_dir.join(format!("step-{step}.txt")), b"PROCEED\n")
            .expect("seed the new step input");
        fs::write(run_dir.join(".step-name"), format!("{step}\n")).expect("flip the step name");
        fs::write(run_dir.join(".event-start"), format!("{size}\n"))
            .expect("flip the start offset");
        fs::write(run_dir.join(".started-at"), b"2026-09-24T21:35:28Z\n")
            .expect("flip the step start");
        run_dir
    }

    /// Seed the same window one step later, after the sidecar removal.
    ///
    /// The preparation removes the run directory's sidecars between the flip
    /// and the removal of the report, so a kill in that narrower sub-window
    /// leaves the same mismatch with the prior step's answer, follower cursor,
    /// and evidence files standing only inside its history. Every sidecar the
    /// preparation archives is seeded here with bytes of its own, so what
    /// survives the undo can be told apart from what a fresh run would write.
    pub fn seed_preparation_window_after_removal(
        &self,
        name: &str,
        session: &str,
        step: &str,
    ) -> PathBuf {
        let run_dir = self.seed_preparation_window(name, session, step);
        let history = run_dir.join("steps").join("gate");
        fs::write(history.join("feed-offset.txt"), b"4096\n")
            .expect("archive a moved follower cursor");
        fs::write(history.join("reconstructed.txt"), b"reason=DRIVER-EXIT\n")
            .expect("archive the prior reconstruction record");
        fs::write(history.join("rate-limit.txt"), b"status=rejected\n")
            .expect("archive the prior rejection evidence");
        for file in ["last-message.txt", ".feed-offset"] {
            fs::remove_file(run_dir.join(file))
                .expect("remove the sidecar the preparation removes");
        }
        run_dir
    }

    pub fn seed_interrupted_step(&self, name: &str, session: &str, events: &str) -> PathBuf {
        let run_dir = self.seed_resume(name, session);
        fs::remove_file(run_dir.join("run-report.txt")).expect("remove interrupted report");
        fs::remove_file(run_dir.join("last-message.txt")).expect("remove interrupted message");
        fs::write(run_dir.join("events.jsonl"), events).expect("seed interrupted events");
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

pub fn argument(path: &Path) -> &OsStr {
    path.as_os_str()
}
