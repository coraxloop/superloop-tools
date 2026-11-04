use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use loop_home::allocations::{Allocations, allocations_path};
use loop_home::registry::WorkerBlock;
use loop_home::{
    CommandSpec, IoMode, LoopError, LoopRecord, Registry, Runner, load_registry, registry_path,
};

use crate::alloc::{
    AllocationRequest, Reservation, Subordinate, allocate, deployment_account, subordinate_counts,
};
use crate::cli::{Action, Invocation};
use crate::clock::{epoch_from_stamp, utc_stamp};
use crate::entry::{
    EntryRequest, MonitorRequest, WorkerCredentials, WorkerEntryPlan, shell_word, worker_entry_plan,
};
use crate::error::WorkerError;
use crate::layout::{
    LaunchEnv, LayoutRow, Node, Placement, Stage, install_command, layout_plan, ownership_commands,
    run_tree_command, staged,
};
use crate::table;
use crate::watch::{Outcome, evaluate, lock_pids, snapshot};

/// Seconds between two reads of a watched run directory.
pub const POLL_SECONDS: u64 = 1;
/// Seconds between the child's `TERM` and the stop by UID.
pub const GRACE_SECONDS: u64 = 10;

/// The machine facts every subcommand reads.
///
/// The owner probe is a function pointer, so this carries no equality: comparing
/// two of them would compare addresses, which say nothing about behaviour.
#[derive(Clone, Debug)]
pub struct Environment {
    /// The configured absolute private Claude adapter executable.
    pub claude_hook: PathBuf,
    /// The owner's home, used to derive every row's paths.
    pub caller_home: PathBuf,
    /// The one registry file named by the entry's variable or default.
    pub registry: PathBuf,
    /// Metadata path whose owner is the running process's own UID.
    pub proc_self: PathBuf,
    /// Process table root, used to ask whether a child is alive.
    pub proc_root: PathBuf,
    /// Passwd database naming the deployment account.
    pub passwd: PathBuf,
    /// Subordinate UID mapping of the deployment account.
    pub subuid: PathBuf,
    /// Subordinate GID mapping of the deployment account.
    pub subgid: PathBuf,
    /// The podman words that carry every namespace-root command.
    pub podman: Vec<String>,
    /// The caller's terminal name.
    pub term: String,
    /// The caller's locale name.
    pub lang: String,
    /// Seconds since the epoch, recorded as the lane's start.
    pub now: u64,
    /// Where row bytes are staged before one namespace command installs them.
    pub staging_root: PathBuf,
    /// How the owner of a path is read, injected so tests can name every outcome.
    pub owner_of: fn(&Path) -> io::Result<Option<u32>>,
}

/// Read one path's owning UID, or nothing when it is absent.
///
/// # Errors
///
/// Returns any metadata failure other than an absent path.
pub fn disk_owner(path: &Path) -> io::Result<Option<u32>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.uid())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

impl Environment {
    /// Return the staging directory one lane's installation writes through.
    #[must_use]
    pub fn staging(&self, lane: &str, uid: u32) -> PathBuf {
        self.staging_root.join(format!("worker-run-{lane}-{uid}"))
    }
}

impl Environment {
    /// Read this machine's own facts, with every path overridable for tests.
    #[must_use]
    pub fn from_process() -> Self {
        let caller_home = std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
        let registry = registry_path(
            std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
            &caller_home,
        );
        let proc_root = std::env::var_os("RUN_WORKER_PROC")
            .map_or_else(|| PathBuf::from("/proc"), PathBuf::from);
        let path = |name: &str, fallback: &str| {
            std::env::var_os(name).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
        };
        Self {
            claude_hook: std::env::var_os("RUN_WORKER_CLAUDE_HOOK_BIN")
                .or_else(|| option_env!("RUN_WORKER_CLAUDE_HOOK_BIN").map(Into::into))
                .map_or_else(
                    || caller_home.join(".local/libexec/superloop/hooks/superloop-claude-hook"),
                    PathBuf::from,
                ),
            caller_home,
            registry,
            proc_self: proc_root.join("self"),
            proc_root,
            passwd: path("RUN_WORKER_PASSWD", "/etc/passwd"),
            subuid: path("RUN_WORKER_SUBUID", "/etc/subuid"),
            subgid: path("RUN_WORKER_SUBGID", "/etc/subgid"),
            podman: std::env::var("RUN_WORKER_PODMAN")
                .map_or_else(|_error| vec![String::from("podman")], |value| vec![value]),
            term: std::env::var("TERM").unwrap_or_else(|_error| String::from("xterm")),
            lang: std::env::var("LANG").unwrap_or_else(|_error| String::from("C.UTF-8")),
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            staging_root: std::env::temp_dir(),
            owner_of: disk_owner,
        }
    }
}

fn refused(failure: &LoopError) -> WorkerError {
    WorkerError::refusal(failure.message())
}

fn registry(environment: &Environment) -> Result<Registry, WorkerError> {
    if environment.caller_home.as_os_str().is_empty() || environment.caller_home.to_str().is_none()
    {
        return Err(WorkerError::refusal("HOME must be a nonempty UTF-8 path"));
    }
    load_registry(&environment.registry).map_err(|failure| refused(&failure))
}

fn record(
    registry: &Registry,
    environment: &Environment,
    name: &str,
) -> Result<LoopRecord, WorkerError> {
    registry
        .row(name, &environment.caller_home)
        .map_err(|failure| refused(&failure))
}

fn block(selected: &LoopRecord, allocations: &Allocations) -> Result<WorkerBlock, WorkerError> {
    allocations
        .require(&selected.name)
        .map_err(|failure| WorkerError::refusal(format!("allocations: {}", failure.message())))
}

fn peers(
    registry: &Registry,
    selected: &str,
    caller_home: &Path,
    allocations: &Allocations,
) -> Vec<Reservation> {
    registry
        .rows(caller_home)
        .into_iter()
        .filter(|peer| peer.name != selected)
        .map(|peer| {
            let block = allocations.get(&peer.name);
            Reservation {
                name: peer.name,
                uid: peer.uid,
                block,
            }
        })
        .collect()
}

fn exists(path: &Path, what: &str) -> Result<(), WorkerError> {
    if path.is_file() {
        return Ok(());
    }
    Err(WorkerError::refusal(format!(
        "no {what}: {}",
        path.display()
    )))
}

fn stage_bytes(rows: &[LayoutRow], stage: Stage, staging: &Path) -> Result<(), WorkerError> {
    let failure = |path: &Path, error: &io::Error| {
        WorkerError::runtime(format!("could not stage {}: {error}", path.display()))
    };
    fs::create_dir_all(staging).map_err(|error| failure(staging, &error))?;
    fs::set_permissions(staging, fs::Permissions::from_mode(0o700))
        .map_err(|error| failure(staging, &error))?;
    for (index, layout_row) in rows.iter().enumerate() {
        let Node::File(bytes) = &layout_row.node else {
            continue;
        };
        if layout_row.stage != stage {
            continue;
        }
        let path = staged(staging, index);
        fs::write(&path, bytes).map_err(|error| failure(&path, &error))?;
    }
    Ok(())
}

fn build<R: Runner>(
    runner: &mut R,
    rows: &[LayoutRow],
    stage: Stage,
    environment: &Environment,
    staging: &Path,
) -> Result<(), WorkerError> {
    stage_bytes(rows, stage, staging)?;
    run_one(
        runner,
        &install_command(rows, stage, staging, &environment.podman),
    )
    .map(|_status| ())
}

fn run_one<R: Runner>(runner: &mut R, command: &CommandSpec) -> Result<i32, WorkerError> {
    let output = runner.run(command).map_err(|failure| {
        WorkerError::runtime(format!("{}: {}", command.label, failure.detail))
    })?;
    if output.status == 0 {
        return Ok(0);
    }
    Err(WorkerError::runtime(format!(
        "{} exited {}",
        command.label, output.status
    )))
}

fn namespaced(podman: &[String], words: Vec<String>) -> Vec<String> {
    podman
        .iter()
        .cloned()
        .chain([String::from("unshare")])
        .chain(words)
        .collect()
}

fn mail_birth<R: Runner>(
    runner: &mut R,
    environment: &Environment,
    loop_name: &str,
    lane: &str,
    uid: u32,
    phase: &str,
) -> Result<(), WorkerError> {
    let executable = std::env::current_exe()
        .map_err(|error| WorkerError::runtime(format!("worker birth executable: {error}")))?;
    let identity =
        loop_home::mail::birth::Identity::for_reservation(uid, format!("worker-run:{lane}:{uid}"));
    let command = CommandSpec {
        label: format!("mail-birth-{phase}"),
        argv: namespaced(
            &environment.podman,
            vec![
                executable.to_string_lossy().into_owned(),
                "_mail-worker-birth".into(),
                environment.caller_home.to_string_lossy().into_owned(),
                loop_name.into(),
                phase.into(),
                identity.name,
                uid.to_string(),
                identity.reservation,
            ],
        ),
        io: IoMode::Inherit,
    };
    run_one(runner, &command).map(|_| ())
}

fn git(label: &str, podman: &[String], words: Vec<String>) -> CommandSpec {
    CommandSpec {
        label: String::from(label),
        argv: namespaced(
            podman,
            std::iter::once(String::from("git")).chain(words).collect(),
        ),
        io: IoMode::Inherit,
    }
}

fn clone_commands(
    placement: &Placement,
    hub: &Path,
    commit: &str,
    podman: &[String],
) -> Vec<CommandSpec> {
    let clone = placement.clone_dir().to_string_lossy().into_owned();
    let account = format!("{}-{}", placement.loop_name, placement.lane);
    let at = |label: &str, words: [&str; 3]| {
        git(
            label,
            podman,
            [String::from("-C"), clone.clone()]
                .into_iter()
                .chain(words.into_iter().map(String::from))
                .collect(),
        )
    };
    vec![
        git(
            "clone",
            podman,
            vec![
                String::from("clone"),
                hub.to_string_lossy().into_owned(),
                clone.clone(),
            ],
        ),
        at("checkout", ["checkout", "--detach", commit]),
        at("config-name", ["config", "user.name", &account]),
        at(
            "config-email",
            ["config", "user.email", &format!("{account}@lanes.invalid")],
        ),
        at("config-signing", ["config", "commit.gpgsign", "false"]),
        at("remote-remove", ["remote", "remove", "origin"]),
    ]
}

struct Lane<'a> {
    selected: &'a LoopRecord,
    name: &'a str,
    uid: u32,
    launcher: u32,
}

fn placement(
    lane: &Lane<'_>,
    estate: &Path,
    claude_hook: &Path,
    brief: String,
    launch: Option<LaunchEnv>,
) -> Placement {
    Placement {
        home: lane.selected.home.clone(),
        loop_name: lane.selected.name.clone(),
        loop_uid: lane.selected.uid,
        lane: lane.name.to_owned(),
        uid: lane.uid,
        estate: estate.to_owned(),
        claude_hook: claude_hook.to_owned(),
        brief,
        launch,
        launcher_uid: lane.launcher,
    }
}

fn ensure_run_tree<R: Runner>(
    runner: &mut R,
    environment: &Environment,
    home: &Path,
    launcher: u32,
) -> Result<PathBuf, WorkerError> {
    let runs = home.join("runs");
    match (environment.owner_of)(&runs) {
        Ok(Some(owner)) if owner == launcher => {}
        Ok(Some(owner)) => {
            return Err(WorkerError::refusal(format!(
                "run tree {} is owned by uid {owner}, not by the launcher's uid {launcher}",
                runs.display()
            )));
        }
        Ok(None) => {
            run_one(runner, &run_tree_command(&runs, &environment.podman)).map(|_status| ())?;
        }
        Err(error) => {
            return Err(WorkerError::refusal(format!(
                "could not read owner of {}: {error}",
                runs.display()
            )));
        }
    }
    Ok(runs.join("table.tsv"))
}

fn allocation(
    worker_block: WorkerBlock,
    taken: &[u32],
    reservations: &[Reservation],
    deployment_uid: u32,
    limits: Subordinate,
) -> Result<u32, WorkerError> {
    allocate(&AllocationRequest {
        block: worker_block,
        taken: taken.to_vec(),
        peers: reservations.to_vec(),
        deployment_uid,
        limits,
    })
}

fn prepare<R: Runner, W: io::Write>(
    invocation: &Invocation,
    environment: &Environment,
    runner: &mut R,
    output: &mut W,
) -> Result<u8, WorkerError> {
    let Action::Prepare {
        commit, hub, brief, ..
    } = &invocation.action
    else {
        return Err(WorkerError::usage(crate::cli::USAGE));
    };
    let lane = invocation.action.lane();
    let registry = registry(environment)?;
    let selected = record(&registry, environment, invocation.action.loop_name())?;
    loop_home::workers_settings::read_execution_settings(
        &environment.caller_home,
        &selected,
        registry.runs_root(&selected.name),
        Some("claude"),
    )
    .map_err(|error| refused(&error))?;
    let brief_text = fs::read_to_string(brief).map_err(|error| {
        WorkerError::refusal(format!("no brief: {} ({error})", brief.display()))
    })?;
    let allocations = Allocations::read(&allocations_path(&environment.caller_home))
        .map_err(|failure| WorkerError::refusal(format!("allocations: {}", failure.message())))?;
    let worker_block = block(&selected, &allocations)?;
    let account = deployment_account(&environment.proc_self, &environment.passwd)?;
    let limits = subordinate_counts(&account.name, &environment.subuid, &environment.subgid)?;
    let reservations = peers(
        &registry,
        &selected.name,
        &environment.caller_home,
        &allocations,
    );
    let retained =
        loop_home::mail::worker_provision::reserved_uids(&environment.caller_home, &selected.name)
            .map_err(|error| WorkerError::refusal(format!("worker birth history: {error}")))?;
    let retained = retained.into_iter().collect::<Vec<_>>();
    allocation(worker_block, &retained, &reservations, account.uid, limits)?;
    let table_path = ensure_run_tree(runner, environment, &selected.home, account.uid)?;
    let claimed = table::claim_slot(&table_path, lane, |taken| {
        let mut occupied = retained.clone();
        occupied.extend_from_slice(taken);
        allocation(worker_block, &occupied, &reservations, account.uid, limits)
    })?;
    let uid = claimed.uid;
    // Preserve the row so an uncertain reservation remains explicitly closable.
    mail_birth(runner, environment, &selected.name, lane, uid, "reserve")?;
    let placement = placement(
        &Lane {
            selected: &selected,
            name: lane,
            uid,
            launcher: account.uid,
        },
        Path::new("/"),
        &environment.claude_hook,
        brief_text,
        None,
    );
    let layout = layout_plan(&placement);
    let staging = environment.staging(lane, uid);
    let cloned = build(runner, &layout, Stage::Prepare, environment, &staging).and_then(|()| {
        for command in clone_commands(&placement, hub, commit, &environment.podman) {
            run_one(runner, &command)?;
        }
        head_of(runner, &placement, &environment.podman)
    });
    let head = match cloned {
        Ok(head) => head,
        Err(failure) => {
            return Err(unwind(runner, environment, &placement, &failure));
        }
    };
    let filled = table::fill_commit(&table_path, lane, &head)?;
    mail_birth(runner, environment, &selected.name, lane, uid, "finish")?;
    writeln!(
        output,
        "{} loop={} lane={lane} uid={uid} commit={} clone={}",
        invocation.action.word(),
        selected.name,
        filled.commit,
        placement.clone_dir().display()
    )
    .map_err(|error| publication(&error))?;
    Ok(0)
}

/// Remove a failed preparation's execution tree while retaining its closable row.
/// A pending mail receipt keeps the UID reserved until explicit close transfers custody.
fn unwind<R: Runner>(
    runner: &mut R,
    environment: &Environment,
    placement: &Placement,
    failure: &WorkerError,
) -> WorkerError {
    let mut message = String::from(failure.message());
    let removal = CommandSpec {
        label: String::from("lane-remove"),
        argv: namespaced(
            &environment.podman,
            [
                String::from("rm"),
                String::from("-rf"),
                placement.lane_dir().to_string_lossy().into_owned(),
            ]
            .to_vec(),
        ),
        io: IoMode::Inherit,
    };
    if let Err(tree) = run_one(runner, &removal) {
        message.push_str("; the lane tree could not be removed: ");
        message.push_str(tree.message());
    }
    WorkerError::runtime(message)
}

fn head_of<R: Runner>(
    runner: &mut R,
    placement: &Placement,
    podman: &[String],
) -> Result<String, WorkerError> {
    let command = CommandSpec {
        label: String::from("rev-parse"),
        argv: namespaced(
            podman,
            [
                String::from("git"),
                String::from("-C"),
                placement.clone_dir().to_string_lossy().into_owned(),
                String::from("rev-parse"),
                String::from("HEAD"),
            ]
            .to_vec(),
        ),
        io: IoMode::Capture,
    };
    let output = runner
        .run(&command)
        .map_err(|failure| WorkerError::runtime(format!("rev-parse: {}", failure.detail)))?;
    if output.status != 0 {
        return Err(WorkerError::runtime(format!(
            "rev-parse exited {}",
            output.status
        )));
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if head.is_empty() {
        return Err(WorkerError::runtime(String::from(
            "rev-parse named no commit",
        )));
    }
    Ok(head)
}

fn driver_command(
    placement: &Placement,
    action: &Action,
    settings: &loop_home::workers_settings::ExecutionSettings,
) -> Result<Vec<String>, WorkerError> {
    let Action::Launch {
        budget,
        model,
        effort,
        ..
    } = action
    else {
        return Err(WorkerError::usage(crate::cli::USAGE));
    };
    let driver = settings
        .driver_argv
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!(
        "exec {} -C {} -d {} -s workspace-write -m {} -e {} -t {budget} -n work - < {}",
        driver,
        shell_word(&placement.clone_dir().to_string_lossy()),
        shell_word(&placement.run_dir().to_string_lossy()),
        shell_word(model),
        shell_word(effort),
        shell_word(&placement.lane_dir().join("brief.md").to_string_lossy()),
    );
    Ok(vec![String::from("sh"), String::from("-c"), line])
}

fn refuse_legacy_home(home: &Path, lane: &str) -> Result<(), WorkerError> {
    let old = home.join("workers").join(lane);
    match fs::symlink_metadata(&old) {
        Ok(_) => Err(WorkerError::refusal(format!(
            "worker-run execution home {} requires reconciliation: relocate workers/{lane} to worker-homes/{lane} through the mail migration before launch or watch",
            old.display(),
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WorkerError::refusal(format!(
            "legacy worker home inspection: {error}"
        ))),
    }
}

fn finish_prepared<R: Runner>(
    runner: &mut R,
    environment: &Environment,
    loop_name: &str,
    prepared: &table::Row,
) -> Result<(), WorkerError> {
    if prepared.commit.is_empty() {
        return Err(WorkerError::refusal("worker preparation is incomplete"));
    }
    mail_birth(
        runner,
        environment,
        loop_name,
        &prepared.lane,
        prepared.uid,
        "finish",
    )
}

fn launch<R: Runner, W: io::Write>(
    invocation: &Invocation,
    environment: &Environment,
    runner: &mut R,
    output: &mut W,
) -> Result<u8, WorkerError> {
    let Action::Launch {
        driver,
        estate,
        budget,
        model,
        effort,
        ..
    } = &invocation.action
    else {
        return Err(WorkerError::usage(crate::cli::USAGE));
    };
    let lane = invocation.action.lane();
    let registry = registry(environment)?;
    let selected = record(&registry, environment, invocation.action.loop_name())?;
    refuse_legacy_home(&selected.home, lane)?;
    let settings = loop_home::workers_settings::read_execution_settings(
        &environment.caller_home,
        &selected,
        registry.runs_root(&selected.name),
        Some(driver),
    )
    .map_err(|error| refused(&error))?;
    if !environment.claude_hook.is_absolute() || environment.claude_hook.to_str().is_none() {
        return Err(WorkerError::refusal(
            "RUN_WORKER_CLAUDE_HOOK_BIN must name an absolute UTF-8 path",
        ));
    }
    exists(&environment.claude_hook, "Claude adapter")?;
    exists(&estate.join("charters").join("worker.md"), "worker charter")?;
    exists(
        &selected
            .home
            .join("shared")
            .join("permissions")
            .join("domain.md"),
        "worker rubric",
    )?;
    let _lifetime = lifetime_lock(invocation, environment)?;
    let table_path = selected.home.join("runs").join("table.tsv");
    let rows = table::read_rows(&table_path)?;
    let prepared = rows
        .iter()
        .find(|row| row.lane == lane)
        .ok_or_else(|| WorkerError::refusal(format!("lane {lane} has no prepared row")))?;
    finish_prepared(runner, environment, &selected.name, prepared)?;
    let started = utc_stamp(environment.now);
    let account = deployment_account(&environment.proc_self, &environment.passwd)?;
    let placement = placement(
        &Lane {
            selected: &selected,
            name: lane,
            uid: prepared.uid,
            launcher: account.uid,
        },
        estate,
        &environment.claude_hook,
        String::new(),
        Some(LaunchEnv {
            driver: driver.clone(),
            model: model.clone(),
            effort: effort.clone(),
            budget: *budget,
            started: started.clone(),
        }),
    );
    let filled = table::fill_launch(&table_path, lane, driver, &started)?;
    let layout = layout_plan(&placement);
    let staging = environment.staging(lane, placement.uid);
    build(runner, &layout, Stage::Launch, environment, &staging)?;
    for command in ownership_commands(&placement, &layout, &environment.podman) {
        run_one(runner, &command)?;
    }
    writeln!(
        output,
        "{} loop={} lane={lane} uid={} run={} driver={driver} started={}",
        invocation.action.word(),
        selected.name,
        placement.uid,
        placement.run_dir().display(),
        filled.started
    )
    .map_err(|error| publication(&error))?;
    let plan = drop_plan(
        &placement,
        environment,
        &invocation.action,
        *budget,
        &settings,
    )?;
    let dropped = runner.run(&plan.command).map_err(|failure| {
        WorkerError::runtime(format!("{}: {}", plan.command.label, failure.detail))
    })?;
    Ok(u8::from(dropped.status != 0))
}

fn drop_plan(
    placement: &Placement,
    environment: &Environment,
    action: &Action,
    budget: u64,
    settings: &loop_home::workers_settings::ExecutionSettings,
) -> Result<WorkerEntryPlan, WorkerError> {
    let home = placement.worker_home();
    Ok(worker_entry_plan(
        &EntryRequest {
            credentials: WorkerCredentials {
                loop_name: placement.loop_name.clone(),
                lane: placement.lane.clone(),
                uid: placement.uid,
                loop_gid: placement.loop_uid,
                mail_gid: Allocations::read(&allocations_path(&environment.caller_home))
                    .and_then(|allocations| {
                        allocations.mail_group(&placement.loop_name, Some(placement.uid))
                    })
                    .map_err(|error| refused(&error))?,
            },
            home: home.to_string_lossy().into_owned(),
            command: driver_command(placement, action, settings)?,
            extra_env: settings
                .environment()
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .split_once('=')
                        .map(|(key, value)| (key.to_owned(), value.to_owned()))
                })
                .chain(std::iter::once((
                    String::from("CLAUDE_CONFIG_DIR"),
                    home.join(".claude").to_string_lossy().into_owned(),
                )))
                .collect(),
            term: environment.term.clone(),
            lang: environment.lang.clone(),
        },
        &environment.podman,
        Some(&MonitorRequest {
            lock: placement.lock().to_string_lossy().into_owned(),
            evidence: placement
                .run_dir()
                .join("budget-notice.txt")
                .to_string_lossy()
                .into_owned(),
            lane: placement.lane.clone(),
            budget_seconds: budget,
            grace_seconds: GRACE_SECONDS,
        }),
        IoMode::Inherit,
    ))
}

fn watch_outcome(
    placement: &Placement,
    environment: &Environment,
    stall: Duration,
    budget: Duration,
    already: Duration,
) -> Result<Outcome, WorkerError> {
    let run_dir = placement.run_dir();
    let child = lock_pids(&placement.lock()).map(|(_monitor, child)| child);
    let started = Instant::now();
    let mut growth = Instant::now();
    let mut size = 0;
    loop {
        let instant = snapshot(&run_dir, 0, &environment.proc_root, child)?;
        if instant.events_size != size {
            size = instant.events_size;
            growth = Instant::now();
        }
        if let Some(outcome) = evaluate(
            &instant,
            already + started.elapsed(),
            growth.elapsed(),
            stall,
            budget,
        ) {
            return Ok(outcome);
        }
        std::thread::sleep(Duration::from_secs(POLL_SECONDS));
    }
}

/// The budget and start instant `launch` recorded beside the run directory.
fn launch_record(run_dir: &Path) -> Result<(u64, String), WorkerError> {
    let path = run_dir.join("launch.env");
    let text = fs::read_to_string(&path).map_err(|error| {
        WorkerError::refusal(format!("no launch record: {} ({error})", path.display()))
    })?;
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key).map(str::trim))
    };
    let budget = field("BUDGET=")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            WorkerError::refusal(format!("launch record names no budget: {}", path.display()))
        })?;
    let started = field("STARTED=")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            WorkerError::refusal(format!("launch record names no start: {}", path.display()))
        })?;
    Ok((budget, started.to_owned()))
}

fn watch<W: io::Write>(
    invocation: &Invocation,
    environment: &Environment,
    output: &mut W,
) -> Result<u8, WorkerError> {
    let Action::Watch { stall, budget, .. } = &invocation.action else {
        return Err(WorkerError::usage(crate::cli::USAGE));
    };
    let lane = invocation.action.lane();
    let registry = registry(environment)?;
    let selected = record(&registry, environment, invocation.action.loop_name())?;
    refuse_legacy_home(&selected.home, lane)?;
    let table_path = selected.home.join("runs").join("table.tsv");
    let row = table::read_rows(&table_path)?
        .into_iter()
        .find(|row| row.lane == lane)
        .ok_or_else(|| WorkerError::refusal(format!("lane {lane} has no prepared row")))?;
    let account = deployment_account(&environment.proc_self, &environment.passwd)?;
    let placement = placement(
        &Lane {
            selected: &selected,
            name: lane,
            uid: row.uid,
            launcher: account.uid,
        },
        Path::new("/"),
        &environment.claude_hook,
        String::new(),
        None,
    );
    let (recorded, started) = launch_record(&placement.run_dir())?;
    let seconds = budget.unwrap_or(recorded);
    let epoch = epoch_from_stamp(&started).ok_or_else(|| {
        WorkerError::refusal(format!(
            "launch record names an unreadable start: {started}"
        ))
    })?;
    let already = Duration::from_secs(environment.now.saturating_sub(epoch));
    let outcome = watch_outcome(
        &placement,
        environment,
        Duration::from_secs(*stall),
        Duration::from_secs(seconds),
        already,
    )?;
    writeln!(
        output,
        "{} {} loop={} lane={lane} uid={} {}",
        invocation.action.word(),
        outcome.word(),
        selected.name,
        row.uid,
        outcome.detail()
    )
    .map_err(|error| publication(&error))?;
    Ok(outcome.status())
}

fn close<R: Runner, W: io::Write>(
    invocation: &Invocation,
    environment: &Environment,
    runner: &mut R,
    output: &mut W,
) -> Result<u8, WorkerError> {
    let registry = registry(environment)?;
    let selected = record(&registry, environment, invocation.action.loop_name())?;
    let lane = invocation.action.lane();
    let _lifetime = lifetime_lock(invocation, environment)?;
    let table_path = selected.home.join("runs/table.tsv");
    let row = table::read_rows(&table_path)?
        .into_iter()
        .find(|row| row.lane == lane)
        .ok_or_else(|| WorkerError::refusal(format!("lane {lane} has no prepared row")))?;
    // The namespace coordinator verifies process absence and transfers custody
    // before making its receipt reusable. A crash before row removal is retryable.
    mail_birth(runner, environment, &selected.name, lane, row.uid, "retire")?;
    table::remove_row(&table_path, lane)?;
    writeln!(
        output,
        "CLOSE loop={} lane={lane} uid={} mail=retired uid=released",
        selected.name, row.uid
    )
    .map_err(|error| publication(&error))?;
    Ok(0)
}

fn lifetime_lock(
    invocation: &Invocation,
    environment: &Environment,
) -> Result<Option<loop_home::mail::birth::LifetimeLock>, WorkerError> {
    if !matches!(
        invocation.action,
        Action::Launch { .. } | Action::Close { .. }
    ) {
        return Ok(None);
    }
    let registry = registry(environment)?;
    let selected = record(&registry, environment, invocation.action.loop_name())?;
    let path = selected
        .home
        .join("runs")
        .join(format!(".lifetime-{}.lock", invocation.action.lane()));
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|error| WorkerError::refusal(format!("worker lifetime lock: {error}")))?;
    let file = loop_home::mail::birth::lock_lifetime(file)
        .map_err(|error| WorkerError::refusal(format!("worker lifetime is busy: {error}")))?;
    Ok(Some(file))
}

fn publication(error: &io::Error) -> WorkerError {
    WorkerError::runtime(format!("output failure: {error}"))
}

const fn verdict(status: u8) -> &'static str {
    match status {
        0 => "ok",
        2 => "usage",
        3 => "escalation",
        4 => "refused",
        5 => "budget",
        42 => "stall",
        _ => "failed",
    }
}

fn report<W: io::Write>(output: &mut W, status: u8, wall: Duration) -> Result<(), WorkerError> {
    writeln!(
        output,
        "RUN-REPORT exit={status} wall={:.3}s verdict={}",
        wall.as_secs_f64(),
        verdict(status)
    )
    .map_err(|error| publication(&error))
}

/// Execute one parsed invocation against an injected runner.
///
/// # Errors
///
/// Returns the refusal, waiting outcome, or runtime failure the subcommand decided.
pub fn execute<R: Runner, W: io::Write>(
    invocation: &Invocation,
    environment: &Environment,
    runner: &mut R,
    output: &mut W,
) -> Result<u8, WorkerError> {
    match invocation.action {
        Action::Close { .. } => close(invocation, environment, runner, output),
        Action::Prepare { .. } => prepare(invocation, environment, runner, output),
        Action::Launch { .. } => launch(invocation, environment, runner, output),
        Action::Watch { .. } => watch(invocation, environment, output),
    }
}

/// Run `worker-run` with an injected external-command runner.
#[must_use]
pub fn run_worker_entry<I, A, R, W, E>(
    arguments: I,
    environment: &Environment,
    runner: &mut R,
    output: &mut W,
    error: &mut E,
) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<std::ffi::OsString>,
    R: Runner,
    W: io::Write,
    E: io::Write,
{
    let started = Instant::now();
    let outcome = crate::cli::parse_invocation(arguments)
        .and_then(|invocation| execute(&invocation, environment, runner, output));
    let status = match outcome {
        Ok(status) => status,
        Err(failure) => {
            if writeln!(error, "REFUSED {}", escaped_refusal(failure.message())).is_err() {
                return 1;
            }
            failure.status()
        }
    };
    if report(output, status, started.elapsed()).is_err() {
        return 1;
    }
    status
}

fn escaped_refusal(message: &str) -> String {
    let mut escaped = String::new();
    for character in message.chars() {
        if character.is_control() {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    escaped
}
