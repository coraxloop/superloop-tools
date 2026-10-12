//! # `worker-run` library test matrix
//!
//! | Matrix | Tests | Contract |
//! |---|---:|---|
//! | Credentials | 1 | The worker drop, both group lines, and the passwd line |
//! | Allocation | 5 | Lowest free slot, exhaustion, overlap, subordinate mapping, and the account lookup |
//! | Entry planner | 3 | Byte-stable inner, outer, and monitored scripts, and quoting |
//! | Layout builder | 4 | Every row, the two records, and modes before ownership |
//! | Subcommand contract | 20 | Evidence lines, the launcher's run tree, the locked claim, the recorded head, the unwound failure, every waiting outcome, refusals, and the deferred half |

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use loop_home::registry::WorkerBlock;
use loop_home::{CommandOutput, CommandSpec, IoMode, RunError, Runner};

use crate::alloc::{
    AllocationRequest, Reservation, Subordinate, allocate, deployment_account, subordinate_counts,
};
use crate::app::{Environment, execute, run_worker_entry};
use crate::cli::parse_invocation;
use crate::clock::{epoch_from_stamp, utc_stamp};
use crate::entry::{
    EntryRequest, MonitorRequest, WorkerCredentials, inner_script, outer_script, worker_entry_plan,
};
use crate::layout::{
    Group, LaunchEnv, Node, Owner, Placement, Stage, layout_plan, ownership_commands,
};
use crate::table;
use crate::watch::{Child, Outcome, evaluate, snapshot};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

const FIXTURE_BLOCK: WorkerBlock = WorkerBlock {
    base: 40000,
    count: 4,
};

struct Fixture {
    path: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from("/tmp").join(format!(
            "worker-run-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure test directory");
        let fixture = Self { path };
        fixture.write_registry();
        fixture.write_allocations("[alpha]\nuids = { base = 40000, count = 4 }\n[beta]\nuids = { base = 42000, count = 4 }\n");
        let settings_dir = fixture.path.join(".config/loops/alpha");
        fs::create_dir_all(&settings_dir).expect("settings directory");
        fs::set_permissions(&settings_dir, fs::Permissions::from_mode(0o700))
            .expect("settings directory mode");
        let settings = settings_dir.join("workers.toml");
        fs::write(&settings, "driver_argv = [\"/usr/bin/claude-lane\"]\nbackend_argv = { claude = [\"/usr/bin/claude\"] }\n").expect("settings");
        fs::set_permissions(settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
        fixture.write_machine();
        fixture.write_estate();
        fs::create_dir_all(fixture.home().join("shared").join("permissions"))
            .expect("create shared tree");
        fs::write(
            fixture
                .home()
                .join("shared")
                .join("permissions")
                .join("domain.md"),
            "# worker rubric\n",
        )
        .expect("write rubric");
        fs::create_dir_all(fixture.home().join("runs")).expect("create run tree");
        fs::write(fixture.path.join("brief.md"), "# brief\n").expect("write brief");
        fixture
    }

    fn home(&self) -> PathBuf {
        self.path.join(".var/loops/alpha")
    }

    fn estate(&self) -> PathBuf {
        self.path.join("estate")
    }

    fn root(&self) -> PathBuf {
        self.path.clone()
    }

    fn uid(&self) -> u32 {
        fs::metadata(&self.path).expect("fixture metadata").uid()
    }

    fn write_registry(&self) {
        fs::write(
            self.root().join("registry.toml"),
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [\n  { name = \"alpha\", uid = 41001, launch = \"dev/alpha\" },\n  { name = \"beta\", uid = 41002, launch = \"dev/beta\" },\n]\n",
        )
        .expect("write registry");
    }

    fn write_allocations(&self, source: &str) {
        let directory = self.root().join(".config/loops");
        fs::create_dir_all(&directory).expect("allocation directory");
        fs::set_permissions(
            self.root().join(".config"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("config mode");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("loops mode");
        let registry = directory.join("registry.toml");
        fs::copy(self.root().join("registry.toml"), &registry)
            .expect("allocation registry fixture");
        fs::set_permissions(registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
        let path = directory.join("allocations.toml");
        fs::write(&path, source).expect("allocation fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("allocation mode");
    }

    fn write_machine(&self) {
        fs::write(
            self.path.join("passwd"),
            format!(
                "deploy:x:{}:{}:deploy:/home/deploy:/bin/bash\n",
                self.uid(),
                self.uid()
            ),
        )
        .expect("write passwd");
        fs::write(self.path.join("subuid"), "deploy:100000:65536\n").expect("write subuid");
        fs::write(self.path.join("subgid"), "deploy:100000:65536\n").expect("write subgid");
    }

    fn write_estate(&self) {
        let estate = self.estate();
        fs::create_dir_all(estate.join("hooks")).expect("create hooks");
        fs::create_dir_all(estate.join("charters")).expect("create charters");
        fs::write(
            estate.join("hooks").join("superloop-claude-hook"),
            "#!/bin/sh\n",
        )
        .expect("write hook");
        fs::write(estate.join("charters").join("worker.md"), "# charter\n").expect("write charter");
    }

    fn environment(&self) -> Environment {
        Environment {
            claude_hook: self.estate().join("hooks/superloop-claude-hook"),
            caller_home: self.path.clone(),
            registry: self.root().join("registry.toml"),
            proc_self: self.path.clone(),
            proc_root: self.path.join("proc"),
            passwd: self.path.join("passwd"),
            subuid: self.path.join("subuid"),
            subgid: self.path.join("subgid"),
            podman: vec![String::from("podman")],
            term: String::from("vt100"),
            lang: String::from("C.UTF-8"),
            now: 1_700_000_000,
            staging_root: self.path.join("staging"),
            owner_of: crate::app::disk_owner,
        }
    }

    fn prepare_arguments(&self) -> Vec<String> {
        [
            "prepare",
            "alpha",
            "rw1",
            "c0ffee",
            "--hub",
            "/srv/hub.git",
            "--brief",
            &self.path.join("brief.md").to_string_lossy(),
        ]
        .map(String::from)
        .to_vec()
    }

    fn launch_arguments(&self) -> Vec<String> {
        [
            "launch",
            "alpha",
            "rw1",
            "--driver",
            "claude",
            "--estate",
            &self.estate().to_string_lossy(),
            "--budget",
            "1800",
        ]
        .map(String::from)
        .to_vec()
    }

    fn lane_dir(&self) -> PathBuf {
        self.home().join("workers").join("rw1")
    }

    fn clone_dir(&self) -> PathBuf {
        self.lane_dir().join("clone")
    }

    fn table(&self) -> PathBuf {
        self.home().join("runs").join("table.tsv")
    }

    fn lane_dir_lock(&self) -> PathBuf {
        fs::create_dir_all(self.lane_dir()).expect("create lane tree");
        self.lane_dir().join("monitor.lock")
    }

    fn watch_arguments() -> Vec<String> {
        ["watch", "alpha", "rw1"].map(String::from).to_vec()
    }

    fn live_run(&self, launch: &str) -> PathBuf {
        let run_dir = self.home().join("runs").join("40000");
        fs::create_dir_all(&run_dir).expect("create run directory");
        fs::create_dir_all(self.home().join("runs")).expect("create run tree");
        fs::write(run_dir.join("launch.env"), launch).expect("write launch record");
        fs::write(
            self.table(),
            format!(
                "{}\n40000\trw1\tclaude\tabc123\t2023-11-14T22:13:20Z\n",
                table::HEADER
            ),
        )
        .expect("write run table");
        run_dir
    }

    fn placement(&self, uid: u32, launch: Option<LaunchEnv>) -> Placement {
        Placement {
            home: self.home(),
            loop_name: String::from("alpha"),
            loop_uid: 41001,
            lane: String::from("rw1"),
            uid,
            estate: self.estate(),
            claude_hook: self.estate().join("hooks/superloop-claude-hook"),
            brief: String::from("# brief\n"),
            launch,
            launcher_uid: self.uid(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove test directory");
    }
}

#[derive(Default)]
struct FakeNamespace {
    commands: Vec<CommandSpec>,
    statuses: VecDeque<i32>,
    replies: VecDeque<Vec<u8>>,
}

impl FakeNamespace {
    fn labels(&self) -> Vec<String> {
        self.commands
            .iter()
            .map(|command| command.label.clone())
            .collect()
    }

    fn script(&self, label: &str) -> String {
        self.commands
            .iter()
            .find(|command| command.label == label)
            .and_then(|command| command.argv.last())
            .cloned()
            .unwrap_or_default()
    }

    fn head(head: &str) -> Self {
        Self {
            replies: VecDeque::from([head.as_bytes().to_vec()]),
            ..Self::default()
        }
    }
}

impl Runner for FakeNamespace {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RunError> {
        self.commands.push(command.clone());
        Ok(CommandOutput {
            status: self.statuses.pop_front().unwrap_or(0),
            stdout: if command.label == "rev-parse" {
                self.replies.pop_front().unwrap_or_default()
            } else {
                Vec::new()
            },
            stderr: Vec::new(),
            wall: Duration::from_millis(1),
        })
    }
}

fn credentials() -> WorkerCredentials {
    WorkerCredentials {
        loop_name: String::from("alpha"),
        lane: String::from("rw1"),
        uid: 40000,
        loop_gid: 41001,
    }
}

fn request(home: &str, command: &[&str]) -> EntryRequest {
    EntryRequest {
        credentials: credentials(),
        home: String::from(home),
        command: command.iter().copied().map(String::from).collect(),
        extra_env: vec![(String::from("CLAUDE_CONFIG_DIR"), format!("{home}/.claude"))],
        term: String::from("vt100"),
        lang: String::from("C.UTF-8"),
    }
}

const fn mapping(uid_count: u32, gid_count: u32) -> Subordinate {
    Subordinate {
        uid_count,
        gid_count,
    }
}

fn allocation(taken: &[u32], peers: Vec<Reservation>, limits: Subordinate) -> AllocationRequest {
    AllocationRequest {
        block: FIXTURE_BLOCK,
        taken: taken.to_vec(),
        peers,
        deployment_uid: 1000,
        limits,
    }
}

/// The one field that differs from the entry command is asserted rather than inherited.
///
/// ´claim:runworker:a-worker-drop-keeps-its-own-group-and-joins-its-loops´
/// ´test:crate:the-worker-drop-names-both-gids-and-forbids-new-privileges´
#[test]
fn the_worker_drop_names_both_gids_and_forbids_new_privileges() {
    let credentials = credentials();
    assert_eq!(
        credentials.drop_words(),
        [
            "setpriv",
            "--reuid=40000",
            "--regid=40000",
            "--groups=41001",
            "--no-new-privs",
        ]
        .map(String::from)
    );
    assert_eq!(
        credentials.group_lines(),
        [
            String::from("alpha-rw1:x:40000:"),
            String::from("alpha:x:41001:alpha-rw1"),
        ]
    );
    assert_eq!(
        credentials.passwd_line("/srv/alpha/workers/rw1/home"),
        "alpha-rw1:x:40000:40000:alpha lane rw1:/srv/alpha/workers/rw1/home:/bin/bash"
    );
    let script = inner_script(&request("/srv/alpha/workers/rw1/home", &["true"]));
    assert!(!script.contains("--clear-groups"));
    assert!(script.contains("--groups=41001 --no-new-privs env -i"));
}

/// The lowest free slot is taken, and a row removed by hand frees its slot again.
///
/// ´claim:runworker:allocation-takes-the-lowest-free-slot-of-a-block´
/// ´test:crate:the-lowest-free-slot-is-taken-and-freed-again´
#[test]
fn the_lowest_free_slot_is_taken_and_freed_again() {
    let limits = mapping(65_536, 65_536);
    assert_eq!(
        allocate(&allocation(&[], Vec::new(), limits)).expect("empty block"),
        40000
    );
    assert_eq!(
        allocate(&allocation(&[40000, 40002], Vec::new(), limits)).expect("gap"),
        40001
    );
    assert_eq!(
        allocate(&allocation(&[40001, 40002], Vec::new(), limits)).expect("reuse"),
        40000
    );
}

/// An exhausted block is a diagnosis rather than a busy day, so the refusal counts the lanes.
///
/// ´claim:runworker:a-full-block-is-refused-and-names-its-live-count´
/// ´test:crate:a-full-block-is-refused-with-its-live-count´
#[test]
fn a_full_block_is_refused_with_its_live_count() {
    let failure = allocate(&allocation(
        &[40000, 40001, 40002, 40003],
        Vec::new(),
        mapping(65_536, 65_536),
    ))
    .expect_err("full block");
    assert_eq!(failure.status(), 4);
    assert_eq!(
        failure.message(),
        "worker block 40000:4 is full with 4 live lanes"
    );
}

/// A block sharing any number with another registered principal is refused before any command.
///
/// ´claim:runworker:worker-blocks-are-disjoint-from-every-other-registered-number´
/// ´test:crate:overlapping-blocks-and-registered-uids-are-refused´
#[test]
fn overlapping_blocks_and_registered_uids_are_refused() {
    let limits = mapping(65_536, 65_536);
    let peer = |uid, block| {
        vec![Reservation {
            name: String::from("beta"),
            uid,
            block,
        }]
    };
    let overlap = allocate(&allocation(
        &[],
        peer(
            41002,
            Some(WorkerBlock {
                base: 40003,
                count: 8,
            }),
        ),
        limits,
    ))
    .expect_err("peer block overlap");
    assert_eq!(overlap.status(), 4);
    assert_eq!(
        overlap.message(),
        "worker block 40000:4 overlaps the block of loop beta"
    );
    let registered = allocate(&allocation(&[], peer(40002, None), limits))
        .expect_err("registered uid inside block");
    assert_eq!(
        registered.message(),
        "worker block 40000:4 contains the registered uid 40002 of loop beta"
    );
    let mut deployment = allocation(&[], Vec::new(), limits);
    deployment.deployment_uid = 40001;
    assert_eq!(
        allocate(&deployment)
            .expect_err("deployment uid inside block")
            .message(),
        "worker block 40000:4 contains the deployment uid 40001"
    );
}

/// Both subordinate files are read, because a GID beyond its count fails as an unmapped UID does.
///
/// ´claim:runworker:a-block-is-validated-against-the-mapping-the-deployment-account-has´
/// ´test:crate:blocks-beyond-either-fixture-subordinate-count-are-refused´
#[test]
fn blocks_beyond_either_fixture_subordinate_count_are_refused() {
    let beyond_uids = allocate(&allocation(&[], Vec::new(), mapping(39_999, 65_536)))
        .expect_err("block beyond the subordinate uid count");
    assert_eq!(beyond_uids.status(), 4);
    assert_eq!(
        beyond_uids.message(),
        "worker block 40000:4 tops 40003 beyond the subordinate uid count 39999"
    );
    assert_eq!(
        allocate(&allocation(&[], Vec::new(), mapping(65_536, 40_002)))
            .expect_err("block beyond the subordinate gid count")
            .message(),
        "worker block 40000:4 tops 40003 beyond the subordinate gid count 40002"
    );
    assert_eq!(
        allocate(&allocation(&[], Vec::new(), mapping(40_003, 40_003))).expect("exact fit"),
        40000
    );
}

/// The account and its counts come from the deployment's own files, not from a constant.
///
/// ´claim:runworker:the-deployment-account-is-read-from-the-passwd-database´
/// ´test:crate:the-account-and-its-subordinate-counts-are-read-from-fixture-files´
#[test]
fn the_account_and_its_subordinate_counts_are_read_from_fixture_files() {
    let fixture = Fixture::new("account");
    let account = deployment_account(&fixture.path, &fixture.path.join("passwd"))
        .expect("account of the fixture uid");
    assert_eq!(account.name, "deploy");
    assert_eq!(account.uid, fixture.uid());
    assert_eq!(
        subordinate_counts(
            "deploy",
            &fixture.path.join("subuid"),
            &fixture.path.join("subgid")
        )
        .expect("fixture mapping"),
        mapping(65_536, 65_536)
    );
    let missing = subordinate_counts(
        "nobody",
        &fixture.path.join("subuid"),
        &fixture.path.join("subgid"),
    )
    .expect_err("unmapped account");
    assert_eq!(missing.status(), 4);
    assert_eq!(
        missing.message(),
        "no subordinate uid mapping for account nobody"
    );
}

/// The composition is byte-stable against the entry command's measured requirements.
///
/// ´claim:runworker:a-worker-entry-is-one-outer-command-and-one-nested-mount-namespace´
/// ´test:crate:a-worker-entry-produces-the-exact-outer-and-inner-scripts´
#[test]
fn a_worker_entry_produces_the_exact_outer_and_inner_scripts() {
    let request = request("/srv/alpha/workers/rw1/home", &["printf", "ok"]);
    let expected_inner = concat!(
        "set -e\nt=$1\n",
        "mount --bind \"$t/passwd\" /etc/passwd\n",
        "mount --bind \"$t/group\" /etc/group\n",
        "mount --bind \"$t/ssh_config.d\" /etc/ssh/ssh_config.d\n",
        "exec setpriv --reuid=40000 --regid=40000 --groups=41001 --no-new-privs env -i ",
        "HOME=/srv/alpha/workers/rw1/home USER=alpha-rw1 LOGNAME=alpha-rw1 SHELL=/bin/bash ",
        "PATH=/srv/alpha/workers/rw1/home/.local/bin:/usr/local/bin:/usr/bin:/bin ",
        "TERM=vt100 LANG=C.UTF-8 TMPDIR=/srv/alpha/workers/rw1/home/.cache/tmp ",
        "XDG_RUNTIME_DIR=/srv/alpha/workers/rw1/home/.run ",
        "XDG_CONFIG_HOME=/srv/alpha/workers/rw1/home/.config ",
        "XDG_CACHE_HOME=/srv/alpha/workers/rw1/home/.cache ",
        "XDG_DATA_HOME=/srv/alpha/workers/rw1/home/.local/share ",
        "XDG_STATE_HOME=/srv/alpha/workers/rw1/home/.local/state ",
        "CLAUDE_CONFIG_DIR=/srv/alpha/workers/rw1/home/.claude printf ok"
    );
    assert_eq!(inner_script(&request), expected_inner);
    assert!(!inner_script(&request).contains(".config/loops/"));
    let expected_outer = format!(
        concat!(
            "set -e\nt=$(mktemp -d /tmp/worker-run.XXXXXX)\ncleanup() {{\n    rm -rf \"$t\"\n}}\n",
            "trap cleanup EXIT\ncat /etc/passwd > \"$t/passwd\"\n",
            "printf '%s\\n' 'alpha-rw1:x:40000:40000:alpha lane rw1:/srv/alpha/workers/rw1/home:/bin/bash' >> \"$t/passwd\"\n",
            "cat /etc/group > \"$t/group\"\n",
            "printf '%s\\n' 'alpha-rw1:x:40000:' >> \"$t/group\"\n",
            "printf '%s\\n' 'alpha:x:41001:alpha-rw1' >> \"$t/group\"\n",
            "mkdir -p \"$t/ssh_config.d\"\n",
            "set +e\nunshare -m sh -c '{expected_inner}' sh \"$t\"\nrc=$?\nset -e\n",
            "rm -rf \"$t\"\ntrap - EXIT\nexit \"$rc\""
        ),
        expected_inner = expected_inner
    );
    assert_eq!(outer_script(&request, None), expected_outer);
    let plan = worker_entry_plan(&request, &[String::from("podman")], None, IoMode::Inherit);
    assert_eq!(plan.command.label, "drop");
    assert_eq!(
        plan.command.argv,
        ["podman", "unshare", "sh", "-c"]
            .into_iter()
            .map(String::from)
            .chain([expected_outer])
            .collect::<Vec<_>>()
    );
}

/// The monitor records both PIDs and notifies without stopping the worker.
///
/// ´claim:runworker:the-monitor-writes-both-pids-and-notifies-at-budget´
/// ´test:crate:the-monitored-outer-script-writes-both-pids-and-notifies-at-budget´
#[test]
fn the_monitored_outer_script_writes_both_pids_and_notifies_at_budget() {
    let request = request("/srv/alpha/workers/rw1/home", &["true"]);
    let monitor = MonitorRequest {
        lock: String::from("/srv/alpha/workers/rw1/monitor.lock"),
        evidence: String::from("/srv/alpha/runs/40000/budget-notice.txt"),
        lane: String::from("rw1"),
        budget_seconds: 1800,
        grace_seconds: 10,
    };
    let script = outer_script(&request, Some(&monitor));
    let expected_body = concat!(
        "printf '%s\\n' \"$$\" > /srv/alpha/workers/rw1/monitor.lock\nset +e\n",
        "unshare -m sh -c '",
    );
    assert!(script.contains(expected_body));
    assert!(script.contains("' sh \"$t\" &\nchild=$!\nprintf '%s\\n' \"$child\" >> /srv/alpha/workers/rw1/monitor.lock\n"));
    assert!(script.contains(concat!(
        "( sleep 1800; ",
        "printf 'lane=%s\\nuid=%s\\nchild=%s\\nbudget=%s\\nstate=over-budget\\naction=notify\\nobserved=%s\\n' ",
        "rw1 40000 \"$child\" 1800 \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" > /srv/alpha/runs/40000/budget-notice.txt ) &\n",
        "guard=$!\nwait \"$child\"\nrc=$?\nkill \"$guard\" 2>/dev/null\nwait \"$guard\" 2>/dev/null\nset -e\n",
        "rm -rf \"$t\"\ntrap - EXIT\nexit \"$rc\""
    )));
    assert!(!script.contains("kill-evidence.txt"));
    assert!(!script.contains("pkill"));
    assert!(!script.contains("kill -TERM"));
}

/// Home and command words survive both shell layers without becoming executable syntax.
///
/// ´claim:runworker:every-substituted-worker-value-is-shell-quoted´
/// ´test:crate:space-home-and-single-quote-command-are-quoted´
#[test]
fn space_home_and_single_quote_command_are_quoted() {
    let request = request("/srv/with space/home", &["that's-fine"]);
    let inner = inner_script(&request);
    assert!(inner.contains("HOME='/srv/with space/home'"));
    assert!(inner.ends_with("'that'\\''s-fine'"));
    let outer = outer_script(&request, None);
    assert!(outer.contains("alpha lane rw1:/srv/with space/home:/bin/bash"));
    assert!(outer.contains("'\\''that'\\''\\'\\'''\\''s-fine'\\'''"));
}

/// Each path is created with its stated owner, group, mode, and stage, in the stated order.
///
/// ´claim:runworker:every-layout-row-carries-a-stated-owner-group-and-mode´
/// ´test:crate:every-layout-row-carries-its-stated-owner-group-and-mode´
#[test]
fn every_layout_row_carries_its_stated_owner_group_and_mode() {
    let fixture = Fixture::new("layout");
    let placement = fixture.placement(40000, None);
    let rows = layout_plan(&placement);
    let home = fixture.home();
    let lane = home.join("workers").join("rw1");
    let worker_home = lane.join("home");
    let expected: Vec<(PathBuf, Owner, Group, u32, Stage)> = vec![
        (
            home.join("workers"),
            Owner::Loop,
            Group::Loop,
            0o710,
            Stage::Prepare,
        ),
        (
            lane.clone(),
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
        (
            lane.join("clone"),
            Owner::Worker,
            Group::Lane,
            0o700,
            Stage::Prepare,
        ),
        (
            worker_home.clone(),
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
        (
            worker_home.join(".claude"),
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
    ];
    for (index, (path, owner, group, mode, stage)) in expected.into_iter().enumerate() {
        assert_eq!(rows[index].path, path);
        assert_eq!(rows[index].owner, owner);
        assert_eq!(rows[index].group, group);
        assert_eq!(rows[index].mode, mode);
        assert_eq!(rows[index].stage, stage);
    }
    let children: Vec<_> = rows[5..16]
        .iter()
        .map(|row| {
            assert_eq!(row.owner, Owner::Worker);
            assert_eq!(row.group, Group::Lane);
            assert_eq!(row.mode, 0o700);
            row.path
                .strip_prefix(&worker_home)
                .expect("home child")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(children, crate::layout::HARNESS_CHILDREN.map(String::from));
    let tail: Vec<_> = rows[16..]
        .iter()
        .map(|row| (row.path.clone(), row.mode, row.stage))
        .collect();
    assert_eq!(
        tail,
        vec![
            (lane.join("brief.md"), 0o640, Stage::Prepare),
            (home.join("runs"), 0o755, Stage::Prepare),
            (
                worker_home.join(".claude").join("settings.json"),
                0o640,
                Stage::Launch
            ),
            (
                worker_home.join(".claude").join("CLAUDE.md"),
                0,
                Stage::Launch
            ),
            (worker_home.join(".claude").join("logins"), 0, Stage::Launch),
            (lane.join("identity.env"), 0o640, Stage::Launch),
            (lane.join("monitor.lock"), 0o640, Stage::Launch),
            (home.join("runs").join("40000"), 0o755, Stage::Launch),
        ]
    );
    assert_eq!(
        rows[19].node,
        Node::Link(fixture.estate().join("charters").join("worker.md"))
    );
    assert_eq!(
        rows[20].node,
        Node::Link(home.join("shared").join("logins"))
    );
    assert_eq!(rows[20].owner, Owner::Loop);
    assert_eq!(rows[20].group, Group::Lane);
}

/// The records a worker is judged by are data about it, written byte for byte.
///
/// ´claim:runworker:identity-and-launch-records-are-byte-stable´
/// ´test:crate:identity-and-launch-records-are-byte-stable´
#[test]
fn identity_and_launch_records_are_byte_stable() {
    let fixture = Fixture::new("records");
    let launch = LaunchEnv {
        driver: String::from("claude"),
        model: String::from("claude-opus-5"),
        effort: String::from("xhigh"),
        budget: 1800,
        started: String::from("2023-11-14T22:13:20Z"),
    };
    let placement = fixture.placement(40000, Some(launch));
    let home = fixture.home();
    assert_eq!(
        placement.identity_env(),
        format!(
            "LANE=rw1\nLOOP=alpha\nWORKER_UID=40000\nWORKER_GID=40000\nLOOP_GID=41001\nROLE=worker\nRUN_DIR={}\nRUBRIC={}\nESTATE={}\n",
            home.join("runs").join("40000").display(),
            home.join("shared")
                .join("permissions")
                .join("domain.md")
                .display(),
            fixture.estate().display()
        )
    );
    assert_eq!(
        placement.launch.as_ref().expect("launch record").text(),
        "DRIVER=claude\nMODEL=claude-opus-5\nEFFORT=xhigh\nBUDGET=1800\nSTARTED=2023-11-14T22:13:20Z\n"
    );
    assert_eq!(
        placement.settings_json(),
        format!(
            "{{\"hooks\":{{\"PreToolUse\":[{{\"hooks\":[{{\"command\":\"'{}' pre-tool-use\",\"type\":\"command\"}}],\"matcher\":\"*\"}}]}}}}\n",
            fixture
                .estate()
                .join("hooks")
                .join("superloop-claude-hook")
                .display()
        )
    );
    assert_eq!(utc_stamp(1_700_000_000), "2023-11-14T22:13:20Z");
    fs::create_dir_all(fixture.home().join("runs")).expect("create table directory");
    for stamp in [
        "2023-11-14T22:13:20",
        "2023-11-15T00:13:20+02:00",
        "2026-02-29T00:00:00Z",
        "2026-02-31T00:00:00Z",
        "2026-01-01T00:00:60Z",
    ] {
        fs::write(
            fixture.table(),
            format!("{}\n40000\trw1\tclaude\tabc123\t{stamp}\n", table::HEADER),
        )
        .expect("write invalid table");
        let error = table::read_rows(&fixture.table()).expect_err("invalid start refused");
        assert!(error.to_string().contains(stamp));
        assert_eq!(epoch_from_stamp(stamp), None);
    }
    for stamp in ["", "2024-02-29T00:00:00Z"] {
        fs::write(
            fixture.table(),
            format!("{}\n40000\trw1\tclaude\tabc123\t{stamp}\n", table::HEADER),
        )
        .expect("write valid table");
        let rows = table::read_rows(&fixture.table()).expect("valid start");
        assert_eq!(rows[0].started, stamp);
    }
}

/// ´claim:worker:configured-hook-registration-quotes-path-and-refuses-relative-path´
/// ´test:crate:configured-hook-registration-quotes-path-and-refuses-relative-path´
#[test]
fn configured_hook_registration_quotes_path_and_refuses_relative_path() {
    let fixture = Fixture::new("configured-hook");
    let mut placement = fixture.placement(40000, None);
    let hook = fixture.path.join("hook ' \" $literal");
    fs::write(&hook, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").expect("fixture adapter");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).expect("executable");
    placement.claude_hook = hook;
    let settings: serde_json::Value =
        serde_json::from_str(&placement.settings_json()).expect("settings JSON");
    let command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .expect("command");
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", command])
        .output()
        .expect("generated command");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"pre-tool-use\n");
    assert_eq!(output.stderr, [] as [u8; 0]);
    let mut environment = fixture.environment();
    environment.claude_hook = PathBuf::from("relative-adapter");
    let mut runner = FakeNamespace::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = run_worker_entry(
        fixture.launch_arguments(),
        &environment,
        &mut runner,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(status, 4);
    assert!(String::from_utf8_lossy(&stderr).contains("absolute UTF-8 path"));
    assert_eq!(runner.commands, [] as [CommandSpec; 0]);
}

/// A crash between owning and dropping must leave a tree nothing runs as, so ownership is last.
///
/// ´claim:runworker:modes-are-applied-before-ownership-and-ownership-is-last´
/// ´test:crate:modes-precede-ownership-and-the-clone-is-owned-recursively´
#[test]
fn modes_precede_ownership_and_the_clone_is_owned_recursively() {
    let fixture = Fixture::new("ownership");
    let placement = fixture.placement(40000, None);
    let rows = layout_plan(&placement);
    let commands = ownership_commands(&placement, &rows, &[String::from("podman")]);
    let labels: Vec<_> = commands
        .iter()
        .map(|command| command.label.as_str())
        .collect();
    let first_chown = labels
        .iter()
        .position(|label| *label == "layout-chown")
        .expect("an ownership command");
    assert!(
        labels[..first_chown]
            .iter()
            .all(|label| *label == "layout-chmod")
    );
    assert!(
        labels[first_chown..]
            .iter()
            .all(|label| *label == "layout-chown")
    );
    assert_eq!(labels.len(), 2 * (rows.len() - 3));
    assert_eq!(
        commands[0].argv,
        [
            "podman",
            "unshare",
            "chmod",
            "710",
            &fixture.home().join("workers").to_string_lossy()
        ]
        .map(String::from)
    );
    assert_eq!(
        commands[first_chown + 2].argv,
        [
            "podman",
            "unshare",
            "chown",
            "-R",
            "40000:40000",
            &fixture
                .home()
                .join("workers")
                .join("rw1")
                .join("clone")
                .to_string_lossy()
        ]
        .map(String::from)
    );
}

/// Preparation claims the slot in the table before it builds anything the lane will hold.
///
/// ´claim:runworker:preparation-claims-a-slot-then-builds-the-lane-tree´
/// ´test:crate:prepare-allocates-appends-the-row-and-clones-at-the-commit´
#[test]
fn prepare_allocates_appends_the_row_and_clones_at_the_commit() {
    let fixture = Fixture::new("prepare");
    let mut runner = FakeNamespace::head("abc123\n");
    let mut output = Vec::new();
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let status = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut output,
    )
    .expect("prepare succeeds");
    assert_eq!(status, 0);
    let evidence = String::from_utf8(output).expect("UTF-8 evidence");
    assert_eq!(
        evidence,
        format!(
            "PREPARE loop=alpha lane=rw1 uid=40000 commit=abc123 clone={}\n",
            fixture.clone_dir().display()
        )
    );
    assert_eq!(
        runner.labels(),
        [
            "layout-install",
            "clone",
            "checkout",
            "config-name",
            "config-email",
            "config-signing",
            "remote-remove",
            "rev-parse",
        ]
        .map(String::from)
    );
    assert_eq!(
        runner.commands[2].argv[5..],
        ["checkout", "--detach", "c0ffee"].map(String::from)
    );
    assert_eq!(
        runner.commands[7].argv,
        [
            "podman",
            "unshare",
            "git",
            "-C",
            &fixture.clone_dir().to_string_lossy(),
            "rev-parse",
            "HEAD",
        ]
        .map(String::from)
    );
    assert_eq!(
        fs::read_to_string(fixture.table()).expect("run table"),
        format!("{}\n40000\trw1\t\tabc123\t\n", table::HEADER)
    );
    let script = runner.script("layout-install");
    assert!(script.starts_with("set -e\nmkdir -p "));
    assert!(script.contains(&format!(
        "> '{}'",
        fixture.lane_dir().join("brief.md").display()
    )));
    assert!(!fixture.lane_dir().exists());
    let mut second = FakeNamespace::head("abc123");
    let repeat = execute(
        &invocation,
        &fixture.environment(),
        &mut second,
        &mut Vec::new(),
    )
    .expect_err("a live lane is refused");
    assert_eq!(repeat.status(), 4);
    assert_eq!(repeat.message(), "lane rw1 is already live at uid 40000");
    assert_eq!(second.commands, [] as [CommandSpec; 0]);
}

/// The table's commit is the clone's own head, read through the runner after the clone.
///
/// ´claim:runworker:the-row-records-the-commit-the-clone-resolved´
/// ´test:crate:the-row-records-the-runners-rev-parse-not-the-argument´
#[test]
fn the_row_records_the_runners_rev_parse_not_the_argument() {
    let fixture = Fixture::new("rev-parse");
    let mut runner = FakeNamespace::head("deadbeefcafe\n");
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect("prepare succeeds");
    let rows = table::read_rows(&fixture.table()).expect("run table");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].commit, "deadbeefcafe");
    assert_ne!(rows[0].commit, "c0ffee");
}

/// A clone that fails frees the slot it claimed, because no later subcommand can.
///
/// ´claim:runworker:a-failed-clone-frees-the-slot-it-claimed´
/// ´test:crate:a-failed-clone-leaves-no-row´
#[test]
fn a_failed_clone_leaves_no_row() {
    let fixture = Fixture::new("failed-clone");
    let mut runner = FakeNamespace {
        statuses: VecDeque::from([0, 3]),
        ..FakeNamespace::default()
    };
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let failure = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect_err("the clone fails");
    assert_eq!(failure.status(), 1);
    assert_eq!(failure.message(), "clone exited 3");
    assert_eq!(
        table::read_rows(&fixture.table()).expect("run table"),
        [] as [table::Row; 0]
    );
    let labels = runner.labels();
    assert_eq!(labels.last().map(String::as_str), Some("lane-remove"));
    assert_eq!(
        runner.commands.last().expect("the removal").argv,
        [
            "podman",
            "unshare",
            "rm",
            "-rf",
            &fixture.lane_dir().to_string_lossy()
        ]
        .map(String::from)
    );
}

/// A cleanup that fails is reported beside the cause, never in place of it.
///
/// ´claim:runworker:a-failed-cleanup-is-reported-beside-its-cause´
/// ´test:crate:a-failed-cleanup-keeps-the-clones-diagnostic´
#[test]
fn a_failed_cleanup_keeps_the_clones_diagnostic() {
    let fixture = Fixture::new("failed-cleanup");
    let mut runner = FakeNamespace {
        statuses: VecDeque::from([0, 3, 9]),
        ..FakeNamespace::default()
    };
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let failure = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect_err("the clone fails");
    assert_eq!(
        failure.message(),
        "clone exited 3; the lane tree could not be removed: lane-remove exited 9"
    );
}

/// The run tree belongs to the account that writes the run table, and is made by it.
///
/// ´claim:runworker:the-run-tree-is-the-launchers-own´
/// ´test:crate:the-run-tree-is-created-through-the-namespace-and-a-foreign-owner-is-refused´
#[test]
fn the_run_tree_is_created_through_the_namespace_and_a_foreign_owner_is_refused() {
    let fixture = Fixture::new("run-tree");
    let mut runner = FakeNamespace::head("abc123");
    let mut environment = fixture.environment();
    environment.owner_of = |_path| Ok(None);
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    execute(&invocation, &environment, &mut runner, &mut Vec::new()).expect("prepare succeeds");
    assert_eq!(
        runner.labels().first().map(String::as_str),
        Some("runs-install")
    );
    let runs = fixture.home().join("runs");
    assert_eq!(
        runner.commands[0].argv[..3],
        ["podman", "unshare", "sh"].map(String::from)
    );
    assert!(runner.commands[0].argv[4].contains(&format!("mkdir -p '{}'", runs.display())));
    assert!(runner.commands[0].argv[4].contains(&format!("chown 0:0 '{}'", runs.display())));
    assert!(runner.commands[0].argv[4].contains(&format!("chmod 755 '{}'", runs.display())));
    let install = runner.script("layout-install");
    assert!(!install.contains(&format!("mkdir -p '{}'\n", runs.display())));
    for command in &runner.commands {
        if command.label == "layout-chown" || command.label == "layout-chmod" {
            assert_ne!(
                command.argv.last().map(String::as_str),
                Some(runs.to_string_lossy().as_ref())
            );
        }
    }

    let mut foreign = fixture.environment();
    foreign.owner_of = |_path| Ok(Some(0));
    let mut idle = FakeNamespace::head("abc123");
    let refusal = execute(&invocation, &foreign, &mut idle, &mut Vec::new())
        .expect_err("a foreign run tree is refused");
    assert_eq!(refusal.status(), 4);
    assert_eq!(
        refusal.message(),
        format!(
            "run tree {} is owned by uid 0, not by the launcher's uid {}",
            runs.display(),
            fixture.uid()
        )
    );
    assert_eq!(idle.commands, [] as [CommandSpec; 0]);
}

/// An unreadable existing run tree cannot be mistaken for an absent one.
///
/// ´claim:runworker:an-unreadable-run-tree-owner-is-refused´
/// ´test:crate:an-unreadable-run-tree-owner-is-refused-before-the-runner´
#[test]
fn an_unreadable_run_tree_owner_is_refused_before_the_runner() {
    let fixture = Fixture::new("run-tree-owner-error");
    let mut environment = fixture.environment();
    environment.owner_of = |_path| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "probe denied",
        ))
    };
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let mut runner = FakeNamespace::default();
    let failure = execute(&invocation, &environment, &mut runner, &mut Vec::new())
        .expect_err("an unreadable owner is refused");
    assert_eq!(failure.status(), 4);
    assert_eq!(
        failure.message(),
        format!(
            "could not read owner of {}: probe denied",
            fixture.home().join("runs").display()
        )
    );
    assert_eq!(runner.commands, [] as [CommandSpec; 0]);
}

/// A start before the epoch is refused rather than reaching the era arithmetic.
///
/// ´claim:runworker:a-start-before-the-epoch-is-refused´
/// ´test:crate:a-start-before-the-epoch-is-refused-not-computed´
#[test]
fn a_start_before_the_epoch_is_refused_not_computed() {
    assert_eq!(epoch_from_stamp("1900-01-01T00:00:00Z"), None);
    assert_eq!(epoch_from_stamp("1969-12-31T23:59:59Z"), None);
    assert_eq!(epoch_from_stamp("1970-01-01T00:00:00Z"), Some(0));
    let fixture = Fixture::new("watch-old-start");
    fixture.live_run("DRIVER=claude\nBUDGET=1800\nSTARTED=1900-01-01T00:00:00Z\n");
    let mut error = Vec::new();
    let code = run_worker_entry(
        Fixture::watch_arguments(),
        &fixture.environment(),
        &mut FakeNamespace::default(),
        &mut Vec::new(),
        &mut error,
    );
    assert_eq!(code, 4);
    assert_eq!(
        String::from_utf8(error).expect("UTF-8 diagnostic"),
        "REFUSED launch record names an unreadable start: 1900-01-01T00:00:00Z\n"
    );
}

/// Sequential preparations take ascending slots, and a live UID is refused on the way in.
///
/// One lock in `claim_slot` spans reading the table, choosing from what it holds, and
/// writing the row back, which is the property that covers an interleaving no
/// single-threaded test can produce; the duplicate-UID guard asserted below is the
/// backstop that turns any lost race into a refusal rather than two lanes at one UID.
///
/// ´claim:runworker:one-lock-spans-reading-choosing-and-writing-a-slot´
/// ´test:crate:sequential-prepares-take-ascending-slots-and-a-live-uid-is-refused´
#[test]
fn sequential_prepares_take_ascending_slots_and_a_live_uid_is_refused() {
    let fixture = Fixture::new("slot-race");
    let environment = fixture.environment();
    for lane in ["rw1", "rw2"] {
        let mut arguments = fixture.prepare_arguments();
        arguments[2] = String::from(lane);
        let invocation = parse_invocation(arguments).expect("prepare parses");
        execute(
            &invocation,
            &environment,
            &mut FakeNamespace::head("abc123"),
            &mut Vec::new(),
        )
        .expect("prepare succeeds");
    }
    let rows = table::read_rows(&fixture.table()).expect("run table");
    let uids: Vec<_> = rows.iter().map(|row| row.uid).collect();
    let lanes: Vec<_> = rows.iter().map(|row| row.lane.clone()).collect();
    assert_eq!(uids, [40000, 40001]);
    assert_eq!(lanes, ["rw1", "rw2"].map(String::from));
    let duplicate = table::append_row(
        &fixture.table(),
        &table::Row {
            uid: 40000,
            lane: String::from("rw3"),
            driver: String::new(),
            commit: String::new(),
            started: String::new(),
        },
    )
    .expect_err("a duplicate uid is refused");
    assert_eq!(duplicate.status(), 4);
    assert_eq!(duplicate.message(), "uid 40000 is already live as lane rw1");
}

/// Nothing this process writes lands under a row the loop owns; one namespace command installs them.
///
/// ´claim:runworker:loop-owned-rows-are-installed-through-the-namespace´
/// ´test:crate:launch-installs-its-rows-through-the-namespace-and-drops-last´
#[test]
fn launch_installs_its_rows_through_the_namespace_and_drops_last() {
    let fixture = Fixture::new("launch");
    let environment = fixture.environment();
    let prepare = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    execute(
        &prepare,
        &environment,
        &mut FakeNamespace::head("abc123"),
        &mut Vec::new(),
    )
    .expect("prepare succeeds");
    let mut runner = FakeNamespace::default();
    let mut output = Vec::new();
    let launch = parse_invocation(fixture.launch_arguments()).expect("launch parses");
    let status = execute(&launch, &environment, &mut runner, &mut output).expect("launch succeeds");
    assert_eq!(status, 0);
    assert_eq!(
        String::from_utf8(output).expect("UTF-8 evidence"),
        format!(
            "LAUNCH loop=alpha lane=rw1 uid=40000 run={} driver=claude started=2023-11-14T22:13:20Z\n",
            fixture.home().join("runs").join("40000").display()
        )
    );
    let labels = runner.labels();
    assert_eq!(labels.first().map(String::as_str), Some("layout-install"));
    assert_eq!(labels.last().map(String::as_str), Some("drop"));
    let script = runner.script("layout-install");
    let lane_dir = fixture.lane_dir();
    let run_dir = fixture.home().join("runs").join("40000");
    for path in [
        lane_dir.join("identity.env"),
        lane_dir.join("monitor.lock"),
        lane_dir.join("home").join(".claude").join("settings.json"),
        lane_dir.join("home").join(".claude").join("CLAUDE.md"),
        lane_dir.join("home").join(".claude").join("logins"),
        run_dir.clone(),
        run_dir.join("launch.env"),
    ] {
        assert!(
            script.contains(&path.to_string_lossy().into_owned()),
            "install script names {}",
            path.display()
        );
        assert!(!path.exists(), "no in-process write at {}", path.display());
    }
    assert!(script.contains(&format!(
        "ln -sfn '{}' '{}'",
        fixture.home().join("shared").join("logins").display(),
        lane_dir.join("home").join(".claude").join("logins").display()
    )));
    let staged_identity = fs::read_to_string(
        fixture
            .path
            .join("staging")
            .join("worker-run-rw1-40000")
            .join("row-21"),
    )
    .expect("staged identity");
    assert!(staged_identity.starts_with("LANE=rw1\nLOOP=alpha\nWORKER_UID=40000\n"));
    assert_eq!(
        fs::read_to_string(fixture.table()).expect("run table"),
        format!(
            "{}\n40000\trw1\tclaude\tabc123\t2023-11-14T22:13:20Z\n",
            table::HEADER
        )
    );
    let drop_argv = runner.commands.last().expect("the drop").argv.join(" ");
    assert!(drop_argv.contains("/budget-notice.txt"));
    assert!(!drop_argv.contains("kill-evidence.txt"));
    assert!(drop_argv.contains("/usr/bin/claude-lane -C "));
    assert!(
        drop_argv.contains("-s workspace-write -m claude-opus-5 -e xhigh -t 1800 -n work - < ")
    );
}

/// Missing executable selectors cannot publish a launch row or invoke a namespace command.
/// ´claim:runworker:launch-refuses-missing-selectors-before-effects´
/// ´test:crate:launch-refuses-missing-selectors-before-effects´
#[test]
fn launch_refuses_missing_selectors_before_effects() {
    for (source, key) in [
        (
            "backend_argv = { claude = [\"/usr/bin/claude\"] }\n",
            "driver_argv",
        ),
        ("driver_argv = [\"/usr/bin/claude-lane\"]\n", "backend_argv"),
    ] {
        let fixture = Fixture::new(key);
        let settings = fixture.path.join(".config/loops/alpha/workers.toml");
        fs::write(settings, source).expect("incomplete settings");
        let mut runner = FakeNamespace::default();
        let launch = parse_invocation(fixture.launch_arguments()).expect("launch parses");
        let failure = execute(
            &launch,
            &fixture.environment(),
            &mut runner,
            &mut Vec::new(),
        )
        .expect_err("selector refusal");
        assert!(failure.to_string().contains(key));
        let prepare = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
        let failure = execute(
            &prepare,
            &fixture.environment(),
            &mut runner,
            &mut Vec::new(),
        )
        .expect_err("prepare selector refusal");
        assert!(failure.to_string().contains(key));
        assert_eq!(runner.commands, []);
        assert!(!fixture.table().exists());
    }
}

/// Each waiting outcome is decided by what the run directory holds, with its own status.
///
/// ´claim:runworker:waiting-distinguishes-report-escalation-stall-and-budget´
/// ´test:crate:every-watch-outcome-is-driven-by-the-files-a-test-writes´
#[test]
fn every_watch_outcome_is_driven_by_the_files_a_test_writes() {
    let fixture = Fixture::new("watch");
    let run_dir = fixture.home().join("runs").join("40000");
    fs::create_dir_all(&run_dir).expect("create run directory");
    let proc_root = fixture.path.join("proc");
    fs::create_dir_all(proc_root.join("4242")).expect("create process entry");
    let stall = Duration::from_secs(300);
    let budget = Duration::from_secs(1800);
    let read = || snapshot(&run_dir, 0, &proc_root, Some(4242)).expect("snapshot");

    let quiet = read();
    assert_eq!(
        evaluate(
            &quiet,
            Duration::from_secs(10),
            Duration::from_secs(10),
            stall,
            budget
        ),
        None
    );
    assert_eq!(
        evaluate(&quiet, Duration::from_secs(10), stall, stall, budget),
        Some(Outcome::Stall)
    );
    assert_eq!(
        evaluate(&quiet, budget, Duration::ZERO, stall, budget),
        Some(Outcome::Budget)
    );
    fs::write(run_dir.join("events.jsonl"), "{}\n").expect("write events");
    assert_eq!(read().events_size, 3);

    fs::write(
        run_dir.join("escalation.jsonl"),
        "{\"class\":\"suspicious\"}\n",
    )
    .expect("write escalation");
    let escalated = read();
    assert_eq!(
        evaluate(&escalated, Duration::ZERO, Duration::ZERO, stall, budget),
        Some(Outcome::Escalation(String::from(
            "{\"class\":\"suspicious\"}"
        )))
    );

    fs::write(run_dir.join("run-report.txt"), "RUN-REPORT exit=0\nmore\n").expect("write report");
    let reported = read();
    let outcome = evaluate(&reported, budget, stall, stall, budget).expect("a report wins");
    assert_eq!(outcome, Outcome::Report(String::from("RUN-REPORT exit=0")));
    assert_eq!(outcome.status(), 0);
    assert_eq!(outcome.word(), "report");
    assert_eq!(Outcome::Escalation(String::new()).status(), 3);
    assert_eq!(Outcome::Stall.status(), 42);
    assert_eq!(Outcome::Budget.status(), 5);

    let dead = snapshot(&run_dir, 0, &proc_root, Some(9)).expect("snapshot");
    assert_eq!(dead.child, Child::Gone);
    let unknown = snapshot(&run_dir, 0, &proc_root, None).expect("snapshot");
    assert_eq!(unknown.child, Child::Unknown);
}

/// Waiting is driven end to end: the row, the launch record, the evidence line, and the status.
///
/// ´claim:runworker:waiting-reports-one-evidence-line-and-its-status´
/// ´test:crate:watch-reports-the-run-report-through-execute´
#[test]
fn watch_reports_the_run_report_through_execute() {
    let fixture = Fixture::new("watch-execute");
    let run_dir = fixture.live_run("DRIVER=claude\nBUDGET=1800\nSTARTED=2023-11-14T22:13:20Z\n");
    fs::write(run_dir.join("run-report.txt"), "RUN-REPORT exit=0\nrest\n").expect("write report");
    let mut output = Vec::new();
    let invocation = parse_invocation(Fixture::watch_arguments()).expect("watch parses");
    let status = execute(
        &invocation,
        &fixture.environment(),
        &mut FakeNamespace::default(),
        &mut output,
    )
    .expect("watch returns");
    assert_eq!(status, 0);
    assert_eq!(
        String::from_utf8(output).expect("UTF-8 evidence"),
        "WATCH report loop=alpha lane=rw1 uid=40000 RUN-REPORT exit=0\n"
    );
}

/// A waiter attached late measures the budget from the lane's own start.
///
/// ´claim:runworker:the-budget-is-measured-from-the-lanes-recorded-start´
/// ´test:crate:the-elapsed-clock-is-seeded-from-the-launch-record´
#[test]
fn the_elapsed_clock_is_seeded_from_the_launch_record() {
    let fixture = Fixture::new("watch-clock");
    let run_dir = fixture.live_run("DRIVER=claude\nBUDGET=60\nSTARTED=2023-11-14T22:13:20Z\n");
    assert_eq!(
        epoch_from_stamp("2023-11-14T22:13:20Z"),
        Some(1_700_000_000)
    );
    assert_eq!(epoch_from_stamp("not a stamp"), None);
    let mut environment = fixture.environment();
    environment.now = 1_700_000_000 + 600;
    let mut output = Vec::new();
    let invocation = parse_invocation(Fixture::watch_arguments()).expect("watch parses");
    let status = execute(
        &invocation,
        &environment,
        &mut FakeNamespace::default(),
        &mut output,
    )
    .expect("watch returns");
    assert_eq!(status, 5);
    assert!(
        String::from_utf8(output)
            .expect("UTF-8 evidence")
            .starts_with("WATCH budget loop=alpha lane=rw1 uid=40000 ")
    );
    assert!(run_dir.join("launch.env").is_file());
}

/// A dead child with no report is a stalled step, not a wait to the budget.
///
/// ´claim:runworker:a-dead-child-without-a-report-is-stalled´
/// ´test:crate:a-dead-child-with-no-report-is-decided-as-a-stall´
#[test]
fn a_dead_child_with_no_report_is_decided_as_a_stall() {
    let fixture = Fixture::new("watch-dead");
    let run_dir = fixture.live_run("DRIVER=claude\nBUDGET=1800\nSTARTED=2023-11-14T22:13:20Z\n");
    fs::create_dir_all(fixture.path.join("proc")).expect("create process table");
    fs::write(fixture.lane_dir_lock(), "11\n4242\n").expect("write monitor lock");
    let mut output = Vec::new();
    let invocation = parse_invocation(Fixture::watch_arguments()).expect("watch parses");
    let status = execute(
        &invocation,
        &fixture.environment(),
        &mut FakeNamespace::default(),
        &mut output,
    )
    .expect("watch returns");
    assert_eq!(status, 42);
    assert!(
        String::from_utf8(output)
            .expect("UTF-8 evidence")
            .starts_with("WATCH stall loop=alpha lane=rw1 uid=40000 ")
    );
    assert!(!run_dir.join("run-report.txt").exists());
}

/// A waiter with no launch record refuses rather than inventing a budget.
///
/// ´claim:runworker:waiting-refuses-a-lane-with-no-launch-record´
/// ´test:crate:a-missing-launch-record-is-refused´
#[test]
fn a_missing_launch_record_is_refused() {
    let fixture = Fixture::new("watch-no-record");
    let run_dir = fixture.live_run("DRIVER=claude\nBUDGET=1800\nSTARTED=2023-11-14T22:13:20Z\n");
    fs::remove_file(run_dir.join("launch.env")).expect("remove launch record");
    let mut error = Vec::new();
    let code = run_worker_entry(
        Fixture::watch_arguments(),
        &fixture.environment(),
        &mut FakeNamespace::default(),
        &mut Vec::new(),
        &mut error,
    );
    assert_eq!(code, 4);
    assert!(
        String::from_utf8(error)
            .expect("UTF-8 diagnostic")
            .starts_with("REFUSED no launch record: ")
    );
}

/// A malformed peer row refuses the whole registry before allocation.
///
/// ´claim:runworker:a-malformed-peer-row-refuses-before-allocation´
/// ´test:crate:a-malformed-peer-registry-row-is-refused´
#[test]
fn a_malformed_peer_registry_row_is_refused() {
    let fixture = Fixture::new("bad-peer");
    fs::write(
        fixture.root().join("registry.toml"),
        "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [\n  { name = \"alpha\", uid = 41001, launch = \"dev/alpha\" },\n  { name = \"beta\", uid = \"nope\", launch = \"dev/beta\" },\n]\n",
    )
    .expect("rewrite registry");
    let mut runner = FakeNamespace::head("abc123");
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let failure = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect_err("a malformed peer is refused");
    assert_eq!(failure.status(), 4);
    assert_eq!(failure.message(), "malformed uid for loop: beta");
    assert_eq!(runner.commands, [] as [CommandSpec; 0]);
}

/// Lane names obey the portable account and path-component grammar at the CLI boundary.
///
/// ´claim:runworker:lane-names-are-validated-before-any-privileged-call´
/// ´test:crate:invalid-lane-names-are-usage-refusals-before-the-runner´
#[test]
fn invalid_lane_names_are_usage_refusals_before_the_runner() {
    let fixture = Fixture::new("lane-names");
    let environment = fixture.environment();
    for lane in ["../x", "/srv/other-loop", "tab\tlane", "", "Upper"] {
        let mut arguments = fixture.prepare_arguments();
        arguments[2] = String::from(lane);
        let mut runner = FakeNamespace::default();
        let mut error = Vec::new();
        let status = run_worker_entry(
            arguments,
            &environment,
            &mut runner,
            &mut Vec::new(),
            &mut error,
        );
        assert_eq!(status, 2);
        assert_eq!(
            String::from_utf8(error).expect("UTF-8 diagnostic"),
            format!("REFUSED bad lane name: {lane:?}\n")
        );
        assert_eq!(runner.commands, [] as [CommandSpec; 0]);
    }
    assert!(parse_invocation(fixture.prepare_arguments()).is_ok());
    assert_eq!(
        parse_invocation([
            "launch",
            "alpha",
            "Upper",
            "--driver",
            "claude",
            "--estate",
            "/srv/estate",
        ],)
        .expect_err("launch rejects the lane")
        .status(),
        2
    );
    assert_eq!(
        parse_invocation(["watch", "alpha", "Upper"])
            .expect_err("watch rejects the lane")
            .status(),
        2
    );
}

/// Every refusal is decided before the first privileged call, which leaves the runner log empty.
///
/// ´claim:runworker:refusals-precede-every-privileged-call´
/// ´test:crate:refusals-precede-every-privileged-call´
#[test]
fn refusals_precede_every_privileged_call() {
    let fixture = Fixture::new("refusals");
    let environment = fixture.environment();
    let launch_without_estate = {
        let mut arguments = fixture.launch_arguments();
        let index = arguments
            .iter()
            .position(|argument| argument == "--estate")
            .expect("estate option");
        arguments[index + 1] = fixture.path.join("absent").to_string_lossy().into_owned();
        arguments
    };
    let unknown_loop = {
        let mut arguments = fixture.prepare_arguments();
        arguments[1] = String::from("ghost");
        arguments
    };
    for (arguments, status, message) in [
        (unknown_loop, 4_u8, String::from("unknown loop: ghost")),
        (
            launch_without_estate,
            4_u8,
            format!(
                "no worker charter: {}",
                fixture
                    .path
                    .join("absent")
                    .join("charters")
                    .join("worker.md")
                    .display()
            ),
        ),
    ] {
        let mut runner = FakeNamespace::default();
        let mut output = Vec::new();
        let mut error = Vec::new();
        let code = run_worker_entry(
            arguments,
            &environment,
            &mut runner,
            &mut output,
            &mut error,
        );
        assert_eq!(code, status);
        assert_eq!(runner.commands, [] as [CommandSpec; 0]);
        assert_eq!(
            String::from_utf8(error).expect("UTF-8 diagnostic"),
            format!("REFUSED {message}\n")
        );
        assert!(
            String::from_utf8(output)
                .expect("UTF-8 report")
                .contains("RUN-REPORT exit=4 wall=")
        );
    }
}

/// A control byte in a refused path cannot add another diagnostic line.
/// ´claim:worker:allocation-refusal-escapes-control-bytes´
/// ´test:crate:allocation-refusal-escapes-control-bytes´
#[test]
fn allocation_refusal_escapes_control_bytes() {
    let fixture = Fixture::new("allocation-refusal-control");
    let mut environment = fixture.environment();
    environment.caller_home = fixture.path.join("missing\nowner");
    let mut runner = FakeNamespace::default();
    let mut error = Vec::new();
    let status = run_worker_entry(
        fixture.prepare_arguments(),
        &environment,
        &mut runner,
        &mut Vec::new(),
        &mut error,
    );
    assert_eq!(status, 4);
    let line = String::from_utf8(error).expect("UTF-8 diagnostic");
    assert_eq!(line.lines().count(), 1);
    assert!(line.starts_with("REFUSED "));
    assert!(line.contains("\\n"));
}

/// The deferred half of the contract is visible in the grammar rather than absent from it.
///
/// ´claim:runworker:the-second-bites-subcommands-parse-and-refuse´
/// ´test:crate:fetch-and-close-are-refused-with-a-usage-status´
#[test]
fn fetch_and_close_are_refused_with_a_usage_status() {
    for subcommand in ["fetch", "close"] {
        let failure =
            parse_invocation([subcommand, "alpha", "rw1"]).expect_err("a second-bite subcommand");
        assert_eq!(failure.status(), 2);
        assert_eq!(
            failure.message(),
            format!("{subcommand}: {}", crate::cli::SECOND_BITE)
        );
    }
    assert_eq!(
        parse_invocation(["launch", "alpha", "rw1", "--driver", "codex"])
            .expect_err("the Codex driver")
            .status(),
        2
    );
    assert_eq!(
        parse_invocation(["prepare", "alpha", "rw1", "c0ffee"])
            .expect_err("no hub")
            .message(),
        format!("missing --hub: {}", crate::cli::USAGE)
    );
    assert_eq!(
        parse_invocation(["watch", "alpha", "rw1", "--stall", "soon"])
            .expect_err("a word of seconds")
            .message(),
        "--stall takes whole seconds"
    );
    assert_eq!(
        parse_invocation(["watch", "alpha", "rw1", "--nope", "1"])
            .expect_err("an unknown option")
            .status(),
        2
    );
}

/// A record without a declared block cannot launch a worker at all.
///
/// ´claim:runworker:a-loop-without-a-declared-block-cannot-launch-a-worker´
/// ´test:crate:a-loop-without-a-block-is-refused-before-allocation´
#[test]
fn a_loop_without_a_block_is_refused_before_allocation() {
    let fixture = Fixture::new("no-block");
    fixture.write_allocations("[beta]\nuids = { base = 42000, count = 4 }\n");
    let mut runner = FakeNamespace::default();
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let failure = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect_err("no declared block");
    assert_eq!(failure.status(), 4);
    assert_eq!(
        failure.message(),
        "allocations: missing worker uid allocation for loop: alpha"
    );
    assert_eq!(runner.commands, [] as [CommandSpec; 0]);
}

/// Static allocation refusals are decided before an absent run tree is created.
///
/// ´claim:runworker:allocation-is-validated-before-the-run-tree-is-created´
/// ´test:crate:an-unmapped-block-with-no-run-tree-is-refused-before-the-runner´
#[test]
fn an_unmapped_block_with_no_run_tree_is_refused_before_the_runner() {
    let fixture = Fixture::new("unmapped-fresh-home");
    fs::remove_dir_all(fixture.home().join("runs")).expect("remove run tree");
    fs::write(fixture.path.join("subuid"), "deploy:100000:30000\n")
        .expect("rewrite subordinate uids");
    fs::write(fixture.path.join("subgid"), "deploy:100000:30000\n")
        .expect("rewrite subordinate gids");
    let invocation = parse_invocation(fixture.prepare_arguments()).expect("prepare parses");
    let mut runner = FakeNamespace::default();
    let failure = execute(
        &invocation,
        &fixture.environment(),
        &mut runner,
        &mut Vec::new(),
    )
    .expect_err("the unmapped block is refused");
    assert_eq!(failure.status(), 4);
    assert_eq!(
        failure.message(),
        "worker block 40000:4 tops 40003 beyond the subordinate uid count 30000"
    );
    assert_eq!(runner.commands, [] as [CommandSpec; 0]);
}
