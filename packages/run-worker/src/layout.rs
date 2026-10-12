use std::path::{Path, PathBuf};

use loop_home::{CommandSpec, IoMode};

use crate::entry::single_literal;

/// Which principal owns a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The loop, so the worker cannot unlink what is inside.
    Loop,
    /// The worker, so the lane can write it.
    Worker,
    /// The account this launcher runs as, which is the only writer of the run table.
    Launcher,
}

/// Which group a row carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// The loop's own group.
    Loop,
    /// This lane's own group, which is the worker's primary group.
    Lane,
}

/// Which subcommand creates a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Created at the loop UID before any slot is dropped into.
    Prepare,
    /// Created by the monitor at namespace root, before the drop.
    Launch,
}

/// What a row is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// A directory.
    Directory,
    /// A file with exact bytes.
    File(String),
    /// A symbolic link into the estate tree.
    Link(PathBuf),
}

/// One row of the layout table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutRow {
    /// Absolute path of the row.
    pub path: PathBuf,
    /// What the row is.
    pub node: Node,
    /// The principal the row ends up owned by.
    pub owner: Owner,
    /// The group the row carries.
    pub group: Group,
    /// The row's mode, zero for a link.
    pub mode: u32,
    /// The subcommand that creates the row.
    pub stage: Stage,
}

/// What `launch` records beside the run directory for a later waiter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchEnv {
    /// The driver word.
    pub driver: String,
    /// The model the driver runs.
    pub model: String,
    /// The effort the driver runs.
    pub effort: String,
    /// Seconds the child may run.
    pub budget: u64,
    /// The launch instant in UTC.
    pub started: String,
}

impl LaunchEnv {
    /// Return the record's exact bytes, one assignment per line.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "DRIVER={}\nMODEL={}\nEFFORT={}\nBUDGET={}\nSTARTED={}\n",
            self.driver, self.model, self.effort, self.budget, self.started
        )
    }
}

/// Where one lane's tree goes and which numbers it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The loop's home.
    pub home: PathBuf,
    /// The loop's registry name.
    pub loop_name: String,
    /// The loop's own UID, which is also its GID.
    pub loop_uid: u32,
    /// The lane name.
    pub lane: String,
    /// The allocated worker UID, which is also the lane's GID.
    pub uid: u32,
    /// The estate tree holding the charter.
    pub estate: PathBuf,
    /// The configured absolute private Claude adapter path.
    pub claude_hook: PathBuf,
    /// The brief copied beside the clone.
    pub brief: String,
    /// What `launch` records, absent while only `prepare` has run.
    pub launch: Option<LaunchEnv>,
    /// The UID this launcher runs as, which owns the run tree.
    pub launcher_uid: u32,
}

/// The harness children pre-created at the worker's UID inside its home.
pub const HARNESS_CHILDREN: [&str; 11] = [
    ".claude/projects",
    ".claude/todos",
    ".claude/statsig",
    ".claude/shell-snapshots",
    ".run",
    ".config",
    ".cache",
    ".cache/tmp",
    ".local",
    ".local/share",
    ".local/state",
];

impl Placement {
    /// Return the lane's own tree.
    #[must_use]
    pub fn lane_dir(&self) -> PathBuf {
        self.home.join("workers").join(&self.lane)
    }

    /// Return the lane's clone.
    #[must_use]
    pub fn clone_dir(&self) -> PathBuf {
        self.lane_dir().join("clone")
    }

    /// Return the worker's home.
    #[must_use]
    pub fn worker_home(&self) -> PathBuf {
        self.lane_dir().join("home")
    }

    /// Return the lane's public run directory.
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.home.join("runs").join(self.uid.to_string())
    }

    /// Return the run table.
    #[must_use]
    pub fn table(&self) -> PathBuf {
        self.home.join("runs").join("table.tsv")
    }

    /// Return the monitor's lock.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.lane_dir().join("monitor.lock")
    }

    /// Return the worker rubric the identity file names.
    #[must_use]
    pub fn rubric(&self) -> PathBuf {
        self.home
            .join("shared")
            .join("permissions")
            .join("domain.md")
    }

    /// Return the private Claude adapter this lane registers.
    #[must_use]
    pub fn hook(&self) -> PathBuf {
        self.claude_hook.clone()
    }

    /// Return the worker charter this lane links.
    #[must_use]
    pub fn charter(&self) -> PathBuf {
        self.estate.join("charters").join("worker.md")
    }

    /// Return the loop's shared sign-in directory this lane links.
    #[must_use]
    pub fn logins(&self) -> PathBuf {
        self.home.join("shared").join("logins")
    }

    /// Return the identity file's exact bytes.
    #[must_use]
    pub fn identity_env(&self) -> String {
        let fields = [
            (String::from("LANE"), self.lane.clone()),
            (String::from("LOOP"), self.loop_name.clone()),
            (String::from("WORKER_UID"), self.uid.to_string()),
            (String::from("WORKER_GID"), self.uid.to_string()),
            (String::from("LOOP_GID"), self.loop_uid.to_string()),
            (String::from("ROLE"), String::from("worker")),
            (String::from("RUN_DIR"), display(&self.run_dir())),
            (String::from("RUBRIC"), display(&self.rubric())),
            (String::from("ESTATE"), display(&self.estate)),
        ];
        let mut text = String::new();
        for (key, value) in fields {
            text.push_str(&key);
            text.push('=');
            text.push_str(&value);
            text.push('\n');
        }
        text
    }

    /// Return the settings file registering the classifier hook.
    #[must_use]
    pub fn settings_json(&self) -> String {
        let command = format!("{} pre-tool-use", single_literal(&display(&self.hook())));
        let document = serde_json::json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":command}]}]}});
        format!("{document}\n")
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

const fn row(
    path: PathBuf,
    node: Node,
    owner: Owner,
    group: Group,
    mode: u32,
    stage: Stage,
) -> LayoutRow {
    LayoutRow {
        path,
        node,
        owner,
        group,
        mode,
        stage,
    }
}

fn prepare_rows(placement: &Placement) -> Vec<LayoutRow> {
    let lane_dir = placement.lane_dir();
    let worker_home = placement.worker_home();
    let mut rows = vec![
        row(
            placement.home.join("workers"),
            Node::Directory,
            Owner::Loop,
            Group::Loop,
            0o710,
            Stage::Prepare,
        ),
        row(
            lane_dir.clone(),
            Node::Directory,
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
        row(
            placement.clone_dir(),
            Node::Directory,
            Owner::Worker,
            Group::Lane,
            0o700,
            Stage::Prepare,
        ),
        row(
            worker_home.clone(),
            Node::Directory,
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
        row(
            worker_home.join(".claude"),
            Node::Directory,
            Owner::Loop,
            Group::Lane,
            0o750,
            Stage::Prepare,
        ),
    ];
    rows.extend(HARNESS_CHILDREN.iter().map(|child| {
        row(
            worker_home.join(child),
            Node::Directory,
            Owner::Worker,
            Group::Lane,
            0o700,
            Stage::Prepare,
        )
    }));
    rows.extend([
        row(
            lane_dir.join("brief.md"),
            Node::File(placement.brief.clone()),
            Owner::Loop,
            Group::Lane,
            0o640,
            Stage::Prepare,
        ),
        row(
            placement.home.join("runs"),
            Node::Directory,
            Owner::Launcher,
            Group::Loop,
            0o755,
            Stage::Prepare,
        ),
    ]);
    rows
}

fn launch_rows(placement: &Placement) -> Vec<LayoutRow> {
    let lane_dir = placement.lane_dir();
    let worker_home = placement.worker_home();
    let mut rows = vec![
        row(
            worker_home.join(".claude").join("settings.json"),
            Node::File(placement.settings_json()),
            Owner::Loop,
            Group::Lane,
            0o640,
            Stage::Launch,
        ),
        row(
            worker_home.join(".claude").join("CLAUDE.md"),
            Node::Link(placement.charter()),
            Owner::Loop,
            Group::Lane,
            0,
            Stage::Launch,
        ),
        row(
            worker_home.join(".claude").join("logins"),
            Node::Link(placement.logins()),
            Owner::Loop,
            Group::Lane,
            0,
            Stage::Launch,
        ),
        row(
            lane_dir.join("identity.env"),
            Node::File(placement.identity_env()),
            Owner::Loop,
            Group::Lane,
            0o640,
            Stage::Launch,
        ),
        row(
            placement.lock(),
            Node::File(String::new()),
            Owner::Loop,
            Group::Lane,
            0o640,
            Stage::Launch,
        ),
        row(
            placement.run_dir(),
            Node::Directory,
            Owner::Worker,
            Group::Lane,
            0o755,
            Stage::Launch,
        ),
    ];
    if let Some(launch) = &placement.launch {
        rows.push(row(
            placement.run_dir().join("launch.env"),
            Node::File(launch.text()),
            Owner::Loop,
            Group::Lane,
            0o644,
            Stage::Launch,
        ));
    }
    rows
}

/// Produce every row this launcher builds, in the layout table's order.
#[must_use]
pub fn layout_plan(placement: &Placement) -> Vec<LayoutRow> {
    let mut rows = prepare_rows(placement);
    rows.extend(launch_rows(placement));
    rows
}

/// Name the staging file one row's bytes are written to before installation.
#[must_use]
pub fn staged(staging: &Path, index: usize) -> PathBuf {
    staging.join(format!("row-{index}"))
}

/// Compose the script that installs one stage's rows inside the namespace.
///
/// The rows live under parents the loop owns, and the account that runs this
/// launcher is the deployment account, which owns none of them: only root inside
/// the user namespace can write there. So the bytes are staged where the
/// deployment account can write and installed by one namespace command, and
/// nothing this process writes lands under a loop-owned row.
#[must_use]
pub fn install_script(rows: &[LayoutRow], stage: Stage, staging: &Path) -> String {
    let mut script = String::from("set -e");
    for (index, layout_row) in rows.iter().enumerate() {
        if layout_row.stage != stage || layout_row.owner == Owner::Launcher {
            continue;
        }
        let path = single_literal(&display(&layout_row.path));
        let line = match &layout_row.node {
            Node::Directory => format!("mkdir -p {path}"),
            Node::File(_) => format!(
                "cat {} > {path}",
                single_literal(&display(&staged(staging, index)))
            ),
            Node::Link(target) => format!("ln -sfn {} {path}", single_literal(&display(target))),
        };
        script.push('\n');
        script.push_str(&line);
    }
    script
}

/// Compose the command that creates the launcher's own run tree.
///
/// Root inside the user namespace is the launcher's account outside it, so a run
/// tree created this way belongs to the account that writes the run table, while
/// the loop keeps the read and traverse that 0755 already gives it.
#[must_use]
pub fn run_tree_command(runs: &Path, podman: &[String]) -> CommandSpec {
    let path = single_literal(&display(runs));
    CommandSpec {
        label: String::from("runs-install"),
        argv: podman
            .iter()
            .cloned()
            .chain([
                String::from("unshare"),
                String::from("sh"),
                String::from("-c"),
                format!("set -e\nmkdir -p {path}\nchown 0:0 {path}\nchmod 755 {path}"),
            ])
            .collect(),
        io: IoMode::Inherit,
    }
}

/// Produce the one namespace command that installs a stage's rows.
#[must_use]
pub fn install_command(
    rows: &[LayoutRow],
    stage: Stage,
    staging: &Path,
    podman: &[String],
) -> CommandSpec {
    CommandSpec {
        label: String::from("layout-install"),
        argv: podman
            .iter()
            .cloned()
            .chain([
                String::from("unshare"),
                String::from("sh"),
                String::from("-c"),
                install_script(rows, stage, staging),
            ])
            .collect(),
        io: IoMode::Inherit,
    }
}

const fn numbers(placement: &Placement, layout_row: &LayoutRow) -> (u32, u32) {
    let owner = match layout_row.owner {
        Owner::Loop => placement.loop_uid,
        Owner::Worker => placement.uid,
        Owner::Launcher => placement.launcher_uid,
    };
    let group = match layout_row.group {
        Group::Loop => placement.loop_uid,
        Group::Lane => placement.uid,
    };
    (owner, group)
}

/// Produce the namespace-root mode and ownership commands, ownership last.
#[must_use]
pub fn ownership_commands(
    placement: &Placement,
    rows: &[LayoutRow],
    podman: &[String],
) -> Vec<CommandSpec> {
    let command = |label: &str, words: Vec<String>| CommandSpec {
        label: String::from(label),
        argv: podman
            .iter()
            .cloned()
            .chain([String::from("unshare")])
            .chain(words)
            .collect(),
        io: IoMode::Inherit,
    };
    let changeable = || {
        rows.iter().filter(|layout_row| {
            !matches!(layout_row.node, Node::Link(_)) && layout_row.owner != Owner::Launcher
        })
    };
    let clone_dir = placement.clone_dir();
    let modes = changeable().map(|layout_row| {
        command(
            "layout-chmod",
            vec![
                String::from("chmod"),
                format!("{:o}", layout_row.mode),
                display(&layout_row.path),
            ],
        )
    });
    let owners = changeable().map(|layout_row| {
        let (owner, group) = numbers(placement, layout_row);
        let mut words = vec![String::from("chown")];
        if layout_row.path == clone_dir {
            words.push(String::from("-R"));
        }
        words.push(format!("{owner}:{group}"));
        words.push(display(&layout_row.path));
        command("layout-chown", words)
    });
    modes.chain(owners).collect()
}
