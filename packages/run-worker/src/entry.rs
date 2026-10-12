use loop_home::{CommandSpec, IoMode};

/// The three credentials a dropped worker holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerCredentials {
    /// The loop whose block the UID came from.
    pub loop_name: String,
    /// The lane this UID is allocated to.
    pub lane: String,
    /// The allocated UID, which is also the worker's primary GID.
    pub uid: u32,
    /// The loop's GID, the worker's one supplementary group.
    pub loop_gid: u32,
}

impl WorkerCredentials {
    /// Return the passwd and group name of this worker.
    #[must_use]
    pub fn account(&self) -> String {
        format!("{}-{}", self.loop_name, self.lane)
    }

    /// Return the primary GID, which equals the allocated UID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.uid
    }

    /// Return the exact privilege-dropping words placed before `env -i`.
    #[must_use]
    pub fn drop_words(&self) -> Vec<String> {
        vec![
            String::from("setpriv"),
            format!("--reuid={}", self.uid),
            format!("--regid={}", self.gid()),
            format!("--groups={}", self.loop_gid),
            String::from("--no-new-privs"),
        ]
    }

    /// Return the worker's own group line and the loop's group line naming it a member.
    #[must_use]
    pub fn group_lines(&self) -> [String; 2] {
        [
            format!("{}:x:{}:", self.account(), self.gid()),
            format!("{}:x:{}:{}", self.loop_name, self.loop_gid, self.account()),
        ]
    }

    /// Return the temporary passwd line naming this worker at its home.
    #[must_use]
    pub fn passwd_line(&self, home: &str) -> String {
        format!(
            "{}:x:{}:{}:{} lane {}:{home}:/bin/bash",
            self.account(),
            self.uid,
            self.gid(),
            self.loop_name,
            self.lane
        )
    }
}

/// What the monitor does around the dropped child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorRequest {
    /// Absolute path of the lock carrying the monitor and child PIDs.
    pub lock: String,
    /// Absolute path of the notification written when the budget passes.
    pub evidence: String,
    /// Lane name recorded in the evidence.
    pub lane: String,
    /// Seconds the child may run before it is stopped.
    pub budget_seconds: u64,
    /// Retained compatibility setting; budget expiry never stops the worker.
    pub grace_seconds: u64,
}

/// One drop, its two scripts, and the exact podman argv carrying them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerEntryPlan {
    /// Script run inside the nested mount namespace.
    pub inner_script: String,
    /// Script run by the single outer podman invocation.
    pub outer_script: String,
    /// Exact podman argv.
    pub command: CommandSpec,
}

/// What the dropped child runs and the environment it runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRequest {
    /// The worker's credentials.
    pub credentials: WorkerCredentials,
    /// The worker's home, which is also its `HOME`.
    pub home: String,
    /// The command words executed after the drop.
    pub command: Vec<String>,
    /// Additional environment entries appended after the fixed set.
    pub extra_env: Vec<(String, String)>,
    /// The caller's terminal name.
    pub term: String,
    /// The caller's locale name.
    pub lang: String,
}

pub(crate) fn shell_word(value: &str) -> String {
    if value.is_empty() {
        return String::from("''");
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        return value.to_owned();
    }
    single_literal(value)
}

pub(crate) fn single_literal(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    quoted.push_str(&value.replace('\'', "'\\''"));
    quoted.push('\'');
    quoted
}

fn fixed_environment(request: &EntryRequest) -> String {
    let home = &request.home;
    let account = request.credentials.account();
    let mut assignments = vec![
        format!("HOME={}", shell_word(home)),
        format!("USER={}", shell_word(&account)),
        format!("LOGNAME={}", shell_word(&account)),
        String::from("SHELL=/bin/bash"),
        format!(
            "PATH={}",
            shell_word(&format!("{home}/.local/bin:/usr/local/bin:/usr/bin:/bin"))
        ),
        format!("TERM={}", shell_word(&request.term)),
        format!("LANG={}", shell_word(&request.lang)),
        format!("TMPDIR={}", shell_word(&format!("{home}/.cache/tmp"))),
        format!("XDG_RUNTIME_DIR={}", shell_word(&format!("{home}/.run"))),
        format!("XDG_CONFIG_HOME={}", shell_word(&format!("{home}/.config"))),
        format!("XDG_CACHE_HOME={}", shell_word(&format!("{home}/.cache"))),
        format!(
            "XDG_DATA_HOME={}",
            shell_word(&format!("{home}/.local/share"))
        ),
        format!(
            "XDG_STATE_HOME={}",
            shell_word(&format!("{home}/.local/state"))
        ),
    ];
    for (key, value) in &request.extra_env {
        assignments.push(format!("{key}={}", shell_word(value)));
    }
    assignments.join(" ")
}

/// Compose the script executed inside the nested mount namespace.
#[must_use]
pub fn inner_script(request: &EntryRequest) -> String {
    let command_line = request
        .command
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "set -e\nt=$1\nmount --bind \"$t/passwd\" /etc/passwd\nmount --bind \"$t/group\" /etc/group\nmount --bind \"$t/ssh_config.d\" /etc/ssh/ssh_config.d\nexec {} env -i {} {command_line}",
        request.credentials.drop_words().join(" "),
        fixed_environment(request),
    )
}

fn preamble(request: &EntryRequest) -> String {
    let [own_group, loop_group] = request.credentials.group_lines();
    format!(
        "set -e\nt=$(mktemp -d /tmp/worker-run.XXXXXX)\ncleanup() {{\n    rm -rf \"$t\"\n}}\ntrap cleanup EXIT\ncat /etc/passwd > \"$t/passwd\"\nprintf '%s\\n' {} >> \"$t/passwd\"\ncat /etc/group > \"$t/group\"\nprintf '%s\\n' {} >> \"$t/group\"\nprintf '%s\\n' {} >> \"$t/group\"\nmkdir -p \"$t/ssh_config.d\"",
        single_literal(&request.credentials.passwd_line(&request.home)),
        single_literal(&own_group),
        single_literal(&loop_group),
    )
}

fn monitored_body(inner: &str, monitor: &MonitorRequest, uid: u32) -> String {
    let lock = shell_word(&monitor.lock);
    let evidence = shell_word(&monitor.evidence);
    let guard = format!(
        "( sleep {}; printf 'lane=%s\\nuid=%s\\nchild=%s\\nbudget=%s\\nstate=over-budget\\naction=notify\\nobserved=%s\\n' {} {uid} \"$child\" {} \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" > {evidence} ) &",
        monitor.budget_seconds,
        shell_word(&monitor.lane),
        monitor.budget_seconds,
    );
    format!(
        "printf '%s\\n' \"$$\" > {lock}\nset +e\nunshare -m sh -c {} sh \"$t\" &\nchild=$!\nprintf '%s\\n' \"$child\" >> {lock}\n{guard}\nguard=$!\nwait \"$child\"\nrc=$?\nkill \"$guard\" 2>/dev/null\nwait \"$guard\" 2>/dev/null\nset -e",
        single_literal(inner),
    )
}

fn plain_body(inner: &str) -> String {
    format!(
        "set +e\nunshare -m sh -c {} sh \"$t\"\nrc=$?\nset -e",
        single_literal(inner),
    )
}

/// Compose the outer script, optionally wrapping the drop in the monitor.
#[must_use]
pub fn outer_script(request: &EntryRequest, monitor: Option<&MonitorRequest>) -> String {
    let inner = inner_script(request);
    let body = monitor.map_or_else(
        || plain_body(&inner),
        |monitor| monitored_body(&inner, monitor, request.credentials.uid),
    );
    format!(
        "{}\n{body}\nrm -rf \"$t\"\ntrap - EXIT\nexit \"$rc\"",
        preamble(request),
    )
}

/// Produce the one-podman worker entry plan.
#[must_use]
pub fn worker_entry_plan(
    request: &EntryRequest,
    podman: &[String],
    monitor: Option<&MonitorRequest>,
    io: IoMode,
) -> WorkerEntryPlan {
    let inner_script = inner_script(request);
    let outer_script = outer_script(request, monitor);
    let argv = podman
        .iter()
        .cloned()
        .chain([
            String::from("unshare"),
            String::from("sh"),
            String::from("-c"),
            outer_script.clone(),
        ])
        .collect();
    WorkerEntryPlan {
        inner_script,
        outer_script,
        command: CommandSpec {
            label: String::from("drop"),
            argv,
            io,
        },
    }
}
