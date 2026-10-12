//! Keep host-observed vendor phases in protected run custody.

use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, fchmod, fstat};
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::home;
use crate::plan::verify_box_attestation;
use crate::valid_run_name;

use super::checkout;

const RECORD: &str = "network-evidence.json";
const ATTEMPT: &str = "network-evidence-attempt.json";
const LIMIT: usize = 65_536;

#[cfg(test)]
std::thread_local! {
    static FAIL_VERIFY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_RECORD_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_WITHDRAW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn error(detail: impl Into<String>) -> LaneError {
    LaneError::input("network-evidence-record", detail.into())
}

fn custody(runs: &OwnedFd, run: &str, owner: u32) -> Result<OwnedFd, LaneError> {
    let name = format!(".launch-{run}");
    let directory = openat2(
        runs,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|cause| error(format!("run custody is absent: {cause}")))?;
    let stat = fstat(&directory).map_err(|cause| error(cause.to_string()))?;
    if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
        return Err(error("run custody owner or mode differs"));
    }
    Ok(directory)
}

fn read_leaf(directory: &OwnedFd, name: &str, owner: u32) -> Result<Option<Vec<u8>>, LaneError> {
    let descriptor = match openat2(
        directory,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(descriptor) => descriptor,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(cause) => return Err(error(format!("{name}: {cause}"))),
    };
    let stat = fstat(&descriptor).map_err(|cause| error(cause.to_string()))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size < 0
        || !usize::try_from(stat.st_size).is_ok_and(|size| size <= LIMIT)
    {
        return Err(error(format!("{name} owner, mode or size differs")));
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|cause| error(format!("{name}: {cause}")))?;
    if bytes.len() > LIMIT {
        return Err(error(format!("{name} exceeds limit")));
    }
    Ok(Some(bytes))
}

fn write_leaf(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), LaneError> {
    #[cfg(test)]
    if name == RECORD && FAIL_RECORD_WRITE.with(std::cell::Cell::take) {
        return Err(error("fixture record write failed"));
    }
    if bytes.len() > LIMIT {
        return Err(error(format!("{name} exceeds limit")));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| error(cause.to_string()))?
        .as_nanos();
    let temporary = format!(".network-{}-{stamp}.tmp", std::process::id());
    let result = (|| {
        let descriptor = openat2(
            directory,
            temporary.as_str(),
            OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_CLOEXEC
                        | OFlag::O_NOFOLLOW,
                )
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|cause| error(format!("{name}: {cause}")))?;
        fchmod(&descriptor, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|cause| error(format!("{name}: {cause}")))?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|cause| error(format!("{name}: {cause}")))?;
        renameat(directory, temporary.as_str(), directory, name)
            .map_err(|cause| error(format!("{name}: {cause}")))?;
        File::from(
            directory
                .as_fd()
                .try_clone_to_owned()
                .map_err(|cause| error(cause.to_string()))?,
        )
        .sync_all()
        .map_err(|cause| error(format!("{name}: {cause}")))
    })();
    if result.is_err() {
        let _removed = unlinkat(directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

fn keys(value: &Value, expected: &[&str], kind: &str) -> Result<(), LaneError> {
    if value.as_object().is_none_or(|object| {
        object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key))
    }) {
        return Err(error(format!("{kind} has unknown or missing keys")));
    }
    Ok(())
}

fn host_words(value: &Value) -> Result<Vec<String>, LaneError> {
    let rows = value
        .as_array()
        .ok_or_else(|| error("host list is absent"))?;
    if rows.is_empty() || rows.len() > 128 {
        return Err(error("host list is empty or over limit"));
    }
    let mut hosts = Vec::new();
    for row in rows {
        let host = row.as_str().ok_or_else(|| error("host is not a name"))?;
        if !crate::vendor_net::exact_dns_host(host) || hosts.contains(&host.to_owned()) {
            return Err(error(format!("host {host} is invalid or repeated")));
        }
        hosts.push(host.to_owned());
    }
    hosts.sort();
    Ok(hosts)
}

fn proxy_reply(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some("HTTP/1.1 403 Forbidden" | "HTTP/1.1 200 Connection Established")
    )
}

fn validate_proxy_observations(event: &Value, pinned: &[String]) -> Result<(), LaneError> {
    let transition = &event["host_list_transition"];
    if !transition.is_null() {
        keys(
            transition,
            &[
                "host",
                "prior_hosts",
                "before_reply",
                "after_reply",
                "source",
            ],
            "host list transition",
        )?;
        let prior = host_words(&transition["prior_hosts"])?;
        let host = transition["host"]
            .as_str()
            .ok_or_else(|| error("transition host is absent"))?;
        if !crate::vendor_net::exact_dns_host(host)
            || prior.contains(&host.to_owned())
            || !pinned.contains(&host.to_owned())
            || !proxy_reply(&transition["before_reply"])
            || !proxy_reply(&transition["after_reply"])
            || transition["source"]
                .as_str()
                .is_none_or(|source| source.is_empty() || source.len() > 256)
        {
            return Err(error(
                "host list transition observation differs from the pins",
            ));
        }
    }
    let checks = event["dns_answer_checks"]
        .as_array()
        .ok_or_else(|| error("DNS answer checks are absent"))?;
    if checks.len() > 6 {
        return Err(error("DNS answer checks exceed limit"));
    }
    let mut seen = Vec::new();
    for check in checks {
        keys(
            check,
            &["address", "proxy_reply", "source"],
            "DNS answer check",
        )?;
        let address = check["address"]
            .as_str()
            .and_then(|word| word.parse::<IpAddr>().ok())
            .ok_or_else(|| error("DNS answer address is invalid"))?;
        if crate::vendor_net::public_address(address)
            || seen.contains(&address)
            || !proxy_reply(&check["proxy_reply"])
            || check["source"]
                .as_str()
                .is_none_or(|source| source.is_empty() || source.len() > 256)
        {
            return Err(error("DNS answer observation is invalid or repeated"));
        }
        seen.push(address);
    }
    Ok(())
}

fn validate_event(
    event: &Value,
    loop_name: &str,
    run: &str,
    pinned: &[String],
) -> Result<(), LaneError> {
    keys(
        event,
        &[
            "schema",
            "loop",
            "run",
            "phase",
            "at",
            "source",
            "program_status",
            "proxy_mode",
            "proxy_hosts",
            "observed_hosts",
            "proxy_pass_hosts",
            "host_list_transition",
            "dns_answer_checks",
        ],
        "network event",
    )?;
    if event["schema"] != 1
        || event["loop"] != loop_name
        || event["run"] != run
        || !matches!(
            event["phase"].as_str(),
            Some("start" | "refresh" | "resume")
        )
        || event["program_status"] != "passed"
        || event["proxy_mode"] != "enforcing"
        || event["at"].as_str().is_none_or(|word| {
            word.len() < 10 || word.len() > 40 || !word.bytes().all(|byte| byte.is_ascii_digit())
        })
        || event["source"]
            .as_str()
            .is_none_or(|word| word.is_empty() || word.len() > 256)
    {
        return Err(error(
            "network event identity or successful host observation differs",
        ));
    }
    let proxy_hosts = host_words(&event["proxy_hosts"])?;
    let observed = host_words(&event["observed_hosts"])?;
    let passed = host_words(&event["proxy_pass_hosts"])?;
    if proxy_hosts != pinned
        || observed.iter().any(|host| !pinned.contains(host))
        || passed.iter().any(|host| !observed.contains(host))
        || (event["phase"] == "start" && observed != pinned)
    {
        return Err(error(
            "host observation or proxy grant differs from the run's pin",
        ));
    }
    validate_proxy_observations(event, pinned)?;
    Ok(())
}

fn decode(bytes: &[u8], loop_name: &str, run: &str, pinned: &[String]) -> Result<Value, LaneError> {
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|cause| error(format!("network evidence is not JSON: {cause}")))?;
    keys(
        &document,
        &["schema", "loop", "run", "pinned_hosts", "events"],
        "network evidence",
    )?;
    if document["schema"] != 1
        || document["loop"] != loop_name
        || document["run"] != run
        || host_words(&document["pinned_hosts"])? != pinned
    {
        return Err(error("network evidence identity or pinned hosts differ"));
    }
    let events = document["events"]
        .as_array()
        .ok_or_else(|| error("events are absent"))?;
    if events.is_empty() || events.len() > 3 {
        return Err(error("event count is outside the three phases"));
    }
    for (index, event) in events.iter().enumerate() {
        validate_event(event, loop_name, run, pinned)?;
        if event["phase"] != ["start", "refresh", "resume"][index]
            || (index > 0 && event["at"].as_str() <= events[index - 1]["at"].as_str())
        {
            return Err(error(
                "network phases or observation times are out of order",
            ));
        }
    }
    Ok(document)
}

/// Read the host observation from a held runs-root descriptor.
///
/// # Errors
///
/// Refuses an older, malformed or changed evidence record by name.
pub(crate) fn read(
    runs: &OwnedFd,
    run: &str,
    owner: u32,
    loop_name: &str,
    pinned: &[String],
) -> Result<Option<Value>, LaneError> {
    let directory = custody(runs, run, owner)?;
    read_leaf(&directory, RECORD, owner)?
        .map(|bytes| decode(&bytes, loop_name, run, pinned))
        .transpose()
}

fn attempt(directory: &OwnedFd, owner: u32, phase: &str, detail: &str) -> Result<(), LaneError> {
    let previous = read_leaf(directory, ATTEMPT, owner)?;
    let mut rows = if let Some(bytes) = previous {
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|cause| error(cause.to_string()))?;
        keys(&value, &["schema", "attempts"], "network attempt journal")?;
        if value["schema"] != 1 {
            return Err(error("network attempt journal schema differs"));
        }
        value["attempts"]
            .as_array()
            .cloned()
            .ok_or_else(|| error("network attempts are absent"))?
    } else {
        Vec::new()
    };
    if rows.len() >= 16 {
        return Err(error("network attempt journal is full"));
    }
    rows.push(json!({"phase":phase,"detail":detail}));
    let bytes = serde_json::to_vec(&json!({"schema":1,"attempts":rows}))
        .map_err(|cause| error(cause.to_string()))?;
    write_leaf(directory, ATTEMPT, &bytes)
}

fn commit(
    directory: &OwnedFd,
    owner: u32,
    loop_name: &str,
    run: &str,
    pinned: &[String],
    document: &Value,
) -> Result<(), LaneError> {
    let prior = read_leaf(directory, RECORD, owner)?;
    let bytes = serde_json::to_vec(document).map_err(|cause| error(cause.to_string()))?;
    decode(&bytes, loop_name, run, pinned)?;
    if let Err(cause) = write_leaf(directory, RECORD, &bytes) {
        let withdrawn = withdraw(directory, prior.as_deref());
        let phase = if withdrawn.is_ok() {
            "withdrawn"
        } else {
            "withdrawal-failed"
        };
        attempt(directory, owner, phase, &cause.line())?;
        return Err(cause);
    }
    let verified = read_leaf(directory, RECORD, owner)
        .and_then(|value| {
            value.ok_or_else(|| error("network evidence disappeared after publication"))
        })
        .and_then(|actual| decode(&actual, loop_name, run, pinned).map(|_| actual))
        .and_then(|actual| {
            if actual == bytes {
                Ok(())
            } else {
                Err(error("network evidence changed after publication"))
            }
        });
    #[cfg(test)]
    let verified = if FAIL_VERIFY.with(std::cell::Cell::take) {
        Err(error("fixture network verification failed"))
    } else {
        verified
    };
    if let Err(cause) = verified {
        let withdrawn = withdraw(directory, prior.as_deref());
        let phase = if withdrawn.is_ok() {
            "withdrawn"
        } else {
            "withdrawal-failed"
        };
        attempt(directory, owner, phase, &cause.line())?;
        return Err(cause);
    }
    Ok(())
}

fn withdraw(directory: &OwnedFd, prior: Option<&[u8]>) -> Result<(), LaneError> {
    #[cfg(test)]
    if FAIL_WITHDRAW.with(std::cell::Cell::take) {
        return Err(error("fixture withdrawal failed"));
    }
    prior.map_or_else(
        || match unlinkat(directory, RECORD, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(nix::errno::Errno::ENOENT) => Ok(()),
            Err(cause) => Err(error(cause.to_string())),
        },
        |prior| write_leaf(directory, RECORD, prior),
    )
}

/// Record one real host-observed vendor phase for a pinned run.
///
/// # Errors
///
/// Refuses malformed evidence, a changed host pin or an out-of-order phase before writing.
pub fn run(owner_home: &Path, args: &[String], input: &mut impl Read) -> Result<Value, LaneError> {
    let [command, loop_name, run] = args else {
        return Err(LaneError::input(
            "network-evidence-usage",
            "network-evidence LOOP RUN < HOST-OBSERVATION.json",
        ));
    };
    if command != "network-evidence" || !valid_run_name(run) {
        return Err(LaneError::input(
            "network-evidence-usage",
            "network-evidence LOOP RUN < HOST-OBSERVATION.json",
        ));
    }
    let owner = Uid::effective().as_raw();
    let settings = super::exercise::door_shape::settings(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| error("runs root is absent"))?;
    let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let _lock = super::lock_runs_root(root, true, owner)?;
    let (record, _identity) = checkout::read_record_bound(&runs, run, owner)?;
    if record["loop"] != loop_name.as_str() || record["run"] != run.as_str() {
        return Err(error("reservation identity differs"));
    }
    verify_box_attestation(&record["plan"])?;
    let pinned = host_words(&record["plan"]["vendor_hosts"])?;
    let mut active = settings
        .vendor_hosts
        .get("codex")
        .cloned()
        .unwrap_or_default();
    active.sort();
    if pinned != active {
        return Err(error("active host list differs from the run's pin"));
    }
    let directory = custody(&runs, run, owner)?;
    let prior = read_leaf(&directory, RECORD, owner)?
        .map(|bytes| decode(&bytes, loop_name, run, &pinned))
        .transpose()?;
    let mut bytes = Vec::new();
    input
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|cause| LaneError::input("network-evidence-input", cause.to_string()))?;
    if bytes.len() > LIMIT {
        return Err(LaneError::input(
            "network-evidence-input",
            "host observation exceeds 65536 bytes",
        ));
    }
    let event: Value = serde_json::from_slice(&bytes)
        .map_err(|cause| LaneError::input("network-evidence-input", cause.to_string()))?;
    validate_event(&event, loop_name, run, &pinned)?;
    let mut events = prior
        .as_ref()
        .and_then(|value| value["events"].as_array())
        .cloned()
        .unwrap_or_default();
    if events.len() >= 3
        || event["phase"] != ["start", "refresh", "resume"][events.len()]
        || events
            .last()
            .is_some_and(|last| event["at"].as_str() <= last["at"].as_str())
    {
        return Err(error("network phase is duplicate or out of order"));
    }
    events.push(event.clone());
    let document = json!({"schema":1,"loop":loop_name,"run":run,
        "pinned_hosts":pinned,"events":events});
    commit(&directory, owner, loop_name, run, &pinned, &document)?;
    Ok(
        json!({"schema":1,"command":"network-evidence","loop":loop_name,"run":run,
        "phase":event["phase"],"pinned_hosts":pinned,"events":events.len(),"changed":true}),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use nix::unistd::Uid;
    use serde_json::{Value, json};

    use crate::home;
    use crate::requests::store::tests::Fixture;

    use super::{
        ATTEMPT, FAIL_RECORD_WRITE, FAIL_VERIFY, FAIL_WITHDRAW, RECORD, attempt, custody, decode,
        read, read_leaf, run, validate_event, write_leaf,
    };

    pub fn recorded_fixture(fixture: &Fixture) {
        let config = fixture.home.join(".config/loops/alpha");
        let root = fixture.home.join("runs");
        let settings = format!(
            "runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nvendor_hosts = {{ codex = [\"api.example.com\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
            root.display(),
            "a".repeat(64),
            fixture.home.join("template").display(),
            fixture.home.join("sockets").display(),
        );
        let path = config.join("workers.toml");
        fs::write(&path, settings).expect("settings");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("settings mode");
        let mut plan: Value = serde_json::from_str(include_str!("../../tests/fixtures/plan.json"))
            .expect("fixture plan");
        plan["vendor_hosts"] = json!(["api.example.com"]);
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
            "worker_uid":3000,"door_scope":"review","plan":plan});
        crate::launch::publish_reservation(&crate::launch::reservation_path(&root, "R"), &record)
            .expect("reservation");
    }

    pub fn event(phase: &str, index: usize) -> Value {
        json!({"schema":1,"loop":"alpha","run":"R","phase":phase,
            "at":format!("170000000000000000{index}"),"source":format!("journal-{index}"),
            "program_status":"passed","proxy_mode":"enforcing",
            "proxy_hosts":["api.example.com"],"observed_hosts":["api.example.com"],
            "proxy_pass_hosts":["api.example.com"],
            "host_list_transition":null,"dns_answer_checks":[]})
    }

    pub fn observed_start() -> Value {
        let mut start = event("start", 0);
        start["host_list_transition"] = json!({"host":"api.example.com","prior_hosts":["prior.example.com"],
            "before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy-log-transition"});
        start["dns_answer_checks"] = json!(["127.0.0.1","10.0.0.1","198.51.100.1","::1","fc00::1","2001:db8::1"].into_iter().map(|address| json!({"address":address,"proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy-log-dns"})).collect::<Vec<_>>());
        start
    }

    pub fn submit(home: &Path, event: &Value) -> Result<Value, crate::error::LaneError> {
        let args = ["network-evidence".into(), "alpha".into(), "R".into()];
        let bytes = serde_json::to_vec(event).expect("event bytes");
        run(home, &args, &mut Cursor::new(bytes))
    }

    /// ´test:unit:network-evidence-records-three-phases-under-run-custody´
    #[test]
    fn network_evidence_records_three_phases_under_run_custody() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        for (index, phase) in ["start", "refresh", "resume"].into_iter().enumerate() {
            let result = submit(&fixture.home, &event(phase, index)).expect("host event");
            assert_eq!(result["events"], index + 1);
        }
        let owner = Uid::effective().as_raw();
        let runs = home::verify_host_launch_root(
            Path::new("/"),
            &fixture.home,
            &fixture.home.join("runs"),
            owner,
            0,
        )
        .expect("runs descriptor");
        let record = read(&runs, "R", owner, "alpha", &["api.example.com".into()])
            .expect("evidence reader")
            .expect("record");
        assert_eq!(record["events"].as_array().map(Vec::len), Some(3));
        let directory = custody(&runs, "R", owner).expect("custody");
        assert!(
            read_leaf(&directory, RECORD, owner)
                .expect("leaf")
                .is_some()
        );
        assert!(
            read_leaf(&directory, ATTEMPT, owner)
                .expect("attempt")
                .is_none()
        );
    }

    /// ´test:unit:network-evidence-refuses-changed-events-and-withdraws-verified-failure´
    #[test]
    fn network_evidence_refuses_changed_events_and_withdraws_verified_failure() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let owner = Uid::effective().as_raw();
        let runs = home::verify_host_launch_root(
            Path::new("/"),
            &fixture.home,
            &fixture.home.join("runs"),
            owner,
            0,
        )
        .expect("runs descriptor");
        let directory = custody(&runs, "R", owner).expect("custody");
        let bad = submit(&fixture.home, &event("refresh", 1)).expect_err("first phase");
        assert_eq!(bad.kind, "network-evidence-record");
        let mut changed = event("start", 0);
        changed["proxy_hosts"] = json!(["other.example.com"]);
        assert_eq!(
            submit(&fixture.home, &changed)
                .expect_err("host drift")
                .kind,
            "network-evidence-record"
        );
        submit(&fixture.home, &event("start", 0)).expect("first event");
        let before = read_leaf(&directory, RECORD, owner)
            .expect("before")
            .expect("bytes");
        FAIL_VERIFY.with(|flag| flag.set(true));
        let failure = submit(&fixture.home, &event("refresh", 1)).expect_err("verified failure");
        assert_eq!(failure.kind, "network-evidence-record");
        assert_eq!(
            read_leaf(&directory, RECORD, owner)
                .expect("after")
                .expect("bytes"),
            before
        );
        let journal: Value = serde_json::from_slice(
            &read_leaf(&directory, ATTEMPT, owner)
                .expect("journal read")
                .expect("journal"),
        )
        .expect("journal JSON");
        assert_eq!(journal["attempts"][0]["phase"], "withdrawn");
        assert_eq!(
            submit(&fixture.home, &event("start", 0))
                .expect_err("duplicate")
                .kind,
            "network-evidence-record"
        );
        write_leaf(&directory, RECORD, b"{\"schema\":0}").expect("old record");
        assert_eq!(
            read(&runs, "R", owner, "alpha", &["api.example.com".into()])
                .expect_err("old schema")
                .kind,
            "network-evidence-record"
        );
    }

    /// ´test:unit:network-evidence-bounds-input-and-names-usage´
    #[test]
    fn network_evidence_bounds_input_and_names_usage() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(
            run(&fixture.home, &["network-evidence".into()], &mut empty)
                .expect_err("usage")
                .kind,
            "network-evidence-usage"
        );
        let mut large = Cursor::new(vec![b' '; super::LIMIT + 1]);
        let args = ["network-evidence".into(), "alpha".into(), "R".into()];
        assert_eq!(
            run(&fixture.home, &args, &mut large)
                .expect_err("limit")
                .kind,
            "network-evidence-input"
        );
        let mut malformed = Cursor::new(b"not JSON".to_vec());
        assert_eq!(
            run(&fixture.home, &args, &mut malformed)
                .expect_err("JSON")
                .kind,
            "network-evidence-input"
        );
    }

    /// ´test:unit:network-evidence-every-event-identity-and-observation-refusal´
    #[test]
    fn network_evidence_every_event_identity_and_observation_refusal() {
        let pinned = vec!["api.example.com".to_owned()];
        for (key, value, detail) in [
            ("schema", json!(2), "identity"),
            ("loop", json!("other"), "identity"),
            ("run", json!("other"), "identity"),
            ("phase", json!("other"), "identity"),
            ("program_status", json!("failed"), "identity"),
            ("proxy_mode", json!("observing"), "identity"),
            ("at", json!("bad"), "identity"),
            ("source", json!(""), "identity"),
            ("proxy_hosts", json!(["other.example.com"]), "observation"),
            (
                "observed_hosts",
                json!(["other.example.com"]),
                "observation",
            ),
            (
                "proxy_pass_hosts",
                json!(["other.example.com"]),
                "observation",
            ),
        ] {
            let mut changed = event("start", 0);
            changed[key] = value;
            let refusal = validate_event(&changed, "alpha", "R", &pinned).expect_err(key);
            assert!(refusal.detail.contains(detail), "{key}: {refusal:?}");
        }
        let mut missing = event("start", 0);
        missing.as_object_mut().expect("event").remove("source");
        assert!(
            validate_event(&missing, "alpha", "R", &pinned)
                .expect_err("missing source")
                .detail
                .contains("missing keys")
        );
        let mut changed = event("start", 0);
        changed["observed_hosts"] = json!(["api.example.com", "other.example.com"]);
        assert!(
            validate_event(&changed, "alpha", "R", &pinned)
                .expect_err("observed outside pin")
                .detail
                .contains("observation")
        );
        let mut changed = event("start", 0);
        changed["proxy_hosts"] = json!(["api.example.com", "second.example.com"]);
        assert!(
            validate_event(
                &changed,
                "alpha",
                "R",
                &["api.example.com".into(), "second.example.com".into()]
            )
            .expect_err("start differs")
            .detail
            .contains("observation")
        );
        let mut changed = event("start", 0);
        changed["observed_hosts"] = json!(["api.example.com"]);
        changed["proxy_pass_hosts"] = json!(["api.example.com", "other.example.com"]);
        assert!(
            validate_event(&changed, "alpha", "R", &pinned)
                .expect_err("passed outside observed")
                .detail
                .contains("observation")
        );
        let mut changed = event("start", 0);
        changed["observed_hosts"] = json!(["api.example.com"]);
        changed["proxy_pass_hosts"] = json!(["api.example.com"]);
        assert!(validate_event(&changed, "alpha", "R", &pinned).is_ok());
    }

    /// ´test:unit:network-evidence-proxy-observations-require-one-closed-shape´
    #[test]
    fn network_evidence_proxy_observations_require_one_closed_shape() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        submit(&fixture.home, &observed_start()).expect("observed start");
        drop(fixture);
        for (field, value) in [
            ("host_list_transition", json!({"host":"api.example.com"})),
            ("host_list_transition", json!({"host":null,"prior_hosts":["prior.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"})),
            ("host_list_transition", json!({"host":"127.0.0.1","prior_hosts":["prior.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"})),
            ("host_list_transition", json!({"host":"api.example.com","prior_hosts":"bad","before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"})),
            (
                "host_list_transition",
                json!({"host":"api.example.com","prior_hosts":["api.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"}),
            ),
            ("host_list_transition", json!({"host":"other.example.com","prior_hosts":["prior.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"})),
            ("host_list_transition", json!({"host":"api.example.com","prior_hosts":["prior.example.com"],"before_reply":"bad","after_reply":"HTTP/1.1 200 Connection Established","source":"proxy"})),
            ("host_list_transition", json!({"host":"api.example.com","prior_hosts":["prior.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"bad","source":"proxy"})),
            ("host_list_transition", json!({"host":"api.example.com","prior_hosts":["prior.example.com"],"before_reply":"HTTP/1.1 403 Forbidden","after_reply":"HTTP/1.1 200 Connection Established","source":""})),
            ("dns_answer_checks", json!(null)),
            ("dns_answer_checks", json!((0..7).map(|_| json!({"address":"127.0.0.1","proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy"})).collect::<Vec<_>>())),
            ("dns_answer_checks", json!([{"address":"127.0.0.1"}])),
            ("dns_answer_checks", json!([{"address":"bad","proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy"}])),
            (
                "dns_answer_checks",
                json!([{"address":"8.8.8.8","proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy"}]),
            ),
            ("dns_answer_checks", json!([{"address":"127.0.0.1","proxy_reply":"bad","source":"proxy"}])),
            ("dns_answer_checks", json!([{"address":"127.0.0.1","proxy_reply":"HTTP/1.1 403 Forbidden","source":""}])),
            (
                "dns_answer_checks",
                json!([{"address":"127.0.0.1","proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy"},{"address":"127.0.0.1","proxy_reply":"HTTP/1.1 403 Forbidden","source":"proxy"}]),
            ),
        ] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture);
            let mut changed = observed_start();
            let expected_detail = if field == "host_list_transition"
                && value["prior_hosts"] == json!(["prior.example.com"])
            {
                Some(if value["host"].is_null() {
                    "transition host is absent"
                } else {
                    "host list transition observation differs from the pins"
                })
            } else {
                None
            };
            changed[field] = value;
            let refusal = submit(&fixture.home, &changed).expect_err(field);
            assert_eq!(refusal.kind, "network-evidence-record");
            if let Some(detail) = expected_detail {
                assert_eq!(refusal.detail, detail);
            }
        }
    }

    /// ´test:unit:network-evidence-stored-count-order-and-time-refuse´
    #[test]
    fn network_evidence_stored_count_order_and_time_refuse() {
        let pinned = vec!["api.example.com".to_owned()];
        for events in [
            json!([]),
            json!([
                event("start", 0),
                event("refresh", 1),
                event("resume", 2),
                event("resume", 3)
            ]),
            json!([event("refresh", 0)]),
            json!([event("start", 0), event("refresh", 0)]),
        ] {
            let bytes = serde_json::to_vec(
                &json!({"schema":1,"loop":"alpha","run":"R","pinned_hosts":pinned,"events":events}),
            )
            .expect("record");
            assert_eq!(
                decode(&bytes, "alpha", "R", &pinned)
                    .expect_err("bad stored events")
                    .kind,
                "network-evidence-record"
            );
        }
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        submit(&fixture.home, &event("start", 0)).expect("start");
        let refusal = submit(&fixture.home, &event("refresh", 0)).expect_err("non-increasing time");
        assert!(refusal.detail.contains("out of order"));
    }

    /// ´test:unit:network-evidence-write-and-withdraw-failures-are-recorded´
    #[test]
    fn network_evidence_write_and_withdraw_failures_are_recorded() {
        for fail_withdraw in [false, true] {
            let fixture = Fixture::new();
            recorded_fixture(&fixture);
            submit(&fixture.home, &event("start", 0)).expect("start");
            let owner = Uid::effective().as_raw();
            let runs = home::verify_host_launch_root(
                Path::new("/"),
                &fixture.home,
                &fixture.home.join("runs"),
                owner,
                0,
            )
            .expect("runs");
            let directory = custody(&runs, "R", owner).expect("custody");
            FAIL_RECORD_WRITE.with(|flag| flag.set(true));
            FAIL_WITHDRAW.with(|flag| flag.set(fail_withdraw));
            let refusal = submit(&fixture.home, &event("refresh", 1)).expect_err("write failure");
            assert!(refusal.detail.contains("fixture record write failed"));
            let journal: Value = serde_json::from_slice(
                &read_leaf(&directory, ATTEMPT, owner)
                    .expect("journal")
                    .expect("journal bytes"),
            )
            .expect("journal JSON");
            assert_eq!(
                journal["attempts"][0]["phase"],
                if fail_withdraw {
                    "withdrawal-failed"
                } else {
                    "withdrawn"
                }
            );
        }
    }

    /// ´test:unit:network-evidence-verified-failure-reports-failed-withdrawal´
    #[test]
    fn network_evidence_verified_failure_reports_failed_withdrawal() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        submit(&fixture.home, &event("start", 0)).expect("start");
        let owner = Uid::effective().as_raw();
        let runs = home::verify_host_launch_root(
            Path::new("/"),
            &fixture.home,
            &fixture.home.join("runs"),
            owner,
            0,
        )
        .expect("runs");
        let directory = custody(&runs, "R", owner).expect("custody");
        FAIL_VERIFY.with(|flag| flag.set(true));
        FAIL_WITHDRAW.with(|flag| flag.set(true));
        let refusal = submit(&fixture.home, &event("refresh", 1)).expect_err("verified refusal");
        assert!(
            refusal
                .detail
                .contains("fixture network verification failed")
        );
        let record: Value = serde_json::from_slice(
            &read_leaf(&directory, RECORD, owner)
                .expect("record")
                .expect("bytes"),
        )
        .expect("JSON");
        assert_eq!(record["events"].as_array().map(Vec::len), Some(2));
        assert_eq!(record["events"][1]["phase"], "refresh");
        let journal: Value = serde_json::from_slice(
            &read_leaf(&directory, ATTEMPT, owner)
                .expect("journal")
                .expect("bytes"),
        )
        .expect("JSON");
        assert_eq!(journal["attempts"][0]["phase"], "withdrawal-failed");
    }

    /// ´test:unit:network-evidence-attempt-journal-and-custody-refuse-changed-leaves´
    #[test]
    fn network_evidence_attempt_journal_and_custody_refuse_changed_leaves() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let owner = Uid::effective().as_raw();
        let runs = home::verify_host_launch_root(
            Path::new("/"),
            &fixture.home,
            &fixture.home.join("runs"),
            owner,
            0,
        )
        .expect("runs");
        let directory = custody(&runs, "R", owner).expect("custody");
        for bytes in [
            b"not JSON".as_slice(),
            b"{\"schema\":2,\"attempts\":[]}",
            b"{\"schema\":1,\"attempts\":null}",
        ] {
            write_leaf(&directory, ATTEMPT, bytes).expect("journal fixture");
            assert_eq!(
                attempt(&directory, owner, "withdrawn", "fixture")
                    .expect_err("bad journal")
                    .kind,
                "network-evidence-record"
            );
        }
        let full = json!({"schema":1,"attempts":(0..16).map(|_|json!({"phase":"withdrawn","detail":"fixture"})).collect::<Vec<_>>()});
        write_leaf(
            &directory,
            ATTEMPT,
            &serde_json::to_vec(&full).expect("full journal"),
        )
        .expect("journal fixture");
        assert!(
            attempt(&directory, owner, "withdrawn", "fixture")
                .expect_err("full journal")
                .detail
                .contains("full")
        );
        write_leaf(&directory, RECORD, b"{}").expect("leaf");
        let leaf = fixture.home.join("runs/.launch-R/network-evidence.json");
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644)).expect("wrong mode");
        assert!(
            read_leaf(&directory, RECORD, owner)
                .expect_err("wrong mode")
                .detail
                .contains("owner, mode or size")
        );
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).expect("restore mode");
        write_leaf(&directory, RECORD, &vec![b'a'; super::LIMIT]).expect("large leaf");
        let oversized = fs::OpenOptions::new()
            .append(true)
            .open(&leaf)
            .expect("append");
        oversized
            .set_len((super::LIMIT + 1) as u64)
            .expect("oversize");
        assert!(
            read_leaf(&directory, RECORD, owner)
                .expect_err("oversize")
                .detail
                .contains("owner, mode or size")
        );
        let custody_path = fixture.home.join("runs/.launch-R");
        fs::set_permissions(&custody_path, fs::Permissions::from_mode(0o755))
            .expect("wrong custody mode");
        assert!(
            custody(&runs, "R", owner)
                .expect_err("custody mode")
                .detail
                .contains("owner or mode")
        );
        fs::set_permissions(&custody_path, fs::Permissions::from_mode(0o700))
            .expect("restore custody");
        assert!(
            custody(&runs, "R", owner + 1)
                .expect_err("custody owner")
                .detail
                .contains("owner or mode")
        );
        assert!(
            read_leaf(&directory, ATTEMPT, owner + 1)
                .expect_err("leaf owner")
                .detail
                .contains("owner, mode or size")
        );
    }

    /// ´test:unit:network-evidence-refuses-changed-reservation-and-active-grant´
    #[test]
    fn network_evidence_refuses_changed_reservation_and_active_grant() {
        let fixture = Fixture::new();
        recorded_fixture(&fixture);
        let reservation = crate::launch::reservation_path(&fixture.home.join("runs"), "R");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&reservation).expect("reservation")).expect("JSON");
        record["loop"] = json!("other");
        crate::launch::publish_reservation(&reservation, &record).expect("changed reservation");
        assert!(
            submit(&fixture.home, &event("start", 0))
                .expect_err("reservation identity")
                .detail
                .contains("reservation identity differs")
        );
        record["loop"] = json!("alpha");
        crate::launch::publish_reservation(&reservation, &record).expect("restored reservation");
        let settings = fixture.home.join(".config/loops/alpha/workers.toml");
        let prior = fs::read_to_string(&settings).expect("settings");
        fs::write(
            &settings,
            prior.replace("api.example.com", "other.example.com"),
        )
        .expect("changed grant");
        assert!(
            submit(&fixture.home, &event("start", 0))
                .expect_err("active list")
                .detail
                .contains("active host list differs")
        );
    }
}
