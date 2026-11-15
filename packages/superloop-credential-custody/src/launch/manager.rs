//! Pinned manager CLI transport. Replies are bounded metadata, never diagnostics.
use super::{
    Result,
    measure::{Admission, HeldArtifact},
    policy::{ArtifactRole, FIXTURE_STANDARD_STREAMS},
    require,
};
use crate::{identity::hash, process, record::Limits};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const FIELDS: [&str; 27] = [
    "Id",
    "InvocationID",
    "MainPID",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "NoNewPrivileges",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "ProtectSystem",
    "PrivateUsers",
    "PrivatePIDs",
    "DynamicUser",
    FIXTURE_STANDARD_STREAMS[0].property,
    FIXTURE_STANDARD_STREAMS[1].property,
    FIXTURE_STANDARD_STREAMS[2].property,
    "ReadWritePaths",
    "InaccessiblePaths",
    "Type",
    "RemainAfterExit",
    "Slice",
    "TimeoutStartUSec",
    "TimeoutStopUSec",
    "KillMode",
    "SendSIGKILL",
];
struct Expected<'a> {
    unit: &'a str,
    sockets: &'a [PathBuf; 2],
    slice: &'a str,
    case_ms: u64,
    openfiles: [String; 2],
}
pub(super) struct Manager<'a> {
    admission: &'a Admission,
    deadline: Instant,
    index: usize,
    start: &'a HeldArtifact,
    query: &'a HeldArtifact,
}
#[derive(Debug)]
pub(super) struct Snapshot {
    pub invocation: String,
    pub pid: u32,
    pub active: String,
    pub sub: String,
    pub result: String,
    pub code: i32,
    pub status: i32,
    /// Full binding of actual reply bytes to protected policy and held CLI expectations.
    pub raw_sha256: String,
    /// Full binding of canonical, compared loaded properties to those expectations.
    pub configuration_sha256: String,
    pub properties: Vec<u8>,
}
impl<'a> Manager<'a> {
    pub fn new(admission: &'a Admission, index: usize) -> Result<Self> {
        require(
            index < admission.policy().cases.len(),
            "launch-case-binding",
        )?;
        let find = |role| {
            admission
                .artifacts()
                .iter()
                .find(|a| a.role == role)
                .ok_or("manager-artifact-roster")
        };
        Ok(Self {
            admission,
            deadline: Instant::now() + Duration::from_millis(admission.policy().limits.case_ms),
            index,
            start: find(ArtifactRole::ManagerStart)?,
            query: find(ArtifactRole::ManagerQuery)?,
        })
    }
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn start_vector(&self, paths: &[PathBuf; 2]) -> Result<Vec<String>> {
        let policy = self.admission.policy();
        let case = &policy.cases[self.index];
        let expected = [
            policy.roots.runtime.join(&case.id).join("left.fifo"),
            policy.roots.runtime.join(&case.id).join("right.fifo"),
        ];
        require(paths == &expected, "manager-fifo-binding")?;
        let fixture = policy
            .artifacts
            .iter()
            .find(|a| a.role == ArtifactRole::Fixture)
            .ok_or("manager-artifact-roster")?;
        let mut args = vec![
            "--system".into(),
            "--no-block".into(),
            "--quiet".into(),
            format!("--unit={}", case.generator_unit),
            "--service-type=oneshot".into(),
            "--remain-after-exit".into(),
            "--expand-environment=no".into(),
            format!("--slice={}", policy.slice),
        ];
        for value in [
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectSystem=strict",
            "PrivateUsers=no",
            "PrivatePIDs=no",
            "DynamicUser=yes",
            "ReadWritePaths=",
            "TimeoutStopSec=5s",
            "KillMode=control-group",
            "SendSIGKILL=yes",
        ] {
            args.push(format!("--property={value}"));
        }
        for stream in &FIXTURE_STANDARD_STREAMS {
            args.push(format!(
                "--property={}={}",
                stream.property, stream.manager_value
            ));
        }
        args.push(format!(
            "--property=TimeoutStartSec={}ms",
            policy.limits.case_ms
        ));
        args.push(format!(
            "--property=InaccessiblePaths={} {}",
            policy.manager_sockets[0].display(),
            policy.manager_sockets[1].display()
        ));
        for (path, stream) in paths.iter().zip(&case.streams) {
            args.push(format!(
                "--property=OpenFile={}:{}:append",
                path.display(),
                stream.name
            ));
        }
        args.extend([
            "--".into(),
            fixture.path.display().to_string(),
            "emit".into(),
            "--case-record".into(),
            case.record.display().to_string(),
        ]);
        Ok(args)
    }
    pub fn start(&self, paths: &[PathBuf; 2]) -> Result<()> {
        let args = self.start_vector(paths)?;
        self.check_version()?;
        let reply = self.call(self.start, &args)?;
        require(reply.is_empty(), "manager-start-output")
    }
    fn expected(&self) -> Expected<'_> {
        let p = self.admission.policy();
        let c = &p.cases[self.index];
        Expected {
            unit: &c.generator_unit,
            sockets: &p.manager_sockets,
            slice: &p.slice,
            case_ms: p.limits.case_ms,
            openfiles: [
                format!(
                    "{}:{}:append",
                    p.roots.runtime.join(&c.id).join("left.fifo").display(),
                    c.streams[0].name
                ),
                format!(
                    "{}:{}:append",
                    p.roots.runtime.join(&c.id).join("right.fifo").display(),
                    c.streams[1].name
                ),
            ],
        }
    }
    fn check_version(&self) -> Result<()> {
        let client = self.call(self.start, &["--version".into()])?;
        let server = self.call(
            self.query,
            &[
                "--system".into(),
                "show".into(),
                "--property=Version".into(),
                "--value".into(),
                "--no-pager".into(),
            ],
        )?;
        require(
            version(&client) >= Some(257) && version(&server) >= Some(257),
            "manager-version",
        )
    }
    pub fn snapshot(&self, expected: Option<&str>) -> Result<Snapshot> {
        self.snapshot_at(expected, self.deadline)
    }
    fn snapshot_at(&self, expected: Option<&str>, deadline: Instant) -> Result<Snapshot> {
        let unit = &self.admission.policy().cases[self.index].generator_unit;
        let args = vec![
            "--system".into(),
            "show".into(),
            "--no-pager".into(),
            "--all".into(),
            format!("--property={},OpenFile", FIELDS.join(",")),
            "--".into(),
            unit.clone(),
        ];
        let reply = self.call_at(self.query, &args, deadline)?;
        parse(&reply, &self.expected(), expected)
    }
    // A caller must retain ownership of the unit name for this invocation.
    // Recheck immediately before the exact-unit request; a mismatch never stops
    // a new invocation. Atomic manager ownership is an installed-manager witness.
    pub fn stop(&self, invocation: &str) -> Result<()> {
        let deadline =
            Instant::now() + Duration::from_millis(self.admission.policy().limits.case_ms);
        self.snapshot_at(Some(invocation), deadline)?;
        let unit = &self.admission.policy().cases[self.index].generator_unit;
        let reply = self.call_at(
            self.query,
            &["--system".into(), "stop".into(), "--".into(), unit.clone()],
            deadline,
        )?;
        require(reply.is_empty(), "manager-stop-output")
    }
    fn call(&self, artifact: &HeldArtifact, args: &[String]) -> Result<Vec<u8>> {
        self.call_at(artifact, args, self.deadline)
    }
    fn call_at(
        &self,
        artifact: &HeldArtifact,
        args: &[String],
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        artifact.unchanged()?;
        let reference = self
            .admission
            .policy()
            .artifacts
            .iter()
            .find(|a| a.id == artifact.id)
            .ok_or("manager-artifact-roster")?;
        let mut command = Command::new(&reference.path);
        command.args(args);
        loop_home::CommandDescriptors::default()
            .configure(&mut command)
            .map_err(|_| "manager-descriptors")?;
        let limits = Limits {
            file_bytes: 0,
            output_bytes: self
                .admission
                .policy()
                .limits
                .diagnostic_bytes
                .min(64 * 1024),
            timeout_ms: u64::try_from(
                super::sealer::remaining_timeout(Instant::now(), deadline, deadline)
                    .map_err(|_| "manager-deadline")?,
            )
            .map_err(|_| "manager-deadline")?,
        };
        let reply = process::capture_matching(command, &[], &limits, &artifact.file)?;
        artifact.unchanged()?;
        require(Instant::now() < deadline, "manager-deadline")?;
        Ok(reply)
    }
}
fn parse(bytes: &[u8], wire: &Expected<'_>, expected: Option<&str>) -> Result<Snapshot> {
    let unit = wire.unit;
    require(bytes.len() <= 64 * 1024, "manager-reply-size")?;
    let text = std::str::from_utf8(bytes).map_err(|_| "manager-reply-shape")?;
    require(
        text.ends_with('\n') && !text.contains('\r'),
        "manager-reply-shape",
    )?;
    let mut values = BTreeMap::new();
    let mut openfiles = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("manager-reply-shape")?;
        if key == "OpenFile" {
            require(openfiles.len() < 2, "manager-open-files")?;
            openfiles.push(value);
            continue;
        }
        require(
            FIELDS.contains(&key) && values.insert(key, value).is_none(),
            "manager-reply-shape",
        )?;
    }
    require(values.len() == FIELDS.len(), "manager-reply-shape")?;
    require(
        openfiles.len() == 2 && openfiles.iter().zip(&wire.openfiles).all(|(a, b)| *a == b),
        "manager-open-files",
    )?;
    require(values["Id"] == unit, "manager-unit-binding")?;
    let id = values["InvocationID"];
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && id.bytes().any(|b| b != b'0')
            && expected.is_none_or(|expected| expected == id),
        "manager-invocation-binding",
    )?;
    let pid = values["MainPID"]
        .parse::<u32>()
        .map_err(|_| "manager-pid")?;
    for field in ["ActiveState", "SubState", "Result"] {
        let v = values[field];
        require(
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "manager-state",
        )?;
    }
    let code = values["ExecMainCode"]
        .parse::<i32>()
        .map_err(|_| "manager-status")?;
    let status = values["ExecMainStatus"]
        .parse::<i32>()
        .map_err(|_| "manager-status")?;
    require(
        (0..=6).contains(&code) && (0..=255).contains(&status),
        "manager-status",
    )?;
    let properties = properties(&values, wire)?;
    let measured: BTreeMap<_, _> = FIELDS[8..].iter().map(|key| (*key, values[*key])).collect();
    let configuration_sha256 = super::measure::canonical(
        "credential-manager-properties-v1",
        &serde_json::json!({"properties":measured,"open_files":openfiles}),
    )?;
    Ok(Snapshot {
        invocation: id.into(),
        pid,
        active: values["ActiveState"].into(),
        sub: values["SubState"].into(),
        result: values["Result"].into(),
        code,
        status,
        raw_sha256: hash(bytes),
        configuration_sha256,
        properties,
    })
}

#[cfg(test)]
#[path = "manager_tests.rs"]
pub(super) mod tests;

fn version(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_prefix("systemd ").unwrap_or(text);
    let token = text.split_whitespace().next()?;
    let number: String = token.chars().take_while(char::is_ascii_digit).collect();
    number.parse().ok()
}
fn duration_us(text: &str) -> Option<u64> {
    let mut total = 0_u64;
    let mut seen = std::collections::BTreeSet::new();
    for part in text.split_whitespace() {
        let n = part.find(|c: char| !c.is_ascii_digit())?;
        let value = part[..n].parse::<u64>().ok()?;
        let unit = &part[n..];
        if !seen.insert(unit) {
            return None;
        }
        let factor = match unit {
            "us" | "µs" => 1,
            "ms" => 1000,
            "s" => 1_000_000,
            "min" => 60_000_000,
            _ => return None,
        };
        total = total.checked_add(value.checked_mul(factor)?)?;
    }
    if seen.is_empty() { None } else { Some(total) }
}

fn properties(values: &BTreeMap<&str, &str>, wire: &Expected<'_>) -> Result<Vec<u8>> {
    let sockets = format!(
        "{} {}",
        wire.sockets[0].display(),
        wire.sockets[1].display()
    );
    for (key, value) in [
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("ProtectSystem", "strict"),
        ("PrivateUsers", "no"),
        ("PrivatePIDs", "no"),
        ("DynamicUser", "yes"),
        ("ReadWritePaths", ""),
        ("InaccessiblePaths", sockets.as_str()),
    ] {
        require(values[key] == value, "manager-property-drift")?;
    }
    for stream in &FIXTURE_STANDARD_STREAMS {
        require(
            values[stream.property] == stream.manager_value,
            "manager-property-drift",
        )?;
    }
    // Values are mapped only after each loaded wire value passed its closed
    // comparison. The raw reply digest separately binds their actual bytes.
    for (key, value) in [
        ("Type", "oneshot"),
        ("RemainAfterExit", "yes"),
        ("Slice", wire.slice),
        ("KillMode", "control-group"),
        ("SendSIGKILL", "yes"),
    ] {
        require(values[key] == value, "manager-property-drift")?;
    }
    require(
        duration_us(values["TimeoutStartUSec"]) == Some(wire.case_ms * 1000)
            && duration_us(values["TimeoutStopUSec"]) == Some(5_000_000),
        "manager-property-drift",
    )?;
    let actual = super::policy::Properties {
        capability_bounding_set: Vec::new(),
        ambient_capabilities: Vec::new(),
        no_new_privileges: values["NoNewPrivileges"] == "yes",
        protect_system: super::policy::Protection::Strict,
        user_namespace: super::policy::Namespace::Host,
        pid_namespace: super::policy::Namespace::Host,
        manager_access: false,
        dynamic_user: values["DynamicUser"] == "yes",
        writable: Vec::new(),
        private_diagnostics: FIXTURE_STANDARD_STREAMS
            .iter()
            .all(|s| values[s.property] == s.manager_value),
    };
    serde_json::to_vec(&actual).map_err(|_| "manager-reply-shape")
}
