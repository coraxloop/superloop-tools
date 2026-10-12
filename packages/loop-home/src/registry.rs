use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::LoopError;
use crate::verify::push_json_string;

const NAMESPACE: &str = "org.superloop-tools.loophome.registry";
const RESERVED_NAMES: [&str; 11] = [
    "enter",
    "provision",
    "run-bridge",
    "verify",
    "bind-custody",
    "show",
    "ensure-roots",
    "inspect-roots",
    "driver-launch",
    "letters-private",
    "letters-group",
];

/// One loop's reserved run of worker UIDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerBlock {
    /// Lowest UID of the inclusive run.
    pub base: u32,
    /// Number of UIDs in the run, at least one.
    pub count: u32,
}

impl WorkerBlock {
    /// Return the highest UID of the inclusive run.
    ///
    /// # Panics
    ///
    /// Panics only if `base + count` leaves the unsigned 32-bit range, which a
    /// allocation-validated block cannot arrange.
    #[must_use]
    pub const fn top(self) -> u32 {
        self.base + self.count - 1
    }

    /// Report whether one UID belongs to this run.
    #[must_use]
    pub const fn contains(self, uid: u32) -> bool {
        self.base <= uid && uid <= self.top()
    }

    /// Report whether two runs share any UID.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.base <= other.top() && other.base <= self.top()
    }

    /// Iterate the run from its lowest UID to its highest.
    pub fn uids(self) -> impl Iterator<Item = u32> {
        self.base..=self.top()
    }
}

/// One validated loop registry record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopRecord {
    /// Registry and passwd name.
    pub name: String,
    /// Subordinate UID and GID used for entry.
    pub uid: u32,
    /// Absolute private home.
    pub home: PathBuf,
    /// Absolute launch directory.
    pub launch: PathBuf,
    /// Live session identifier when declared.
    pub session: Option<String>,
    /// Optional least-strict door mode granted by the row; absence means audit.
    pub door_floor: Option<DoorFloor>,
}

/// The row's least-strict admitted door mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorFloor {
    Audit,
    Enforce,
    Allow,
}

impl DoorFloor {
    /// Stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
            Self::Allow => "allow",
        }
    }
}

impl LoopRecord {
    /// Render the validated registry row as compact key-sorted JSON.
    #[must_use]
    pub fn to_registry_json(&self) -> String {
        self.to_registry_json_with_runs_root(None)
    }

    /// Render the row with a declared durable runs root when the registry carries one.
    #[must_use]
    pub fn to_registry_json_with_runs_root(&self, runs_root: Option<&Path>) -> String {
        let mut output = String::from("{");
        if let Some(floor) = self.door_floor {
            output.push_str("\"door_floor\":");
            push_json_string(&mut output, floor.as_str());
            output.push(',');
        }
        output.push_str("\"launch\":");
        push_json_string(&mut output, &self.launch.to_string_lossy());
        output.push_str(",\"name\":");
        push_json_string(&mut output, &self.name);
        output.push_str(",\"session\":");
        if let Some(session) = &self.session {
            push_json_string(&mut output, session);
        } else {
            output.push_str("null");
        }
        if let Some(runs_root) = runs_root {
            output.push_str(",\"runs_root\":");
            push_json_string(&mut output, &runs_root.to_string_lossy());
        }
        let _write = write!(&mut output, ",\"uid\":{}", self.uid);
        output.push('}');
        output
    }
}

#[derive(Clone, Debug)]
struct Row {
    name: String,
    uid: u32,
    launch: PathBuf,
    runs_root: Option<PathBuf>,
    session: Option<String>,
    door_floor: Option<DoorFloor>,
}

/// A whole-file validated registry in file order.
#[derive(Clone, Debug)]
pub struct Registry {
    rows: Vec<Row>,
}

impl Registry {
    /// Return a validated row's declared runs root, when present.
    #[must_use]
    pub fn runs_root(&self, name: &str) -> Option<&Path> {
        self.rows
            .iter()
            .find(|row| row.name == name)
            .and_then(|row| row.runs_root.as_deref())
    }

    /// Select a row by name and derive its paths from the caller's home.
    ///
    /// # Errors
    ///
    /// Returns a status-two refusal for a malformed or unknown name.
    pub fn row(&self, name: &str, caller_home: &Path) -> Result<LoopRecord, LoopError> {
        validate_name(name)?;
        self.rows
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.record(caller_home))
            .ok_or_else(|| LoopError::refusal(format!("unknown loop: {name}")))
    }

    /// Derive all rows in file order from the caller's home.
    #[must_use]
    pub fn rows(&self, caller_home: &Path) -> Vec<LoopRecord> {
        self.rows
            .iter()
            .map(|row| row.record(caller_home))
            .collect()
    }
}

impl Row {
    fn record(&self, caller_home: &Path) -> LoopRecord {
        LoopRecord {
            name: self.name.clone(),
            uid: self.uid,
            home: caller_home.join(".var/loops").join(&self.name),
            launch: caller_home.join(&self.launch),
            session: self.session.clone(),
            door_floor: self.door_floor,
        }
    }
}

/// Validate the portable loop-name grammar and reserved subcommands.
///
/// # Errors
///
/// Returns a status-two refusal for a reserved or malformed name.
pub fn validate_name(name: &str) -> Result<(), LoopError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid || RESERVED_NAMES.contains(&name) {
        return Err(LoopError::refusal(format!("bad loop name: {name}")));
    }
    Ok(())
}

/// Resolve the registry override or its default beneath the caller's home.
#[must_use]
pub fn registry_path(env_value: Option<&OsStr>, caller_home: &Path) -> PathBuf {
    env_value.filter(|value| !value.is_empty()).map_or_else(
        || caller_home.join(".config/loops/registry.toml"),
        PathBuf::from,
    )
}

fn malformed() -> LoopError {
    LoopError::refusal("malformed loop registry")
}

fn table<'a>(value: &'a toml::Value, context: &str) -> Result<&'a toml::Table, LoopError> {
    value
        .as_table()
        .ok_or_else(|| LoopError::refusal(format!("malformed {context}")))
}

fn keys(table: &toml::Table, allowed: &[&str], context: &str) -> Result<(), LoopError> {
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(LoopError::refusal(format!("unknown {context} key: {key}")));
    }
    Ok(())
}

fn integer(value: Option<&toml::Value>) -> Option<u32> {
    value?
        .as_integer()
        .and_then(|number| u32::try_from(number).ok())
}

fn parse_runs_root(value: Option<&toml::Value>, name: &str) -> Result<Option<PathBuf>, LoopError> {
    value
        .map(|value| {
            let path = value.as_str().ok_or_else(|| {
                LoopError::refusal(format!(
                    "malformed runs_root for loop {name}: must be an absolute path string with no . or .. components"
                ))
            })?;
            if path.is_empty()
                || !Path::new(path).is_absolute()
                || path
                    .split('/')
                    .any(|component| component == "." || component == "..")
            {
                return Err(LoopError::refusal(format!(
                    "invalid runs_root for loop {name}: must be an absolute path with no . or .. components"
                )));
            }
            Ok(PathBuf::from(path))
        })
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn parse_row(value: &toml::Value, index: usize) -> Result<Row, LoopError> {
    let context = format!("loop row {}", index + 1);
    let row = table(value, &context)?;
    keys(
        row,
        &[
            "name",
            "uid",
            "launch",
            "runs_root",
            "session",
            "door_floor",
        ],
        "loop row",
    )?;
    let name = row
        .get("name")
        .ok_or_else(|| LoopError::refusal(format!("missing name in {context}")))?
        .as_str()
        .ok_or_else(|| LoopError::refusal(format!("malformed name in {context}")))?;
    validate_name(name)?;
    let uid = match row.get("uid") {
        None => return Err(LoopError::refusal(format!("missing uid for loop: {name}"))),
        Some(value) if value.as_integer().is_none() => {
            return Err(LoopError::refusal(format!(
                "malformed uid for loop: {name}"
            )));
        }
        value => integer(value).unwrap_or(0),
    };
    if !(1000..=65_535).contains(&uid) {
        return Err(LoopError::refusal(format!(
            "uid out of range for loop: {name}"
        )));
    }
    let launch = match row.get("launch") {
        None => {
            return Err(LoopError::refusal(format!(
                "missing launch for loop: {name}"
            )));
        }
        Some(value) => value
            .as_str()
            .ok_or_else(|| LoopError::refusal(format!("malformed launch for loop: {name}")))?,
    };
    if launch.is_empty()
        || Path::new(launch).is_absolute()
        || launch
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(LoopError::refusal(format!(
            "invalid launch for loop: {name}"
        )));
    }
    let runs_root = parse_runs_root(row.get("runs_root"), name)?;
    let session = row
        .get("session")
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| LoopError::refusal(format!("malformed session for loop: {name}")))
        })
        .transpose()?;
    let door_floor = row
        .get("door_floor")
        .map(|value| match value.as_str() {
            Some("audit") => Ok(DoorFloor::Audit),
            Some("enforce") => Ok(DoorFloor::Enforce),
            Some("allow") => Ok(DoorFloor::Allow),
            _ => Err(LoopError::refusal(format!(
                "malformed door_floor for loop: {name}"
            ))),
        })
        .transpose()?;
    Ok(Row {
        name: name.to_owned(),
        uid,
        launch: PathBuf::from(launch),
        runs_root,
        session,
        door_floor,
    })
}

/// Parse one bounded registry source after its reader has pinned the file.
fn parse_registry(source: &str) -> Result<Registry, LoopError> {
    let parsed: toml::Value = toml::from_str(source).map_err(|_error| malformed())?;
    let root = table(&parsed, "loop registry")?;
    keys(root, &["namespace", "version", "loops"], "registry")?;
    if root.get("namespace").and_then(toml::Value::as_str) != Some(NAMESPACE) {
        return Err(LoopError::refusal("wrong loop registry namespace"));
    }
    let version = root
        .get("version")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| LoopError::refusal("malformed loop registry version"))?;
    if version.len() != 3
        || version
            .iter()
            .any(|part| part.as_integer().is_none_or(|n| n < 0))
    {
        return Err(LoopError::refusal("malformed loop registry version"));
    }
    if version[0].as_integer() != Some(1) {
        return Err(LoopError::refusal(
            "unsupported loop registry major version",
        ));
    }
    let values = root
        .get("loops")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| LoopError::refusal("malformed loop registry loops"))?;
    let rows: Vec<Row> = values
        .iter()
        .enumerate()
        .map(|(index, value)| parse_row(value, index))
        .collect::<Result<_, _>>()?;
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for row in &rows {
        if !names.insert(&row.name) {
            return Err(LoopError::refusal(format!(
                "duplicate loop name: {}",
                row.name
            )));
        }
        if !uids.insert(row.uid) {
            return Err(LoopError::refusal(format!(
                "duplicate loop uid: {}",
                row.uid
            )));
        }
    }
    Ok(Registry { rows })
}

/// Read a registry through a held, validated file descriptor.
///
/// # Errors
///
/// Refuses an unreadable or oversized source and every malformed row.
pub fn load_registry_from_file(file: &mut fs::File) -> Result<Registry, LoopError> {
    use std::io::Read as _;

    let mut source = String::new();
    file.take(65_537)
        .read_to_string(&mut source)
        .map_err(|_| LoopError::refusal("could not read loop registry descriptor"))?;
    if source.len() > 65_536 {
        return Err(LoopError::refusal("loop registry exceeds byte limit"));
    }
    parse_registry(&source)
}

/// Read and validate the whole TOML registry before selecting any loop.
///
/// # Errors
///
/// Returns a status-two refusal for an unreadable file or any schema or registry-wide violation.
pub fn load_registry(path: &Path) -> Result<Registry, LoopError> {
    let source = fs::read_to_string(path).map_err(|_error| {
        LoopError::refusal(format!("could not read loop registry: {}", path.display()))
    })?;
    parse_registry(&source)
}
