use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use session_core::heartbeat::{
    self, Entry, FailureClass, Observations, StopFields, StopInput, Timer,
};
use session_core::letters::Listing;

pub fn dispatch(args: &[OsString]) -> Option<u8> {
    let subject = args.first()?.to_str()?;
    if !matches!(subject, "heartbeat" | "orchestrator") {
        return None;
    }
    let result = run(subject, &args[1..]);
    Some(match result {
        Ok(bytes) => u8::from(std::io::stdout().lock().write_all(&bytes).is_err()),
        Err(reason) => {
            let _written = writeln!(std::io::stderr().lock(), "superloop {subject}: {reason}");
            2
        }
    })
}

fn run(subject: &str, args: &[OsString]) -> Result<Vec<u8>, String> {
    let action = args.first().and_then(|a| a.to_str()).unwrap_or("status");
    if action == "decide" {
        let [_, file] = args else {
            return Err("decide requires one neutral observation file".into());
        };
        return if subject == "heartbeat" {
            heartbeat_decision(Path::new(file))
        } else {
            orchestrator_decision(Path::new(file))
        };
    }
    let global = subject == "orchestrator" && args.get(1).is_some_and(|a| a == "--global");
    if args.len() > 1 && !(global && args.len() == 2) {
        return Err("expected on|off|status [--global] or decide FILE".into());
    }
    let result = if subject == "heartbeat" {
        use session_core::heartbeat_toggle::{ToggleCommand, execute};
        let command = match action {
            "on" => ToggleCommand::On,
            "off" => ToggleCommand::Off,
            "status" => ToggleCommand::Status,
            _ => return Err("expected on|off|status or decide FILE".into()),
        };
        execute(command, &state_dir()?)
    } else {
        use session_core::orchestrator_toggle::{ToggleCommand, execute};
        let command = match action {
            "on" => ToggleCommand::On,
            "off" => ToggleCommand::Off,
            "status" => ToggleCommand::Status,
            _ => return Err("expected on|off|status [--global] or decide FILE".into()),
        };
        execute(command, global)
    };
    result.map_err(|_| "cannot access the selected session state".into())
}

fn state_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/state/superloop-tools/hook"))
        .ok_or_else(|| "HOME is required".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatInput {
    schema: u64,
    cwd: String,
    session: String,
    observations: PathBuf,
    retry: bool,
    letters: Letters,
}

#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    content = "text",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Letters {
    Empty,
    Notice,
    Failed(String),
}

impl Letters {
    fn listing(&self) -> Listing {
        match self {
            Self::Empty => Listing::Empty,
            Self::Notice => Listing::Notice,
            Self::Failed(text) => Listing::Failed(text.clone()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    sidechain: bool,
    timestamp: Option<f64>,
    role: Role,
    real_user: bool,
    feedback: bool,
    results: Vec<(String, bool)>,
    timers: Vec<(String, bool, Option<f64>)>,
}

struct NeutralObservations(Letters);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    User,
    Assistant,
    Other,
}

impl Observations for NeutralObservations {
    fn load(&self, path: &Path) -> Result<Vec<Entry>, FailureClass> {
        let bytes = std::fs::read_to_string(path).map_err(|_| FailureClass::TranscriptRead)?;
        bytes
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let item: Observation =
                    serde_json::from_str(line).map_err(|_| FailureClass::TranscriptStructure)?;
                Ok(Entry {
                    sidechain: item.sidechain,
                    timestamp: item.timestamp,
                    user: matches!(item.role, Role::User),
                    assistant: matches!(item.role, Role::Assistant),
                    real_user: Ok(item.real_user),
                    feedback: Ok(item.feedback),
                    results: Ok(item
                        .results
                        .into_iter()
                        .map(|(id, success)| (Ok(id), success))
                        .collect()),
                    timers: Ok(item
                        .timers
                        .into_iter()
                        .map(|(id, stop, delay)| Timer {
                            id: Ok(id),
                            parameters: Ok((stop, delay)),
                        })
                        .collect()),
                })
            })
            .collect()
    }

    fn letters(&self, _cwd: &str, _home: &Path) -> Listing {
        self.0.listing()
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("observation file: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("neutral observation record: {e}"))
}

fn heartbeat_decision(path: &Path) -> Result<Vec<u8>, String> {
    let input: HeartbeatInput = read(path)?;
    if input.schema != 1 || input.session.is_empty() {
        return Err("schema must be 1 and session must be nonempty".into());
    }
    let observations = NeutralObservations(input.letters);
    let input = StopInput {
        cwd: Some(input.cwd),
        fields: Ok(StopFields {
            transcript_path: input.observations,
            session: Some(input.session),
            retry: input.retry,
        }),
    };
    let result = heartbeat::run(
        &input,
        &state_dir()?,
        heartbeat::Timing::system(),
        &observations,
        observations.0.listing(),
    );
    serde_json::to_vec(&serde_json::json!({"schema":1,"terminal":format!("{:?}", result.state),"path":result.path.iter().map(|state| format!("{state:?}")).collect::<Vec<_>>(),"retry_count":result.retry_count,"feedback":result.feedback})).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    schema: u64,
    kind: String,
    class: String,
    session: String,
    cwd: String,
    source: String,
    prompt: Option<String>,
    witnessed_digests: Option<String>,
}

fn orchestrator_decision(path: &Path) -> Result<Vec<u8>, String> {
    use session_core::orchestrator::{self, EventClass, SessionKind};
    let input: SessionInput = read(path)?;
    if input.schema != 1 || input.session.is_empty() {
        return Err("schema must be 1 and session must be nonempty".into());
    }
    let kind = match input.kind.as_str() {
        "start" => SessionKind::Start,
        "prompt" => SessionKind::Prompt,
        _ => return Err("kind must be start or prompt".into()),
    };
    let event_class = match input.class.as_str() {
        "fresh" => EventClass::Fresh,
        "resumed" => EventClass::Resumed,
        "tracked" => EventClass::Tracked,
        _ => return Err("class must be fresh, resumed or tracked".into()),
    };
    let input = orchestrator::SessionInput {
        kind,
        event_class,
        event: input.kind,
        session_id: input.session,
        cwd: input.cwd,
        source: input.source,
        prompt_id: input.prompt,
        transcript_path: input.witnessed_digests,
        refused_audience: false,
    };
    let injection = orchestrator::run(&input, witnessed_digest);
    serde_json::to_vec(&serde_json::json!({"schema":1,"injection":injection}))
        .map_err(|e| e.to_string())
}

fn witnessed_digest(path: &str, digest: &str) -> bool {
    read::<Vec<String>>(Path::new(path))
        .is_ok_and(|digests| digests.iter().any(|entry| entry == digest))
}
