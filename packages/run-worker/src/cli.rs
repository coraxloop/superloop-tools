use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::WorkerError;

/// The command-line forms this binary accepts.
pub const USAGE: &str = "usage: worker-run {prepare LOOP LANE COMMIT --hub PATH --brief PATH|launch LOOP LANE --driver claude --estate DIR [--budget SECONDS] [--model MODEL] [--effort EFFORT]|watch LOOP LANE [--stall SECONDS] [--budget SECONDS]}";

/// The second bite's refusal, naming what carries the two remaining subcommands.
pub const SECOND_BITE: &str =
    "fetch and close arrive in the second bite, with the loop-side paths they depend on";

/// The default seconds a lane may run before the monitor stops it.
pub const DEFAULT_BUDGET: u64 = 3_600;
/// The default seconds without events that mean a stalled step.
pub const DEFAULT_STALL: u64 = 300;
/// The default model the Claude driver runs.
pub const DEFAULT_MODEL: &str = "claude-opus-5";
/// The default reasoning effort the Claude driver runs.
pub const DEFAULT_EFFORT: &str = "xhigh";

/// One parsed subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Build a lane's tree at a freshly allocated slot.
    Prepare {
        /// The loop whose block the slot comes from.
        loop_name: String,
        /// The lane name.
        lane: String,
        /// The commit the clone is checked out at.
        commit: String,
        /// The hub the clone comes from.
        hub: PathBuf,
        /// The brief copied beside the clone.
        brief: PathBuf,
    },
    /// Drop the lane's child to its worker UID and monitor it.
    Launch {
        /// The loop whose block the slot comes from.
        loop_name: String,
        /// The lane name.
        lane: String,
        /// The driver word recorded in the run table.
        driver: String,
        /// The estate tree holding the hook and the charter.
        estate: PathBuf,
        /// Seconds the child may run.
        budget: u64,
        /// The model passed to the driver.
        model: String,
        /// The effort passed to the driver.
        effort: String,
    },
    /// Block on a lane's run directory until one outcome is decided.
    Watch {
        /// The loop whose block the slot comes from.
        loop_name: String,
        /// The lane name.
        lane: String,
        /// Seconds without events that mean a stalled step.
        stall: u64,
        /// Seconds overriding the launch record's budget.
        budget: Option<u64>,
    },
}

impl Action {
    /// Return the loop this action names.
    #[must_use]
    pub fn loop_name(&self) -> &str {
        match self {
            Self::Prepare { loop_name, .. }
            | Self::Launch { loop_name, .. }
            | Self::Watch { loop_name, .. } => loop_name,
        }
    }

    /// Return the lane this action names.
    #[must_use]
    pub fn lane(&self) -> &str {
        match self {
            Self::Prepare { lane, .. } | Self::Launch { lane, .. } | Self::Watch { lane, .. } => {
                lane
            }
        }
    }

    /// Return the evidence word this action prints in capitals.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Prepare { .. } => "PREPARE",
            Self::Launch { .. } => "LAUNCH",
            Self::Watch { .. } => "WATCH",
        }
    }
}

/// One parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The selected subcommand.
    pub action: Action,
}

fn strings<I, A>(arguments: I) -> Result<Vec<String>, WorkerError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    arguments
        .into_iter()
        .map(|argument| {
            argument
                .into()
                .into_string()
                .map_err(|_argument| WorkerError::usage(USAGE))
        })
        .collect()
}

fn positionals(arguments: &mut Vec<String>, wanted: usize) -> Result<Vec<String>, WorkerError> {
    let mut taken = Vec::with_capacity(wanted);
    while taken.len() < wanted {
        match arguments.first() {
            Some(argument) if !argument.starts_with("--") => taken.push(arguments.remove(0)),
            _ => return Err(WorkerError::usage(USAGE)),
        }
    }
    Ok(taken)
}

fn options(arguments: &[String]) -> Result<BTreeMap<String, String>, WorkerError> {
    let mut parsed = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let Some(rest) = argument.strip_prefix("--") else {
            return Err(WorkerError::usage(USAGE));
        };
        let (key, value) = if let Some((key, value)) = rest.split_once('=') {
            (key.to_owned(), value.to_owned())
        } else {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| WorkerError::usage(USAGE))?;
            index += 1;
            (rest.to_owned(), value.clone())
        };
        if parsed.insert(key, value).is_some() {
            return Err(WorkerError::usage(USAGE));
        }
        index += 1;
    }
    Ok(parsed)
}

fn required(parsed: &mut BTreeMap<String, String>, key: &str) -> Result<String, WorkerError> {
    parsed
        .remove(key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| WorkerError::usage(format!("missing --{key}: {USAGE}")))
}

fn seconds(parsed: &mut BTreeMap<String, String>, key: &str) -> Result<Option<u64>, WorkerError> {
    parsed
        .remove(key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_error| WorkerError::usage(format!("--{key} takes whole seconds")))
        })
        .transpose()
}

fn exhausted(parsed: &BTreeMap<String, String>) -> Result<(), WorkerError> {
    parsed.keys().next().map_or(Ok(()), |key| {
        Err(WorkerError::usage(format!(
            "unknown option --{key}: {USAGE}"
        )))
    })
}

// Worker allocation shares ``reg:mail:identity-names`` with the registry and mail parser.
fn lane_name(lane: String) -> Result<String, WorkerError> {
    loop_home::validate_name(&lane)
        .map_err(|_failure| WorkerError::usage(format!("bad lane name: {lane:?}")))?;
    Ok(lane)
}

fn prepare_action(arguments: &mut Vec<String>) -> Result<Action, WorkerError> {
    let [loop_name, lane, commit] = positionals(arguments, 3)?
        .try_into()
        .map_err(|_names| WorkerError::usage(USAGE))?;
    let lane = lane_name(lane)?;
    let mut parsed = options(arguments)?;
    let hub = PathBuf::from(required(&mut parsed, "hub")?);
    let brief = PathBuf::from(required(&mut parsed, "brief")?);
    exhausted(&parsed)?;
    Ok(Action::Prepare {
        loop_name,
        lane,
        commit,
        hub,
        brief,
    })
}

fn launch_action(arguments: &mut Vec<String>) -> Result<Action, WorkerError> {
    let [loop_name, lane] = positionals(arguments, 2)?
        .try_into()
        .map_err(|_names| WorkerError::usage(USAGE))?;
    let lane = lane_name(lane)?;
    let mut parsed = options(arguments)?;
    let driver = required(&mut parsed, "driver")?;
    if driver != "claude" {
        return Err(WorkerError::usage(format!(
            "driver {driver} is not the Claude driver: {SECOND_BITE}"
        )));
    }
    let estate = PathBuf::from(required(&mut parsed, "estate")?);
    let budget = seconds(&mut parsed, "budget")?.unwrap_or(DEFAULT_BUDGET);
    let model = parsed
        .remove("model")
        .unwrap_or_else(|| String::from(DEFAULT_MODEL));
    let effort = parsed
        .remove("effort")
        .unwrap_or_else(|| String::from(DEFAULT_EFFORT));
    exhausted(&parsed)?;
    Ok(Action::Launch {
        loop_name,
        lane,
        driver,
        estate,
        budget,
        model,
        effort,
    })
}

fn watch_action(arguments: &mut Vec<String>) -> Result<Action, WorkerError> {
    let [loop_name, lane] = positionals(arguments, 2)?
        .try_into()
        .map_err(|_names| WorkerError::usage(USAGE))?;
    let lane = lane_name(lane)?;
    let mut parsed = options(arguments)?;
    let stall = seconds(&mut parsed, "stall")?.unwrap_or(DEFAULT_STALL);
    let budget = seconds(&mut parsed, "budget")?;
    exhausted(&parsed)?;
    Ok(Action::Watch {
        loop_name,
        lane,
        stall,
        budget,
    })
}

/// Parse one command line into a subcommand.
///
/// # Errors
///
/// Returns a status-two usage refusal for every form this binary does not accept,
/// including the two subcommands the second bite carries.
pub fn parse_invocation<I, A>(arguments: I) -> Result<Invocation, WorkerError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let mut arguments = strings(arguments)?;
    if arguments.is_empty() {
        return Err(WorkerError::usage(USAGE));
    }
    let subcommand = arguments.remove(0);
    let action = match subcommand.as_str() {
        "prepare" => prepare_action(&mut arguments)?,
        "launch" => launch_action(&mut arguments)?,
        "watch" => watch_action(&mut arguments)?,
        "fetch" | "close" => {
            return Err(WorkerError::usage(format!("{subcommand}: {SECOND_BITE}")));
        }
        _ => return Err(WorkerError::usage(USAGE)),
    };
    Ok(Invocation { action })
}
