#![deny(clippy::indexing_slicing)]

//! Strict decoding for the reduced `PreToolUse` request contract.

use serde_json::{Map, Value};

/// Largest Bash timeout accepted by the tool's documented input schema.
pub const MAX_BASH_TIMEOUT_MS: u64 = 600_000;

pub use execute_command::triage::Scope;

/// The Bash-specific portion of a decoded tool request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashInput {
    command: String,
    description: Option<String>,
    timeout_ms: Option<u64>,
    run_in_background: Option<bool>,
}

impl BashInput {
    /// Exact command bytes represented as UTF-8 text by JSON.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Optional caller-authored description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Optional whole-request timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> Option<u64> {
        self.timeout_ms
    }

    /// Optional detached-execution declaration.
    #[must_use]
    pub const fn run_in_background(&self) -> Option<bool> {
        self.run_in_background
    }
}

/// One type-checked hook request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionRequest {
    session_id: String,
    cwd: String,
    transcript_path: Option<String>,
    agent_id: Option<Value>,
    permission_mode: String,
    hook_event_name: String,
    tool_name: String,
    tool_input: Map<String, Value>,
    tool_use_id: String,
    bash: Option<BashInput>,
}

impl PermissionRequest {
    /// Harness session identity. The fast lane never forwards this value.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Current working directory supplied by the harness.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Optional transcript path used only for caller-role resolution.
    #[must_use]
    pub fn transcript_path(&self) -> Option<&str> {
        self.transcript_path.as_deref()
    }

    /// Optional agent identifier value used only for caller-role resolution.
    #[must_use]
    pub const fn agent_id(&self) -> Option<&Value> {
        self.agent_id.as_ref()
    }

    /// SessionStart-compatible truthiness of the optional agent identifier.
    #[must_use]
    pub fn agent_id_truthy(&self) -> bool {
        self.agent_id.as_ref().is_some_and(json_truthy)
    }

    /// Harness permission mode.
    #[must_use]
    pub fn permission_mode(&self) -> &str {
        &self.permission_mode
    }

    /// Validated hook event name.
    #[must_use]
    pub fn hook_event_name(&self) -> &str {
        &self.hook_event_name
    }

    /// Tool selected by the request.
    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    /// Complete object needed by deterministic tool adapters.
    #[must_use]
    pub const fn tool_input(&self) -> &Map<String, Value> {
        &self.tool_input
    }

    /// Tool-use identity. The fast lane never forwards this value.
    #[must_use]
    pub fn tool_use_id(&self) -> &str {
        &self.tool_use_id
    }

    /// Bash-specific typed fields when the selected tool is Bash.
    #[must_use]
    pub const fn bash(&self) -> Option<&BashInput> {
        self.bash.as_ref()
    }
}

/// Result of decoding one hook input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeResult {
    /// Every required field has the documented type.
    Decoded(Box<PermissionRequest>),
    /// The hook input cannot safely enter classification.
    Unclassifiable {
        /// Stable explanation of the first malformed field.
        reason: String,
    },
}

impl DecodeResult {
    /// Borrow the decoded request when decoding succeeded.
    #[must_use]
    pub fn request(&self) -> Option<&PermissionRequest> {
        match self {
            Self::Decoded(request) => Some(request.as_ref()),
            Self::Unclassifiable { .. } => None,
        }
    }

    /// Borrow the failure reason when decoding refused the input.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Decoded(_) => None,
            Self::Unclassifiable { reason } => Some(reason),
        }
    }
}

/// Decode one complete JSON hook request without consulting external state.
#[must_use]
pub fn decode_request(input: &[u8]) -> DecodeResult {
    decode(input).unwrap_or_else(|reason| DecodeResult::Unclassifiable { reason })
}

fn decode(input: &[u8]) -> Result<DecodeResult, String> {
    let value: Value = serde_json::from_slice(input)
        .map_err(|error| format!("hook input is not valid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "hook input must be one JSON object".to_owned())?;

    let session_id = required_string(object, "session_id")?;
    let cwd = required_string(object, "cwd")?;
    let transcript_path = object
        .get("transcript_path")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let agent_id = object.get("agent_id").cloned();
    let permission_mode = required_string(object, "permission_mode")?;
    let hook_event_name = required_string(object, "hook_event_name")?;
    if hook_event_name != "PreToolUse" {
        return Err("field `hook_event_name` must be `PreToolUse`".to_owned());
    }
    let tool_name = required_string(object, "tool_name")?;
    let tool_input = object
        .get("tool_input")
        .ok_or_else(|| "required field `tool_input` is missing".to_owned())?
        .as_object()
        .ok_or_else(|| "field `tool_input` must be an object".to_owned())?
        .clone();
    let tool_use_id = required_string(object, "tool_use_id")?;

    let bash = if tool_name == "Bash" {
        Some(decode_bash(&tool_input)?)
    } else {
        None
    };

    Ok(DecodeResult::Decoded(Box::new(PermissionRequest {
        session_id,
        cwd,
        transcript_path,
        agent_id,
        permission_mode,
        hook_event_name,
        tool_name,
        tool_input,
        tool_use_id,
        bash,
    })))
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, String> {
    object
        .get(field)
        .ok_or_else(|| format!("required field `{field}` is missing"))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("field `{field}` must be a string"))
}

fn decode_bash(tool_input: &Map<String, Value>) -> Result<BashInput, String> {
    let command = tool_input
        .get("command")
        .ok_or_else(|| "required Bash field `command` is missing".to_owned())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "Bash field `command` must be a string".to_owned())?;
    let description = optional_string(tool_input, "description")?;
    let timeout_ms = optional_timeout(tool_input)?;
    let run_in_background = optional_bool(tool_input, "run_in_background")?;

    Ok(BashInput {
        command,
        description,
        timeout_ms,
        run_in_background,
    })
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("Bash field `{field}` must be a string"))
        })
        .transpose()
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("Bash field `{field}` must be a boolean"))
        })
        .transpose()
}

fn optional_timeout(object: &Map<String, Value>) -> Result<Option<u64>, String> {
    object
        .get("timeout")
        .map(|value| {
            value
                .as_u64()
                .filter(|timeout| *timeout <= MAX_BASH_TIMEOUT_MS)
                .ok_or_else(|| {
                    format!(
                        "Bash field `timeout` must be a nonnegative integer number no greater than {MAX_BASH_TIMEOUT_MS}"
                    )
                })
        })
        .transpose()
}
