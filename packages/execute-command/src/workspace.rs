//! Reader-only workspace contracts. No filesystem access, execution or legacy dispatch.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

mod classification;
mod evidence;
pub use classification::*;
pub use evidence::*;

/// A named admission failure, separate from a policy classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub kind: &'static str,
    pub detail: String,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}
impl std::error::Error for Refusal {}
fn protocol(detail: impl Into<String>) -> Refusal {
    Refusal {
        kind: "door-workspace-protocol-refusal",
        detail: detail.into(),
    }
}
fn context(detail: impl Into<String>) -> Refusal {
    Refusal {
        kind: "door-workspace-context-differs",
        detail: detail.into(),
    }
}

/// SHA-256 of canonical JSON: sorted object keys, ordered arrays, compact UTF-8.
/// # Errors
/// Refuses values that cannot be encoded as JSON.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, Refusal> {
    // Explicit recursive ordering also holds when serde_json uses preserve_order.
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            ),
            Value::Array(array) => Value::Array(array.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    let value = sorted(serde_json::to_value(value).map_err(|e| protocol(e.to_string()))?);
    let bytes = serde_json::to_vec(&value).map_err(|e| protocol(e.to_string()))?;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str) -> bool {
    !value.is_empty() && !value.contains('\0')
}
fn component(value: &str) -> bool {
    text(value) && !matches!(value, "." | "..") && !value.contains('/')
}
fn absolute(value: &str) -> bool {
    value == "/" || (value.starts_with('/') && value[1..].split('/').all(component))
}
fn environment(pairs: &[(String, String)]) -> bool {
    pairs
        .iter()
        .all(|(name, value)| text(name) && !name.contains('=') && !value.contains('\0'))
}

/// Exact process representation. Argv words are bytes, never lossy Unicode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Execution {
    Argv { words: Vec<Vec<u8>> },
    Sequence { steps: Vec<Vec<Vec<u8>>> },
    Shell { shell: String, text: String },
}
impl Execution {
    fn validate(&self) -> Result<(), Refusal> {
        let argv = |words: &[Vec<u8>]| {
            (1..=256).contains(&words.len())
                && !words[0].is_empty()
                && words.iter().all(|w| !w.contains(&0))
        };
        let (valid, bytes) = match self {
            Self::Argv { words } => (argv(words), words.iter().map(Vec::len).sum::<usize>()),
            Self::Sequence { steps } => (
                (1..=8).contains(&steps.len()) && steps.iter().all(|w| argv(w)),
                steps.iter().flatten().map(Vec::len).sum(),
            ),
            Self::Shell { shell, text } => (
                absolute(shell) && !text.contains('\0'),
                shell.len() + text.len(),
            ),
        };
        if !valid || bytes > 65_536 {
            return Err(protocol("execution shape or 65536-byte bound differs"));
        }
        Ok(())
    }
    pub(super) fn steps(&self) -> Option<Vec<&[Vec<u8>]>> {
        match self {
            Self::Argv { words } => Some(vec![words]),
            Self::Sequence { steps } => Some(steps.iter().map(Vec::as_slice).collect()),
            Self::Shell { .. } => None,
        }
    }
}

/// Maximum encoded workspace frame, also the bounded preflight evidence prefix.
pub const MAX_WIRE_BYTES: usize = 1_048_576;

/// Transport schema three. Decode checks structure; grant admission checks authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: u8,
    /// Trusted owner snapshot versus requester-selected context (workspace protocol).
    pub grant_digest: String,
    pub cwd: Vec<String>,
    pub execution: Execution,
    pub env_additions: Vec<(String, String)>,
    pub deadline_ms: u64,
}
impl Envelope {
    /// Decode wire bytes without lossy Unicode or duplicate-field coercion.
    /// # Errors
    /// Refuses invalid JSON, duplicate/unknown fields, invalid UTF-8 and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(protocol("transport exceeds 1048576 bytes"));
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|e| protocol(e.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Decode exact transport fields and bounds without interpreting command semantics.
    /// # Errors
    /// Returns the workspace protocol refusal for malformed encoding or bounds.
    pub fn decode(value: Value) -> Result<Self, Refusal> {
        let result: Self = serde_json::from_value(value).map_err(|e| protocol(e.to_string()))?;
        result.validate()?;
        Ok(result)
    }
    /// Validate a constructed envelope just as a decoded one.
    /// # Errors
    /// Refuses malformed fields or a deadline outside the existing maximum.
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.schema != 3
            || !digest(&self.grant_digest)
            || self.cwd.len() > 256
            || !self.cwd.iter().all(|c| component(c))
            || !environment(&self.env_additions)
            || !(1..=86_400_000).contains(&self.deadline_ms)
            || self.cwd.iter().map(String::len).sum::<usize>() > 65_536
            || self
                .env_additions
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 65_536
        {
            return Err(protocol("envelope fields differ"));
        }
        self.execution.validate()
    }
}

/// Immutable owner declaration, read from the reservation's plan, never worker authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub schema: u8,
    #[serde(rename = "loop")]
    pub loop_name: String,
    pub run: String,
    pub node: String,
    pub workspace: String,
    pub baseline_env: Vec<(String, String)>,
    pub resources: BTreeMap<String, String>,
    pub shells: Vec<String>,
    /// Owner-published rule bytes versus a substituted positive table; full binding.
    pub quick_policy_digest: String,
    /// Owner-published blacklist versus substituted negative policy; full binding.
    pub blacklist_digest: String,
    pub executor_protocol: u8,
}
impl Grant {
    /// Decode the grant body. Its snapshot binds the digest separately.
    /// # Errors
    /// Refuses malformed schema, identity, paths, environment or digests.
    pub fn decode(value: Value) -> Result<Self, Refusal> {
        let grant: Self = serde_json::from_value(value).map_err(|e| protocol(e.to_string()))?;
        grant.validate()?;
        Ok(grant)
    }
    /// Check owner declaration syntax; no node probing or directory creation.
    /// # Errors
    /// Refuses an incomplete or malformed declaration.
    pub fn validate(&self) -> Result<(), Refusal> {
        let path = self
            .baseline_env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v);
        if self.schema != 1
            || self.executor_protocol != 1
            || !component(&self.loop_name)
            || !component(&self.run)
            || !text(&self.node)
            || !absolute(&self.workspace)
            || !environment(&self.baseline_env)
            || path.is_none()
            || !self
                .resources
                .iter()
                .all(|(k, v)| component(k) && absolute(v))
            || !self.shells.iter().all(|s| absolute(s))
            || self.shells.iter().collect::<BTreeSet<_>>().len() != self.shells.len()
            || !digest(&self.quick_policy_digest)
            || !digest(&self.blacklist_digest)
        {
            return Err(protocol("grant fields differ"));
        }
        Ok(())
    }
    /// Canonical identity of every field of the declaration.
    /// # Errors
    /// Refuses an invalid declaration or JSON encoding.
    pub fn digest(&self) -> Result<String, Refusal> {
        self.validate()?;
        canonical_digest(self)
    }
}

/// Snapshot shape accepted by plan and reservation readers before launch writes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSnapshot {
    pub grant: Grant,
    /// Protected launch declaration versus altered grant bytes; custody authenticates the reference.
    pub digest: String,
}
impl GrantSnapshot {
    /// Read and bind the grant to its surrounding protected plan identity.
    /// # Errors
    /// Refuses an altered digest or a foreign loop/run.
    pub fn decode(value: Value, loop_name: &str, run: &str) -> Result<Self, Refusal> {
        let snapshot: Self = serde_json::from_value(value).map_err(|e| protocol(e.to_string()))?;
        if snapshot.grant.digest()? != snapshot.digest
            || snapshot.grant.loop_name != loop_name
            || snapshot.grant.run != run
        {
            return Err(context("workspace snapshot identity or digest differs"));
        }
        Ok(snapshot)
    }
}

/// Authenticate the new context before policy classification. Existing SSH/peer checks remain caller-owned.
/// # Errors
/// Names unregistered, context-differs and protocol failures independently of policy misses.
pub fn admit(
    envelope: &Envelope,
    grant: Option<&Grant>,
    loop_name: &str,
    run: &str,
    node: &str,
) -> Result<(), Refusal> {
    let grant = grant.ok_or_else(|| Refusal {
        kind: "door-workspace-unregistered",
        detail: "no protected workspace grant".into(),
    })?;
    grant.validate()?;
    envelope.validate()?;
    if grant.loop_name != loop_name
        || grant.run != run
        || grant.node != node
        || grant.digest()? != envelope.grant_digest
    {
        return Err(context("request identity or grant digest differs"));
    }
    if let Execution::Shell { shell, .. } = &envelope.execution
        && !grant.shells.contains(shell)
    {
        return Err(protocol("shell is not named by the grant"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
