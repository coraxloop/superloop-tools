//! Owner-published policy evidence; custody and publication belong to adapters.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::request::ShapeError;

/// One source revision with its canonical content digest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub revision: String,
    pub sha256: String,
    pub value: Value,
}

impl Source {
    /// Stamp an independently observed source revision and canonical value.
    ///
    /// # Errors
    /// Refuses a value that cannot be encoded.
    pub fn new(revision: String, value: Value) -> Result<Self, ShapeError> {
        let bytes =
            serde_json::to_vec(&value).map_err(|_| ShapeError("execute-command-record-shape"))?;
        Ok(Self {
            revision,
            sha256: crate::rubric::sha256_digest(&bytes),
            value,
        })
    }

    fn valid(&self) -> bool {
        !self.revision.is_empty()
            && serde_json::to_vec(&self.value)
                .is_ok_and(|bytes| crate::rubric::sha256_digest(&bytes) == self.sha256)
    }
}

/// Policy selected by the authenticated loop identity, never by request text.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshot {
    pub schema: u32,
    #[serde(rename = "loop")]
    pub loop_name: String,
    pub loop_uid: u32,
    pub written_at: String,
    pub door: bool,
    pub registry: Source,
    pub modes: Source,
    pub learned: Source,
    pub rubric: Source,
}

impl PolicySnapshot {
    /// Decode the current shape and verify every source digest.
    ///
    /// # Errors
    /// Refuses unknown shapes, incomplete evidence or inconsistent digests.
    pub fn decode(bytes: &[u8]) -> Result<Self, ShapeError> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| ShapeError("execute-command-record-shape"))?;
        if value.schema != 1
            || value.loop_name.is_empty()
            || value.written_at.is_empty()
            || ![&value.registry, &value.modes, &value.learned, &value.rubric]
                .into_iter()
                .all(Source::valid)
        {
            return Err(ShapeError("execute-command-record-shape"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// ´claim:snapshot:policy-snapshot-rejects-unknown-shapes-and-changed-observations´
    /// ´test:unit:policy-snapshot-rejects-unknown-shapes-and-changed-observations´
    #[test]
    fn policy_snapshot_rejects_unknown_shapes_and_changed_observations() {
        let source = Source::new("revision-1".into(), json!({"floor":"audit"})).expect("source");
        let snapshot = PolicySnapshot {
            schema: 1,
            loop_name: "fixture".into(),
            loop_uid: 41001,
            written_at: "1".into(),
            door: false,
            registry: source.clone(),
            modes: source.clone(),
            learned: source.clone(),
            rubric: source,
        };
        let encoded = serde_json::to_vec(&snapshot).expect("snapshot");
        PolicySnapshot::decode(&encoded).expect("intact observations");
        let original = serde_json::to_value(snapshot).expect("value");
        let mut changed = original.clone();
        changed["registry"]["value"]["floor"] = json!("allow");
        let mut unknown = original.clone();
        unknown["schema"] = json!(2);
        let mut extra = original;
        extra["owner_uid"] = json!(1000);
        for invalid in [changed, unknown, extra] {
            assert_eq!(
                PolicySnapshot::decode(&serde_json::to_vec(&invalid).expect("fixture"))
                    .expect_err("strict shape")
                    .0,
                "execute-command-record-shape"
            );
        }
    }
}
