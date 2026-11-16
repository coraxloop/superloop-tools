//! Preserve legacy JSON decoding, checking only the path to placement facts.
use crate::error::LaneError;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Copy)]
enum Scope {
    Reservation,
    Plan,
    Placement,
    Journal,
    RewritePlan,
    FileRow,
}
#[derive(Default)]
struct Scan {
    placement: bool,
    duplicate: bool,
}
impl<'de> DeserializeSeed<'de> for Scope {
    type Value = Scan;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Scan, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scope {
    type Value = Scan;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Scan, M::Error> {
        let mut result = Scan::default();
        let mut seen = std::collections::BTreeMap::<String, (usize, bool)>::new();
        while let Some(key) = map.next_key::<String>()? {
            let child = match self {
                Self::Reservation if key == "plan" => Some(Self::Plan),
                Self::Journal if key == "plan" => Some(Self::RewritePlan),
                Self::RewritePlan if key == "files" => Some(Self::FileRow),
                Self::FileRow if key == "before" || key == "after" => Some(Self::Reservation),
                Self::Plan if key == "compute_placement" => Some(Self::Placement),
                Self::Placement => Some(Self::Placement),
                _ => None,
            };
            if let Some(child) = child {
                let nested = map.next_value_seed(child)?;
                let on_path = nested.placement || matches!(self, Self::Plan);
                let count = seen.entry(key).or_default();
                count.0 += 1;
                count.1 |= on_path;
                result.placement |= on_path;
                result.duplicate |= nested.duplicate;
            } else {
                let _ignored: IgnoredAny = map.next_value()?;
            }
        }
        result.duplicate |= seen
            .values()
            .any(|(count, on_path)| *count > 1 && (*on_path || matches!(self, Self::Placement)));
        Ok(result)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scan, A::Error> {
        let mut result = Scan::default();
        if !matches!(self, Self::FileRow | Self::Placement) {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(result);
        }
        while let Some(child) = seq.next_element_seed(self)? {
            result.placement |= child.placement;
            result.duplicate |= child.duplicate;
        }
        Ok(result)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Scan, E> {
        Ok(Scan::default())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Scan, E> {
        Ok(Scan::default())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Scan, E> {
        Ok(Scan::default())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Scan, E> {
        Ok(Scan::default())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Scan, E> {
        Ok(Scan::default())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Scan, E> {
        Ok(Scan::default())
    }
}

fn decode(
    bytes: &[u8],
    scope: Scope,
    syntax: impl FnOnce(serde_json::Error) -> LaneError,
) -> Result<Value, LaneError> {
    // Keep the legacy parser and its exact diagnostics first, including malformed JSON.
    let value: Value = serde_json::from_slice(bytes).map_err(syntax)?;
    let scan = scope
        .deserialize(&mut serde_json::Deserializer::from_slice(bytes))
        .map_err(|e| super::refusal(e.to_string()))?;
    if scan.placement {
        if scan.duplicate {
            return Err(super::refusal("duplicate key on placement path"));
        }
        if matches!(scope, Scope::Journal) {
            if let Some(files) = value["plan"]["files"].as_array() {
                for row in files {
                    for key in ["before", "after"] {
                        let _grant = crate::plan::workspace_snapshot(&row[key]["plan"])?;
                    }
                }
            }
        } else {
            let plan = match scope {
                Scope::Reservation => &value["plan"],
                _ => &value,
            };
            let _grant = crate::plan::workspace_snapshot(plan)?;
        }
    }
    Ok(value)
}

pub fn reservation_bytes(
    bytes: &[u8],
    syntax: impl FnOnce(serde_json::Error) -> LaneError,
) -> Result<Value, LaneError> {
    decode(bytes, Scope::Reservation, syntax)
}
/// Decode standalone plan bytes without losing placement-path duplicate keys.
/// # Errors
/// Preserves the supplied syntax refusal and otherwise refuses invalid placement facts.
pub fn plan_bytes(
    bytes: &[u8],
    syntax: impl FnOnce(serde_json::Error) -> LaneError,
) -> Result<Value, LaneError> {
    decode(bytes, Scope::Plan, syntax)
}

pub fn journal_bytes(
    bytes: &[u8],
    syntax: impl FnOnce(serde_json::Error) -> LaneError,
) -> Result<Value, LaneError> {
    decode(bytes, Scope::Journal, syntax)
}
