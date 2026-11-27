//! Preserve legacy JSON decoding, checking only the path to placement facts.
use crate::error::LaneError;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Copy)]
enum Scope {
    Reservation,
    HistoricalReservation,
    Rounds,
    Round,
    ReplyDesignation,
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
    reply_issue: Option<&'static str>,
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
        let mut reply_seen = false;
        let mut state_seen = false;
        while let Some(key) = map.next_key::<String>()? {
            if matches!(self, Self::Round) && key == "reply_designation" {
                let nested = map.next_value_seed(Self::ReplyDesignation)?;
                if reply_seen {
                    result.reply_issue = Some("reply_designation appears twice");
                } else {
                    result.reply_issue = nested.reply_issue;
                }
                reply_seen = true;
                continue;
            }
            if matches!(self, Self::ReplyDesignation) {
                if key == "state" {
                    let state: Value = map.next_value()?;
                    if state_seen {
                        result.reply_issue = Some("reply_designation state appears twice");
                    } else if state != "unmeasured" {
                        result.reply_issue = Some("reply_designation has an unknown state");
                    }
                    state_seen = true;
                } else {
                    let _ignored: IgnoredAny = map.next_value()?;
                    result.reply_issue = Some("reply_designation has extra keys");
                }
                continue;
            }
            let child = match self {
                Self::Reservation | Self::HistoricalReservation if key == "plan" => {
                    Some(Self::Plan)
                }
                Self::Reservation if key == "rounds" => Some(Self::Rounds),
                Self::Journal if key == "plan" => Some(Self::RewritePlan),
                Self::RewritePlan if key == "files" => Some(Self::FileRow),
                Self::FileRow if key == "before" || key == "after" => {
                    Some(Self::HistoricalReservation)
                }
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
                result.reply_issue = result.reply_issue.or(nested.reply_issue);
            } else {
                let _ignored: IgnoredAny = map.next_value()?;
            }
        }
        result.duplicate |= seen
            .values()
            .any(|(count, on_path)| *count > 1 && (*on_path || matches!(self, Self::Placement)));
        if matches!(self, Self::Round) && !reply_seen {
            result.reply_issue = Some("reply_designation is missing");
        }
        if matches!(self, Self::ReplyDesignation) && !state_seen {
            result.reply_issue = Some("reply_designation has an unknown state");
        }
        Ok(result)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scan, A::Error> {
        if matches!(self, Self::Round | Self::ReplyDesignation) {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(self.scalar_issue());
        }
        let mut result = Scan::default();
        if !matches!(self, Self::FileRow | Self::Placement | Self::Rounds) {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(result);
        }
        let element = if matches!(self, Self::Rounds) {
            Self::Round
        } else {
            self
        };
        while let Some(child) = seq.next_element_seed(element)? {
            result.placement |= child.placement;
            result.duplicate |= child.duplicate;
            result.reply_issue = result.reply_issue.or(child.reply_issue);
        }
        Ok(result)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Scan, E> {
        Ok(self.scalar_issue())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Scan, E> {
        Ok(self.scalar_issue())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Scan, E> {
        Ok(self.scalar_issue())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Scan, E> {
        Ok(self.scalar_issue())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Scan, E> {
        Ok(self.scalar_issue())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Scan, E> {
        Ok(Scan {
            reply_issue: if matches!(self, Self::ReplyDesignation) {
                Some("reply_designation is null")
            } else if matches!(self, Self::Round) {
                Some("round row is not an object")
            } else {
                None
            },
            ..Scan::default()
        })
    }
}

impl Scope {
    fn scalar_issue(self) -> Scan {
        Scan {
            reply_issue: if matches!(self, Self::ReplyDesignation) {
                Some("reply_designation must be an object")
            } else if matches!(self, Self::Round) {
                Some("round row is not an object")
            } else {
                None
            },
            ..Scan::default()
        }
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
    if matches!(scope, Scope::Reservation)
        && let Some(issue) = scan.reply_issue
    {
        let run = value["run"].as_str().unwrap_or("<unknown>");
        let loop_name = value["loop"].as_str().unwrap_or("<unknown>");
        return Err(LaneError::input(
            "reply-designation-row",
            format!(
                "run {run}: {issue}; preview conversion with superloop-lane census rewrite-replies {loop_name} --dry-run"
            ),
        ));
    }
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
                Scope::Reservation | Scope::HistoricalReservation => &value["plan"],
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

pub fn conversion_reservation_bytes(
    bytes: &[u8],
    syntax: impl FnOnce(serde_json::Error) -> LaneError,
) -> Result<Value, LaneError> {
    decode(bytes, Scope::HistoricalReservation, syntax)
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
