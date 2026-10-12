//! Closed mode histories and data-supplied would-do decisions.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Value, json};

use super::{Mode, ModeSetting, exact, word};
use crate::error::LaneError;

const MAX_CLASSES: usize = 128;
const MAX_SETTINGS: usize = 64;
const MAX_RULES: usize = 64;

fn problem(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

fn class_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// One class or the loop-wide setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeTarget {
    Loop,
    Class(String),
}

impl ModeTarget {
    /// Validate a named class before it can enter the protected history.
    ///
    /// # Errors
    ///
    /// Refuses empty, overlong, or path-like class names.
    pub fn class(name: &str) -> Result<Self, LaneError> {
        if class_name(name) {
            Ok(Self::Class(name.to_owned()))
        } else {
            Err(problem(
                "door-mode-setting-refusal",
                "class name is invalid",
            ))
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Loop => "loop",
            Self::Class(name) => name,
        }
    }
}

/// The sole serialized history for a loop's class and loop-wide settings.
#[derive(Clone, Debug)]
pub struct ModeLedger {
    loop_name: String,
    revision: u64,
    loop_settings: Vec<ModeSetting>,
    classes: BTreeMap<String, Vec<ModeSetting>>,
}

impl ModeLedger {
    /// An empty history before the first explicit setting.
    #[must_use]
    pub fn empty(loop_name: &str) -> Self {
        Self {
            loop_name: loop_name.to_owned(),
            revision: 0,
            loop_settings: Vec::new(),
            classes: BTreeMap::new(),
        }
    }

    /// Decode the exact version-one history without accepting old shapes.
    ///
    /// # Errors
    ///
    /// Refuses changed keys, duplicate classes, invalid histories or limits.
    pub fn decode(value: &Value, loop_name: &str) -> Result<Self, LaneError> {
        if !exact(
            value,
            &["schema", "loop", "revision", "loop_settings", "classes"],
        ) || value["schema"] != 1
            || value["loop"] != loop_name
        {
            return Err(problem(
                "door-mode-record-refusal",
                "mode history shape or loop differs",
            ));
        }
        let revision = value["revision"]
            .as_u64()
            .ok_or_else(|| problem("door-mode-record-refusal", "mode revision is invalid"))?;
        let loop_settings = decode_settings(&value["loop_settings"])?;
        let rows = value["classes"]
            .as_array()
            .filter(|rows| rows.len() <= MAX_CLASSES)
            .ok_or_else(|| problem("door-mode-record-refusal", "class list exceeds limit"))?;
        let mut classes = BTreeMap::new();
        for row in rows {
            if !exact(row, &["class", "settings"]) {
                return Err(problem(
                    "door-mode-record-refusal",
                    "class history shape differs",
                ));
            }
            let name = row["class"]
                .as_str()
                .filter(|name| class_name(name))
                .ok_or_else(|| {
                    problem("door-mode-record-refusal", "class history name is invalid")
                })?;
            let settings = decode_settings(&row["settings"])?;
            if settings.is_empty() || classes.insert(name.to_owned(), settings).is_some() {
                return Err(problem(
                    "door-mode-record-refusal",
                    "class history is empty or repeated",
                ));
            }
        }
        let total = loop_settings.len() + classes.values().map(Vec::len).sum::<usize>();
        if revision != total as u64 || total == 0 {
            return Err(problem(
                "door-mode-record-refusal",
                "mode revision differs from history",
            ));
        }
        Ok(Self {
            loop_name: loop_name.to_owned(),
            revision,
            loop_settings,
            classes,
        })
    }

    /// Serialize one canonical version-one history.
    #[must_use]
    pub fn value(&self) -> Value {
        let classes = self.classes.iter().map(|(name, settings)| {
            json!({"class":name,"settings":settings.iter().map(ModeSetting::value).collect::<Vec<_>>()})
        }).collect::<Vec<_>>();
        json!({"schema":1,"loop":self.loop_name,"revision":self.revision,
            "loop_settings":self.loop_settings.iter().map(ModeSetting::value).collect::<Vec<_>>(),
            "classes":classes})
    }

    /// Current setting for one target, if it has been explicitly set.
    #[must_use]
    pub fn current(&self, target: &ModeTarget) -> Option<&ModeSetting> {
        match target {
            ModeTarget::Loop => self.loop_settings.last(),
            ModeTarget::Class(name) => self.classes.get(name).and_then(|history| history.last()),
        }
    }

    /// Effective setting bounded by both snapshots and the current row floor.
    #[must_use]
    pub fn effective(&self, class: &str, floor: Mode) -> Option<Value> {
        let class_setting = self.current(&ModeTarget::Class(class.to_owned()))?;
        let loop_setting = self.current(&ModeTarget::Loop)?;
        let class_mode = Mode::parse(class_setting.value()["mode"].as_str()?)?;
        let loop_mode = Mode::parse(loop_setting.value()["mode"].as_str()?)?;
        let selected = execute_command::policy::effective_mode(
            class_mode.domain(),
            loop_mode.domain(),
            execute_command::policy::DoorMode::Allow,
            false,
        );
        Some(
            json!({"class":class_setting.value(),"loop":loop_setting.value(),
            "floor":floor.as_str(),"floor_bounded":floor.domain() < selected,
            "mode":execute_command::policy::effective_mode(class_mode.domain(), loop_mode.domain(), floor.domain(), false).as_str()}),
        )
    }

    /// Recover the last non-exercise setting before a trailing exercise history.
    pub(crate) fn recover_agent_loop(&mut self, floor: Mode, at: &str) -> Result<Value, LaneError> {
        let Some(current) = self.loop_settings.last() else {
            return Ok(json!({"status":"unchanged","mode":null}));
        };
        if !matches!(
            current.value()["setter"].as_str(),
            Some("exercise-agent" | "exercise-agent-restoration")
        ) {
            return Ok(json!({"status":"unchanged","mode":current.value()["mode"]}));
        }
        let previous = self
            .loop_settings
            .iter()
            .rev()
            .find(|setting| {
                !matches!(
                    setting.value()["setter"].as_str(),
                    Some("exercise-agent" | "exercise-agent-restoration")
                )
            })
            .ok_or_else(|| {
                problem(
                    "door-mode-setting-refusal",
                    "exercise revision has no preceding loop setting",
                )
            })?;
        let mode = Mode::parse(previous.value()["mode"].as_str().unwrap_or_default())
            .ok_or_else(|| problem("door-mode-record-refusal", "prior mode is invalid"))?;
        let restored_revision = previous.value()["revision"].clone();
        if current.value()["mode"] == previous.value()["mode"] {
            return Ok(
                json!({"status":"unchanged","mode":mode.as_str(),"restored_revision":restored_revision}),
            );
        }
        mode.within(floor)?;
        if self.revision == u64::MAX || self.loop_settings.len() >= MAX_SETTINGS {
            return Err(problem(
                "door-mode-record-refusal",
                "setting history is full",
            ));
        }
        let evidence =
            format!("restore loop setting revision {restored_revision} after exercise-agent");
        let setting = current.changed(
            mode,
            floor,
            "exercise-agent-restoration",
            &evidence,
            at,
            &[],
        )?;
        self.loop_settings.push(setting.clone());
        self.revision += 1;
        Ok(
            json!({"status":"restored","mode":mode.as_str(),"restored_revision":restored_revision,
            "revision":self.revision,"setting":setting.value()}),
        )
    }

    /// Record a first setting or a cited mode move.
    ///
    /// # Errors
    ///
    /// Refuses a below-floor, duplicate, uncited relaxation or full history.
    #[allow(clippy::too_many_arguments)]
    pub fn set(
        &mut self,
        target: &ModeTarget,
        mode: Mode,
        floor: Mode,
        setter: &str,
        evidence: &str,
        at: &str,
        citations: &[String],
    ) -> Result<Value, LaneError> {
        mode.within(floor)?;
        if self.revision == u64::MAX {
            return Err(problem(
                "door-mode-record-refusal",
                "mode history revision is full",
            ));
        }
        let prior = self.current(target);
        let previous = prior
            .map(|setting| {
                execute_command::policy::DoorMode::from_record(setting.value()["mode"].as_str())
            })
            .transpose()
            .map_err(super::command::shape)?;
        let binding = super::command::binding(
            &json!({"target":target.name(),"mode":mode.as_str(),"floor":floor.as_str(),"prior":prior.map(ModeSetting::value)}),
        );
        let verdict = execute_command::policy::mode_transition(
            &binding,
            previous,
            mode.domain(),
            floor.domain(),
            &super::command::texts(citations)?,
        )
        .map_err(super::command::shape)?;
        super::command::accept(Some(verdict.clone()))?;
        let direction = verdict.reason.as_str();
        let setting = if let Some(prior) = prior {
            prior.changed(mode, floor, setter, evidence, at, citations)?
        } else {
            ModeSetting::first(mode, floor, setter, evidence, at)?
        };
        let history = match target {
            ModeTarget::Loop => &mut self.loop_settings,
            ModeTarget::Class(name) => {
                if !self.classes.contains_key(name) && self.classes.len() >= MAX_CLASSES {
                    return Err(problem(
                        "door-mode-record-refusal",
                        "class list exceeds limit",
                    ));
                }
                self.classes.entry(name.clone()).or_default()
            }
        };
        if history.len() >= MAX_SETTINGS {
            return Err(problem(
                "door-mode-record-refusal",
                "setting history exceeds limit",
            ));
        }
        history.push(setting.clone());
        self.revision += 1;
        Ok(
            json!({"target":target.name(),"mode":mode.as_str(),"floor":floor.as_str(),
            "direction":direction,"revision":self.revision,"setting":setting.value()}),
        )
    }
}

fn decode_settings(value: &Value) -> Result<Vec<ModeSetting>, LaneError> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= MAX_SETTINGS)
        .ok_or_else(|| problem("door-mode-record-refusal", "setting list exceeds limit"))?;
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let setting = ModeSetting::decode(row.clone())?;
            if setting.value()["revision"] != (index + 1) as u64 {
                return Err(problem(
                    "door-mode-record-refusal",
                    "setting revision is not consecutive",
                ));
            }
            Ok(setting)
        })
        .collect()
}

/// One bounded, exact-match rubric supplied by its caller.
#[derive(Clone, Debug)]
pub struct Rubric {
    class: String,
    undecided_reason: String,
    rules: Vec<Value>,
}

impl Rubric {
    /// Class named by this pinned rubric.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }
    /// Validate a fixture-supplied rubric without installing a production class.
    ///
    /// # Errors
    ///
    /// Refuses a changed shape, duplicate row, invalid reason or excess rows.
    pub fn decode(value: &Value) -> Result<Self, LaneError> {
        if !exact(value, &["schema", "class", "undecided_reason", "rules"])
            || value["schema"] != 1
            || value["class"].as_str().is_none_or(|name| !class_name(name))
            || !word(&value["undecided_reason"], 1024)
        {
            return Err(problem("door-rubric-refusal", "rubric shape differs"));
        }
        let rows = value["rules"]
            .as_array()
            .filter(|rows| rows.len() <= MAX_RULES)
            .ok_or_else(|| problem("door-rubric-refusal", "rubric row list exceeds limit"))?;
        let mut seen = HashSet::new();
        for row in rows {
            if !exact(row, &["operation", "shape_key", "decision", "reason"])
                || !word(&row["operation"], 80)
                || !word(&row["shape_key"], 256)
                || !word(&row["reason"], 1024)
                || !matches!(row["decision"].as_str(), Some("allow" | "refuse"))
            {
                return Err(problem("door-rubric-refusal", "rubric row shape differs"));
            }
            let key = (
                row["operation"].as_str().unwrap_or_default(),
                row["shape_key"].as_str().unwrap_or_default(),
            );
            if !seen.insert(key) {
                return Err(problem("door-rubric-refusal", "rubric row is repeated"));
            }
        }
        Ok(Self {
            class: value["class"].as_str().unwrap_or_default().to_owned(),
            undecided_reason: value["undecided_reason"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            rules: rows.clone(),
        })
    }

    /// State an exact request's would-do and reason, including undecided.
    #[must_use]
    pub fn would_do(&self, class: &str, operation: &str, shape_key: &str) -> Value {
        execute_command::rubric::door_would_do(
            &self.class,
            &self.rules,
            &self.undecided_reason,
            class,
            operation,
            shape_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Mode, ModeLedger, ModeTarget, Rubric};

    /// ´test:unit:mode-history-keeps-first-moves-and-strictest-effective-setting´
    #[test]
    fn mode_history_keeps_first_moves_and_strictest_effective_setting() {
        let mut ledger = ModeLedger::empty("alpha");
        let class = ModeTarget::class("fixture").expect("fixture class");
        let first = ledger
            .set(
                &ModeTarget::Loop,
                Mode::Enforce,
                Mode::Allow,
                "owner",
                "floor permits fixture",
                "1",
                &[],
            )
            .expect("loop first");
        assert_eq!(first["direction"], "first");
        ledger
            .set(
                &class,
                Mode::Allow,
                Mode::Allow,
                "owner",
                "known harmless fixture",
                "2",
                &[],
            )
            .expect("class first");
        assert_eq!(
            ledger.effective("fixture", Mode::Allow).expect("effective")["mode"],
            "enforce"
        );
        let strict = ledger
            .set(
                &class,
                Mode::Audit,
                Mode::Allow,
                "owner",
                "correction",
                "3",
                &[],
            )
            .expect("stricter");
        assert_eq!(strict["direction"], "stricter");
        assert_eq!(
            ledger.effective("fixture", Mode::Allow).expect("effective")["mode"],
            "audit"
        );
        let cited = vec!["R:1a".to_owned()];
        let relaxed = ledger
            .set(
                &class,
                Mode::Enforce,
                Mode::Allow,
                "owner",
                "agreeing label",
                "4",
                &cited,
            )
            .expect("relaxed fixture");
        assert_eq!(relaxed["direction"], "relaxed");
        assert_eq!(relaxed["setting"]["citations"], json!(["R:1a"]));
        let saved = ledger.value();
        assert_eq!(saved["revision"], 4);
        assert_eq!(
            ModeLedger::decode(&saved, "alpha")
                .expect("decode")
                .effective("fixture", Mode::Allow)
                .expect("effective")["mode"],
            "enforce"
        );
    }

    /// ´test:unit:mode-history-refuses-floor-uncited-relaxation-and-changed-shapes´
    #[test]
    fn mode_history_refuses_floor_uncited_relaxation_and_changed_shapes() {
        assert_eq!(
            ModeTarget::class("../other").expect_err("class path").kind,
            "door-mode-setting-refusal"
        );
        let class = ModeTarget::class("fixture").expect("class");
        let mut ledger = ModeLedger::empty("alpha");
        ledger
            .set(&class, Mode::Audit, Mode::Audit, "owner", "first", "1", &[])
            .expect("first");
        assert_eq!(
            ledger
                .set(
                    &class,
                    Mode::Enforce,
                    Mode::Audit,
                    "owner",
                    "below floor",
                    "2",
                    &[]
                )
                .expect_err("floor")
                .kind,
            "door-mode-floor-refusal"
        );
        assert_eq!(
            ledger
                .set(&class, Mode::Audit, Mode::Audit, "owner", "same", "2", &[])
                .expect_err("unchanged")
                .kind,
            "door-mode-setting-refusal"
        );
        assert_eq!(
            ledger
                .set(
                    &class,
                    Mode::Enforce,
                    Mode::Allow,
                    "owner",
                    "no labels",
                    "2",
                    &[]
                )
                .expect_err("uncited")
                .kind,
            "door-mode-evidence-refusal"
        );
        let mut old = ledger.value();
        old["schema"] = json!(0);
        assert_eq!(
            ModeLedger::decode(&old, "alpha")
                .expect_err("old schema")
                .kind,
            "door-mode-record-refusal"
        );
        let mut changed = ledger.value();
        changed["classes"][0]["settings"][0]["revision"] = json!(3);
        assert_eq!(
            ModeLedger::decode(&changed, "alpha")
                .expect_err("revision")
                .kind,
            "door-mode-record-refusal"
        );
        let mut duplicate = ledger.value();
        let first = duplicate["classes"][0].clone();
        duplicate["classes"]
            .as_array_mut()
            .expect("classes")
            .push(first);
        duplicate["revision"] = json!(2);
        assert_eq!(
            ModeLedger::decode(&duplicate, "alpha")
                .expect_err("duplicate class")
                .kind,
            "door-mode-record-refusal"
        );
    }

    /// ´test:unit:mode-history-writer-stops-at-reader-bound´
    #[test]
    fn mode_history_writer_stops_at_reader_bound() {
        let mut ledger = ModeLedger::empty("alpha");
        let class = ModeTarget::class("fixture").expect("fixture class");
        ledger
            .set(&class, Mode::Audit, Mode::Allow, "owner", "first", "1", &[])
            .expect("first");
        for index in 2..=64 {
            let mode = if index % 2 == 0 {
                Mode::Enforce
            } else {
                Mode::Audit
            };
            let citations = if mode == Mode::Enforce {
                vec!["R:1a".to_owned()]
            } else {
                Vec::new()
            };
            ledger
                .set(
                    &class,
                    mode,
                    Mode::Allow,
                    "owner",
                    "bounded fixture",
                    &index.to_string(),
                    &citations,
                )
                .expect("within bound");
        }
        let before = ledger.value();
        assert_eq!(
            ledger
                .set(
                    &class,
                    Mode::Audit,
                    Mode::Allow,
                    "owner",
                    "over bound",
                    "65",
                    &[]
                )
                .expect_err("full history")
                .kind,
            "door-mode-record-refusal"
        );
        assert_eq!(ledger.value(), before);
    }

    /// ´test:unit:fixture-rubric-states-allow-refuse-and-undecided-reasons´
    #[test]
    fn fixture_rubric_states_allow_refuse_and_undecided_reasons() {
        let data = json!({"schema":1,"class":"fixture","undecided_reason":"no exact fixture rule",
        "rules":[
            {"operation":"read","shape_key":"shape:read","decision":"allow","reason":"fixture read"},
            {"operation":"write","shape_key":"shape:write","decision":"refuse","reason":"fixture write"}
        ]});
        let rubric = Rubric::decode(&data).expect("fixture rubric");
        assert_eq!(
            rubric.would_do("fixture", "read", "shape:read"),
            json!({"decision":"allow","reason":"fixture read"})
        );
        assert_eq!(
            rubric.would_do("fixture", "write", "shape:write"),
            json!({"decision":"refuse","reason":"fixture write"})
        );
        assert_eq!(
            rubric.would_do("fixture", "other", "shape:other"),
            json!({"decision":"undecided","reason":"no exact fixture rule"})
        );
        assert_eq!(
            rubric.would_do("another", "read", "shape:read")["decision"],
            "undecided"
        );
        let mut duplicate = data.clone();
        let first = data["rules"][0].clone();
        duplicate["rules"]
            .as_array_mut()
            .expect("rules")
            .push(first);
        assert_eq!(
            Rubric::decode(&duplicate).expect_err("duplicate").kind,
            "door-rubric-refusal"
        );
        let mut malformed = data;
        malformed["rules"][0]["reason"] = json!("");
        assert_eq!(
            Rubric::decode(&malformed).expect_err("missing reason").kind,
            "door-rubric-refusal"
        );
    }
}
