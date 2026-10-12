//! Versioned door requests and request-bound adjudication.

/// Maximum output bound admitted by persisted request evidence and transport.
pub const MAX_UPLOAD_OUTPUT_LIMIT: u64 = 1024 * 1024 * 1024;

use serde_json::{Value, json};

use crate::error::LaneError;

mod channel_client;
pub(crate) mod command;
pub mod commands;
pub mod judgement;
pub mod modes;
mod provision;
pub mod store;

const RECORD_KEYS: [&str; 20] = [
    "schema",
    "id",
    "loop",
    "run",
    "worker_uid",
    "class",
    "shape_key",
    "operation",
    "mirror_ref",
    "mode",
    "floor",
    "class_setting",
    "loop_setting",
    "would_do",
    "effect",
    "state",
    "mark_reason",
    "review",
    "label",
    "filed_at",
];

fn refusal(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn word(value: &Value, limit: usize) -> bool {
    value
        .as_str()
        .is_some_and(|word| !word.is_empty() && word.len() <= limit)
}

/// Door modes ordered from strictest to least strict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Audit,
    Enforce,
    Allow,
}

impl Mode {
    /// Decode the caller's existing closed mode spelling through the domain.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        execute_command::policy::DoorMode::from_record(Some(value))
            .ok()
            .map(Self::from)
    }

    /// Caller encoding of the shared door policy mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.domain().as_str()
    }

    pub(crate) const fn domain(self) -> execute_command::policy::DoorMode {
        use execute_command::policy::DoorMode;
        match self {
            Self::Audit => DoorMode::Audit,
            Self::Enforce => DoorMode::Enforce,
            Self::Allow => DoorMode::Allow,
        }
    }

    /// Validate the mode against the registered floor through shared policy.
    ///
    /// # Errors
    /// Refuses a setting below the registry grant.
    pub fn within(self, floor: Self) -> Result<Self, LaneError> {
        let binding = command::binding(&json!({"mode":self.as_str(),"floor":floor.as_str()}));
        command::accept(
            execute_command::policy::mode_floor(&binding, self.domain(), floor.domain())
                .map_err(command::shape)?,
        )?;
        Ok(self)
    }
}

impl From<execute_command::policy::DoorMode> for Mode {
    fn from(mode: execute_command::policy::DoorMode) -> Self {
        use execute_command::policy::DoorMode;
        match mode {
            DoorMode::Audit => Self::Audit,
            DoorMode::Enforce => Self::Enforce,
            DoorMode::Allow => Self::Allow,
        }
    }
}

/// A first setting with its source and floor evidence.
#[derive(Clone, Debug)]
pub struct ModeSetting(Value);

impl ModeSetting {
    /// Build the first recorded setting for a class or loop.
    ///
    /// # Errors
    ///
    /// Refuses a below-floor choice or missing setter and evidence.
    pub fn first(
        mode: Mode,
        floor: Mode,
        setter: &str,
        evidence: &str,
        at: &str,
    ) -> Result<Self, LaneError> {
        mode.within(floor)?;
        let value = json!({"mode":mode.as_str(),"floor":floor.as_str(),"setter":setter,
            "evidence":evidence,"set_at":at,"revision":1,"citations":[]});
        Self::decode(value)
    }

    /// Record a later setting with its exact cited request identifiers.
    ///
    /// # Errors
    ///
    /// Refuses an invalid setting, citation, or revision overflow.
    pub fn changed(
        &self,
        mode: Mode,
        floor: Mode,
        setter: &str,
        evidence: &str,
        at: &str,
        citations: &[String],
    ) -> Result<Self, LaneError> {
        let revision = self.0["revision"]
            .as_u64()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| refusal("requests-record-refusal", "setting revision is full"))?;
        Self::decode(
            json!({"mode":mode.as_str(),"floor":floor.as_str(),"setter":setter,
            "evidence":evidence,"set_at":at,"revision":revision,"citations":citations}),
        )
    }

    /// Validate one exact setting record.
    ///
    /// # Errors
    ///
    /// Refuses an older shape, missing evidence, or below-floor setting.
    pub fn decode(value: Value) -> Result<Self, LaneError> {
        if !exact(
            &value,
            &[
                "mode",
                "floor",
                "setter",
                "evidence",
                "set_at",
                "revision",
                "citations",
            ],
        ) {
            return Err(refusal(
                "requests-record-refusal",
                "mode setting shape differs",
            ));
        }
        let malformed = || refusal("requests-record-refusal", "mode setting shape differs");
        let citations: Vec<String> =
            serde_json::from_value(value["citations"].clone()).map_err(|_| malformed())?;
        let evidence = execute_command::policy::SettingEvidence {
            setter: value["setter"].as_str().ok_or_else(malformed)?,
            evidence: value["evidence"].as_str().ok_or_else(malformed)?,
            set_at: value["set_at"].as_str().ok_or_else(malformed)?,
            revision: value["revision"].as_u64().ok_or_else(malformed)?,
            citations: &citations,
        };
        command::accept(
            execute_command::policy::setting_evidence(&command::binding(&value), &evidence)
                .map_err(command::shape)?,
        )?;
        let mode = value["mode"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "mode is invalid"))?;
        let floor = value["floor"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "floor is invalid"))?;
        mode.within(floor)?;
        Ok(Self(value))
    }

    /// Exact serialized setting.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }
}

/// One fully checked version-four door request.
#[derive(Clone, Debug)]
pub struct RequestRecord(Value);

impl RequestRecord {
    /// Decode the one record shape used by the door and request tools.
    ///
    /// # Errors
    ///
    /// Refuses a malformed or older record before any mutation.
    #[allow(clippy::too_many_lines)]
    pub fn decode(value: Value) -> Result<Self, LaneError> {
        if value["schema"] == 3 {
            return Err(refusal(
                "requests-rewrite-required",
                "schema three requires requests rewrite LOOP --dry-run",
            ));
        }
        let mut keys: Vec<_> = RECORD_KEYS
            .iter()
            .chain(judgement::KEYS.iter())
            .copied()
            .collect();
        for key in [
            "agent_runner_exit",
            "agent_runner_stderr_tail",
            "agent_runner_first_line",
        ] {
            if value.get(key).is_some() {
                keys.push(key);
            }
        }
        if value["schema"] != 4 {
            return Err(refusal("requests-record-refusal", "schema must equal 4"));
        }
        if !exact(&value, &keys) {
            let missing = keys
                .iter()
                .filter(|key| value.get(**key).is_none())
                .copied()
                .collect::<Vec<_>>();
            let extra = value
                .as_object()
                .map(|object| {
                    object
                        .keys()
                        .filter(|key| !keys.contains(&key.as_str()))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Err(refusal(
                "requests-record-refusal",
                format!(
                    "request shape or schema differs; missing fields: {}; unexpected fields: {}",
                    missing.join(", "),
                    extra.join(", ")
                ),
            ));
        }
        if !judgement::valid(&value) {
            return Err(refusal(
                "requests-record-refusal",
                format!(
                    "judgement evidence differs: {}",
                    judgement::invalid_field(&value)
                ),
            ));
        }
        for (key, limit) in [
            ("id", 160),
            ("loop", 80),
            ("run", 64),
            ("class", 80),
            ("shape_key", 256),
            ("operation", 80),
            ("mirror_ref", 160),
            ("filed_at", 64),
        ] {
            if !word(&value[key], limit) {
                return Err(refusal(
                    "requests-record-refusal",
                    format!("{key} is invalid"),
                ));
            }
        }
        if value["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .is_none()
            || value["id"]
                .as_str()
                .and_then(|id| id.split_once(':'))
                .is_none_or(|(run, nonce)| {
                    run != value["run"].as_str().unwrap_or_default()
                        || nonce.is_empty()
                        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        {
            return Err(refusal(
                "requests-record-refusal",
                "request identity is invalid",
            ));
        }
        let floor = value["floor"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "floor is invalid"))?;
        let mode = value["mode"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "mode is invalid"))?;
        mode.within(floor)?;
        let class = ModeSetting::decode(value["class_setting"].clone())?;
        let loop_setting = ModeSetting::decode(value["loop_setting"].clone())?;
        let class_mode = class.value()["mode"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "class mode is invalid"))?;
        let loop_mode = loop_setting.value()["mode"]
            .as_str()
            .and_then(Mode::parse)
            .ok_or_else(|| refusal("requests-record-refusal", "loop mode is invalid"))?;
        // A pending wrong enforced answer can impose audit before its mode history is repaired.
        if mode.domain()
            > execute_command::policy::effective_mode(
                class_mode.domain(),
                loop_mode.domain(),
                floor.domain(),
                false,
            )
        {
            return Err(refusal(
                "requests-record-refusal",
                "setting snapshot differs",
            ));
        }
        if !exact(&value["would_do"], &["decision", "reason"])
            || !matches!(
                value["would_do"]["decision"].as_str(),
                Some("allow" | "refuse" | "undecided" | "refer")
            )
            || !word(&value["would_do"]["reason"], 1024)
        {
            return Err(refusal(
                "requests-record-refusal",
                "would-do or reason differs",
            ));
        }
        let effect_pending = value["effect"]["state"] == "pending";
        let ref_check = &value["effect"]["ref_check"];
        let mut effect_keys = vec![
            "state",
            "reason",
            "exit_status",
            "ref_check",
            "stdin_bytes",
            "stdout_bytes",
            "stderr_bytes",
            "queue_wall_seconds",
            "mediation_wall_seconds",
            "compute_wall_seconds",
        ];
        let preflight = value["state"] == "preflight-refused";
        if preflight {
            effect_keys.push("preflight");
            let detail = &value["effect"]["preflight"];
            let check = detail["check"].as_str().unwrap_or_default();
            // Envelope and changed-ref checks can precede argument decoding.
            // Later checks retain exact byte arrays, including rejected bytes.
            let wire_words = detail["words"].as_array().is_some_and(|words| {
                words.len() <= 128
                    && words.iter().all(|word| {
                        word.as_array().is_some_and(|bytes| {
                            bytes.len() <= 4096
                                && bytes
                                    .iter()
                                    .all(|byte| byte.as_u64().is_some_and(|byte| byte <= 255))
                        })
                    })
            });
            if !exact(detail, &["check", "words"])
                || (!wire_words
                    && !matches!(check, "door-request-refusal" | "door-changed-ref-refusal"))
                || !matches!(
                    check,
                    "door-changed-ref-refusal"
                        | "door-request-refusal"
                        | "door-review-compute-refusal"
                        | "door-transport-pending"
                        | "door-caller-authority-refusal"
                        | "door-compute-unregistered"
                        | "door-compute-root-refusal"
                        | "door-requests-unregistered"
                        | "door-compute-words-refusal"
                        | "door-compute-wrapper-refusal"
                        | "door-compute-command-refusal"
                        | "door-compute-locked-refusal"
                )
                || detail["words"].to_string().len() > 65_536
                || value["class"] != "preflight"
                || value["operation"] != "preflight"
                || value["shape_key"] != format!("preflight:{check}")
                || value["effect"]["state"] != "refused"
                || value["effect"]["reason"] != check
                || value["effect"]["exit_status"] != 125
                || value["effect"]["ref_check"] != "not-reached"
                || !value["effect"]["queue_wall_seconds"].is_null()
                || value["effect"]["compute_wall_seconds"] != 0.0
                || ["stdin_bytes", "stdout_bytes"]
                    .iter()
                    .any(|key| value["effect"][key] != 0)
                || (check != "door-compute-root-refusal" && value["effect"]["stderr_bytes"] != 0)
                || value["would_do"] != json!({"decision":"refuse","reason":check})
                || value["would_do_source"] != "fast-lane"
                || !value["matched_rule"].is_null()
                || ["review", "label", "mark_reason"]
                    .iter()
                    .any(|key| !value[key].is_null())
            {
                return Err(refusal(
                    "requests-record-refusal",
                    "preflight refusal differs",
                ));
            }
        } else if value["operation"] == "preflight" || value["class"] == "preflight" {
            return Err(refusal(
                "requests-record-refusal",
                "preflight state is absent",
            ));
        }
        if value["effect"].get("bound").is_some() != value["effect"].get("output_bytes").is_some() {
            return Err(refusal(
                "requests-record-refusal",
                "effect.bound and effect.output_bytes must be present together",
            ));
        }
        for key in ["bound", "output_bytes"] {
            if let Some(value) = value["effect"].get(key) {
                effect_keys.push(key);
                if value.as_u64().is_none_or(|bytes| {
                    key == "bound" && !(1..=MAX_UPLOAD_OUTPUT_LIMIT).contains(&bytes)
                }) {
                    return Err(refusal(
                        "requests-record-refusal",
                        "output bound or count differs",
                    ));
                }
            }
        }
        if let Some(packet) = value["effect"].get("ref_packet") {
            effect_keys.push("ref_packet");
            if value["operation"] != "git-receive"
                || ref_check != "refused"
                || !exact(packet, &["word_count", "first_word"])
                || packet["word_count"]
                    .as_u64()
                    .is_none_or(|count| count > 65_536)
                || packet["first_word"].as_str().is_none_or(|word| {
                    word.len() > 64 || !word.bytes().all(|byte| byte.is_ascii_graphic())
                })
            {
                return Err(refusal(
                    "requests-record-refusal",
                    "ref packet evidence differs",
                ));
            }
        }
        if value["operation"] == "compute" {
            effect_keys.push("compute");
            if value["class"] != "compute"
                || !crate::door::compute::valid_detail(&value["effect"]["compute"])
            {
                return Err(refusal(
                    "requests-record-refusal",
                    "compute effect shape differs",
                ));
            }
            let detail = &value["effect"]["compute"];
            let words: Vec<_> = detail["words"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            if value["shape_key"] != crate::door::compute::shape(&words)
                || (!detail["checkout_ref"].is_null()
                    && detail["checkout_ref"] != value["mirror_ref"])
                || (value["effect"]["state"] == "completed"
                    && [
                        "checkout_path",
                        "checkout_commit",
                        "checkout_ref",
                        "wrapper_exit_status",
                        "wrapper_wall_seconds",
                        "preparation_wall_seconds",
                        "tree_clean",
                        "tree_change_count",
                        "discarded",
                    ]
                    .iter()
                    .any(|key| detail[*key].is_null()))
            {
                return Err(refusal(
                    "requests-record-refusal",
                    "compute attribution differs",
                ));
            }
        }
        if !exact(&value["effect"], &effect_keys)
            || !matches!(
                value["effect"]["state"].as_str(),
                Some("pending" | "completed" | "refused")
            )
            || !(value["effect"]["reason"].is_null() || word(&value["effect"]["reason"], 128))
            || (effect_pending != ref_check.is_null())
            || (!effect_pending
                && !matches!(
                    ref_check.as_str(),
                    Some(
                        "admitted"
                            | "refused"
                            | "not-reached"
                            | "not-applicable"
                            | "unrecorded"
                            | "no-ref"
                    )
                ))
            || (value["effect"]["state"] == "pending" && !value["effect"]["reason"].is_null())
            || !(value["effect"]["exit_status"].is_null()
                || value["effect"]["exit_status"].as_i64().is_some())
            || ["stdin_bytes", "stdout_bytes", "stderr_bytes"]
                .iter()
                .any(|key| value["effect"][key].as_u64().is_none())
            || !(value["effect"]["queue_wall_seconds"].is_null()
                || value["effect"]["queue_wall_seconds"]
                    .as_f64()
                    .is_some_and(|wall| wall >= 0.0))
            || ["mediation_wall_seconds", "compute_wall_seconds"]
                .iter()
                .any(|key| value["effect"][key].as_f64().is_none_or(|wall| wall < 0.0))
        {
            return Err(refusal("requests-record-refusal", "effect shape differs"));
        }
        let state = value["state"].as_str();
        if !(value["state"].is_null() || state.is_some())
            || !matches!(
                state,
                None | Some(
                    "waiting" | "observed" | "marked" | "adjudicated" | "preflight-refused"
                )
            )
            || !(value["mark_reason"].is_null() || word(&value["mark_reason"], 1024))
            || !(value["review"].is_null()
                || (exact(&value["review"], &["id", "at"])
                    && word(&value["review"]["id"], 160)
                    && word(&value["review"]["at"], 64)))
            || !(value["label"].is_null() || label_valid(&value["label"], &value))
            || !(execute_command::record::ReviewState {
                state,
                effect: if effect_pending {
                    execute_command::record::EffectPublication::Pending
                } else {
                    execute_command::record::EffectPublication::Recorded
                },
                review: !value["review"].is_null(),
                label: !value["label"].is_null(),
                mark: !value["mark_reason"].is_null(),
            })
            .valid()
        {
            return Err(refusal("requests-record-refusal", "request state differs"));
        }
        Ok(Self(value))
    }

    /// Exact request ID.
    #[must_use]
    pub fn id(&self) -> &str {
        self.0["id"].as_str().unwrap_or_default()
    }
    /// Exact run.
    #[must_use]
    pub fn run(&self) -> &str {
        self.0["run"].as_str().unwrap_or_default()
    }
    /// Exact serialized request.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }
    /// Consume a validated request for publication.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }

    /// Record one compute or no-effect outcome while preserving the request's label.
    ///
    /// # Errors
    ///
    /// Refuses a second outcome or an invalid effect document.
    pub fn record_effect(&mut self, mut effect: Value) -> Result<(), LaneError> {
        if self.0["effect"]["state"] != "pending" {
            return Err(refusal(
                "requests-state-refusal",
                "effect is already recorded",
            ));
        }
        let mut changed = self.0.clone();
        if self.0["operation"] == "compute" && effect.get("compute").is_none() {
            effect["compute"] = self.0["effect"]["compute"].clone();
        }
        if self.0["operation"] == "compute"
            && effect["compute"]["words"] != self.0["effect"]["compute"]["words"]
        {
            return Err(refusal("requests-record-refusal", "compute words changed"));
        }
        changed["effect"] = effect;
        let checked = Self::decode(changed)?;
        if checked.0["effect"]["state"] == "pending" {
            return Err(refusal("requests-state-refusal", "effect is still pending"));
        }
        *self = checked;
        Ok(())
    }

    /// Publish a recorded immediate effect for later judgement.
    ///
    /// # Errors
    ///
    /// Refuses a request without an effect or one already filed for judgement.
    pub fn publish_waiting(&mut self) -> Result<(), LaneError> {
        if !self.0["state"].is_null() || self.0["effect"]["state"] == "pending" {
            return Err(refusal(
                "requests-state-refusal",
                "intent is not ready for judgement",
            ));
        }
        self.0["state"] = json!("waiting");
        Ok(())
    }

    /// Publish a decided enforced outcome for optional later review without a waiting request.
    ///
    /// # Errors
    ///
    /// Refuses an unfinished or already published outcome.
    pub fn publish_observed(&mut self) -> Result<(), LaneError> {
        if self.0["state"] != Value::Null
            || self.0["effect"]["state"] == "pending"
            || self.0["mode"] != "enforce"
            || self.0["would_do"]["decision"] == "undecided"
        {
            return Err(refusal(
                "requests-state-refusal",
                "enforced outcome is not ready",
            ));
        }
        self.0["state"] = json!("observed");
        Ok(())
    }

    /// Mark an observed enforced outcome for guarded feedback.
    ///
    /// # Errors
    ///
    /// Refuses a request that is not observed.
    pub fn mark_observed(&mut self) -> Result<(), LaneError> {
        if self.0["state"] != "observed" {
            return Err(refusal("requests-state-refusal", "request is not observed"));
        }
        self.0["state"] = json!("marked");
        self.0["mark_reason"] = json!("enforced outcome review");
        Ok(())
    }

    /// Mark a waiting request for a guarded review.
    ///
    /// # Errors
    ///
    /// Refuses a request that is not waiting.
    pub fn mark(&mut self, reason: &str) -> Result<(), LaneError> {
        if self.0["state"] != "waiting" {
            return Err(refusal("requests-state-refusal", "request is not waiting"));
        }
        if reason.is_empty() || reason.len() > 1024 {
            return Err(refusal("requests-record-refusal", "mark reason is invalid"));
        }
        self.0["state"] = json!("marked");
        self.0["mark_reason"] = json!(reason);
        Ok(())
    }

    /// Save only the latest review identifier and time, retaining marked state.
    ///
    /// # Errors
    ///
    /// Refuses a request that was not marked.
    pub fn review(&mut self, review_id: &str, at: &str) -> Result<(), LaneError> {
        if self.0["state"] != "marked" {
            return Err(refusal("requests-state-refusal", "request is not marked"));
        }
        if review_id.is_empty() || review_id.len() > 160 || at.is_empty() || at.len() > 64 {
            return Err(refusal(
                "requests-record-refusal",
                "review bookkeeping is invalid",
            ));
        }
        self.0["review"] = json!({"id":review_id,"at":at});
        Ok(())
    }

    /// Attach one direct triage label to a waiting request.
    ///
    /// # Errors
    ///
    /// Refuses a request that is not waiting or a malformed treatment.
    pub fn triage(
        &mut self,
        treatment: &str,
        reason: &str,
        adjudicator: &str,
        at: &str,
    ) -> Result<(), LaneError> {
        if self.0["state"] != "waiting" {
            return Err(refusal("requests-state-refusal", "request is not waiting"));
        }
        self.attach_label(treatment, reason, adjudicator, at, None)
    }

    /// Attach a label only to the latest marked review.
    ///
    /// # Errors
    ///
    /// Refuses an unmarked request, stale review ID, or malformed treatment.
    pub fn adjudicate(
        &mut self,
        review_id: &str,
        treatment: &str,
        reason: &str,
        adjudicator: &str,
        at: &str,
    ) -> Result<(), LaneError> {
        execute_command::record::current_review(
            self.0["state"] == "marked",
            self.0["review"]["id"].as_str(),
            review_id,
        )
        .map_err(|error| {
            refusal(
                error.0,
                if error.0 == "requests-state-refusal" {
                    "request is not marked"
                } else {
                    "review identifier is not current"
                },
            )
        })?;
        self.attach_label(treatment, reason, adjudicator, at, Some(review_id))
    }

    fn attach_label(
        &mut self,
        treatment: &str,
        reason: &str,
        adjudicator: &str,
        at: &str,
        review_id: Option<&str>,
    ) -> Result<(), LaneError> {
        if !matches!(treatment, "allow" | "refuse")
            || reason.is_empty()
            || reason.len() > 1024
            || adjudicator.is_empty()
            || adjudicator.len() > 128
            || at.is_empty()
            || at.len() > 64
        {
            return Err(refusal(
                "requests-record-refusal",
                "adjudicated label is invalid",
            ));
        }
        let id = self.0["id"].clone();
        let shape = self.0["shape_key"].clone();
        let would_do = self.0["would_do"].clone();
        self.0["label"] = json!({"treatment":treatment,"reason":reason,"adjudicator":adjudicator,
            "at":at,"request_id":id,"shape_key":shape,
            "would_do":would_do,"review_id":review_id});
        self.0["state"] = json!("adjudicated");
        self.0["decision_tier"] = json!("superloop");
        Ok(())
    }
}

fn label_valid(label: &Value, record: &Value) -> bool {
    exact(
        label,
        &[
            "treatment",
            "reason",
            "adjudicator",
            "at",
            "request_id",
            "shape_key",
            "would_do",
            "review_id",
        ],
    ) && matches!(label["treatment"].as_str(), Some("allow" | "refuse"))
        && word(&label["reason"], 1024)
        && word(&label["adjudicator"], 128)
        && word(&label["at"], 64)
        && label["request_id"] == record["id"]
        && label["shape_key"] == record["shape_key"]
        && label["would_do"] == record["would_do"]
        && (label["review_id"].is_null() || word(&label["review_id"], 160))
        && (record["review"].is_null() && label["review_id"].is_null()
            || !record["review"].is_null() && label["review_id"] == record["review"]["id"])
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{Value, json};

    use super::{Mode, ModeSetting, RequestRecord};

    /// ´test:unit:request-output-evidence-is-optional-and-strict´
    #[test]
    fn request_output_evidence_is_optional_and_strict() {
        let mut original = waiting("R", "1a", 3000, Mode::Audit).into_value();
        for key in ["bound", "output_bytes"] {
            original["effect"]
                .as_object_mut()
                .expect("effect")
                .remove(key);
        }
        assert!(RequestRecord::decode(original.clone()).is_ok());
        for (key, good, bad) in [
            (
                "bound",
                json!(16_777_216),
                vec![
                    json!(0),
                    json!(-1),
                    json!(1_073_741_825_u64),
                    json!(1.5),
                    json!("16"),
                    Value::Null,
                ],
            ),
            (
                "output_bytes",
                json!(16_785_408),
                vec![json!(-1), json!(1.5), json!("16"), Value::Null],
            ),
        ] {
            let mut record = original.clone();
            record["effect"][key] = good;
            let unpaired =
                RequestRecord::decode(record.clone()).expect_err("unpaired output evidence");
            assert_eq!(unpaired.kind, "requests-record-refusal");
            assert!(unpaired.detail.contains("must be present together"));
            record["effect"][if key == "bound" {
                "output_bytes"
            } else {
                "bound"
            }] = json!(16_777_216);
            assert!(RequestRecord::decode(record.clone()).is_ok());
            for value in bad {
                record["effect"][key] = value;
                assert!(RequestRecord::decode(record.clone()).is_err());
            }
        }
    }

    /// ´test:unit:request-ref-packet-evidence-is-optional-and-strict´
    #[test]
    fn request_ref_packet_evidence_is_optional_and_strict() {
        let mut record = waiting("R", "1a", 3000, Mode::Audit).into_value();
        record["operation"] = json!("git-receive");
        record["effect"]["state"] = json!("refused");
        record["effect"]["reason"] = json!("door-changed-ref-refusal");
        record["effect"]["ref_check"] = json!("refused");
        assert!(RequestRecord::decode(record.clone()).is_ok());
        record["effect"]["ref_packet"] = json!({"word_count":2,"first_word":"shallow"});
        assert!(RequestRecord::decode(record.clone()).is_ok());
        for invalid in [
            Value::Null,
            json!({}),
            json!({"word_count":65_537,"first_word":"shallow"}),
            json!({"word_count":-1,"first_word":"shallow"}),
            json!({"word_count":2.5,"first_word":"shallow"}),
            json!({"word_count":2,"first_word":"x".repeat(65)}),
            json!({"word_count":2,"first_word":"bad\nword"}),
            json!({"word_count":2,"first_word":"shallow","pack":"secret"}),
        ] {
            record["effect"]["ref_packet"] = invalid;
            assert!(RequestRecord::decode(record.clone()).is_err());
        }
    }

    pub fn waiting(run: &str, nonce: &str, worker_uid: u32, floor: Mode) -> RequestRecord {
        let first = ModeSetting::first(Mode::Audit, floor, "owner", "first setting from row", "1")
            .expect("first setting");
        let mut value = json!({
            "schema":3,"id":format!("{run}:{nonce}"),"loop":"alpha","run":run,
            "worker_uid":worker_uid,"class":"git","shape_key":"git:upload",
            "operation":"git-upload","mirror_ref":"refs/heads/lane/alpha",
            "mode":"audit","floor":floor.as_str(),"class_setting":first.value(),
            "loop_setting":first.value(),"would_do":{"decision":"allow","reason":"read-only fetch"},
            "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,"stdin_bytes":0,"bound":16_777_216,"output_bytes":0,
                "stdout_bytes":0,"stderr_bytes":0,"queue_wall_seconds":null,
                "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
            "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1"
        });
        super::judgement::initialize(&mut value);
        RequestRecord::decode(value).expect("waiting request")
    }

    /// ´test:unit:first-setting-evidence-and-below-floor-refusal´
    #[test]
    fn first_setting_evidence_and_below_floor_refusal() {
        let setting = ModeSetting::first(Mode::Audit, Mode::Audit, "owner", "row evidence", "1")
            .expect("first");
        assert_eq!(setting.value()["setter"], "owner");
        assert_eq!(setting.value()["evidence"], "row evidence");
        assert_eq!(setting.value()["floor"], "audit");
        for mode in [Mode::Enforce, Mode::Allow] {
            assert_eq!(
                ModeSetting::first(mode, Mode::Audit, "owner", "row", "1")
                    .expect_err("below floor")
                    .kind,
                "door-mode-floor-refusal"
            );
        }
        assert!(ModeSetting::first(Mode::Enforce, Mode::Allow, "owner", "row", "1").is_ok());
    }

    /// ´test:unit:request-states-and-bound-labels´
    #[test]
    fn request_states_and_bound_labels() {
        let mut request = waiting("R", "1a", 3000, Mode::Audit);
        assert_eq!(
            request.review("old", "2").expect_err("not marked").kind,
            "requests-state-refusal"
        );
        request.mark("needs review").expect("mark");
        request.review("old", "2").expect("first review");
        request.review("new", "3").expect("second review");
        assert_eq!(
            request
                .adjudicate("old", "allow", "okay", "owner", "4")
                .expect_err("stale")
                .kind,
            "requests-review-id-refusal"
        );
        request
            .adjudicate("new", "allow", "okay", "owner", "4")
            .expect("adjudicate");
        assert_eq!(request.value()["label"]["request_id"], "R:1a");
        assert_eq!(request.value()["label"]["review_id"], "new");
        assert_eq!(
            request.value()["label"]["would_do"]["reason"],
            "read-only fetch"
        );
        assert_eq!(
            request.mark("again").expect_err("finished").kind,
            "requests-state-refusal"
        );
    }

    /// ´test:unit:malformed-records-refuse-each-shape´
    #[test]
    fn malformed_records_refuse_each_shape() {
        let original = waiting("R", "1a", 3000, Mode::Audit).into_value();
        let mut malformed_observed = original.clone();
        malformed_observed["state"] = json!("observed");
        assert_eq!(
            RequestRecord::decode(malformed_observed)
                .expect_err("observed effect is pending")
                .kind,
            "requests-record-refusal"
        );
        let mut wrong_observed = waiting("R", "2b", 3001, Mode::Audit);
        assert_eq!(
            wrong_observed
                .publish_observed()
                .expect_err("enforced outcome is not ready")
                .kind,
            "requests-state-refusal"
        );
        assert_eq!(
            wrong_observed
                .mark_observed()
                .expect_err("request is not observed")
                .kind,
            "requests-state-refusal"
        );
        for (field, changed) in [
            ("schema", json!(1)),
            ("worker_uid", json!("3000")),
            ("would_do", json!({"decision":"allow"})),
            ("effect", json!({"state":"pending"})),
            ("state", json!(7)),
        ] {
            let mut value: Value = original.clone();
            value[field] = changed;
            assert_eq!(
                RequestRecord::decode(value).expect_err("shape").kind,
                "requests-record-refusal",
                "{field}"
            );
        }
        let mut old = original;
        old.as_object_mut().expect("object").remove("floor");
        assert_eq!(
            RequestRecord::decode(old).expect_err("old shape").kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:old-request-effect-shape-refuses-by-name´
    #[test]
    fn old_request_effect_shape_refuses_by_name() {
        let mut old = waiting("R", "1a", 3000, Mode::Audit).into_value();
        old["schema"] = json!(2);
        old["effect"]
            .as_object_mut()
            .expect("effect")
            .remove("ref_check");
        let refusal = RequestRecord::decode(old.clone()).expect_err("old schema");
        assert_eq!(refusal.kind, "requests-record-refusal");
        assert_eq!(refusal.detail, "schema must equal 4");
        old["schema"] = json!(4);
        let refusal = RequestRecord::decode(old.clone()).expect_err("missing ref check");
        assert_eq!(refusal.kind, "requests-record-refusal");
        assert_eq!(refusal.detail, "effect shape differs");
        old["effect"]["ref_check"] = json!("unknown");
        let refusal = RequestRecord::decode(old).expect_err("unknown ref check");
        assert_eq!(refusal.kind, "requests-record-refusal");
        assert_eq!(refusal.detail, "effect shape differs");
    }
}
