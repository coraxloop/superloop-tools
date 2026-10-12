//! Common requests transported through the private helper. This module owns
//! door source validation, projections, mode correction and service evidence.

use super::super::channel_client as client;

use execute_command::record::{CompletionDisposition, completion_disposition};
use request_core::{Collection, Decision, Kind, Request, State};
use serde_json::{Value, json};

use super::{LaneError, RequestRecord, Store, problem, read_leaf, replace_leaf};
use client::Client;

#[cfg(test)]
pub(super) fn with_test_client<T>(
    helper: &std::path::Path,
    registry: &std::path::Path,
    call: impl FnOnce() -> T,
) -> T {
    client::with_test_client(helper, registry, call)
}

const BINDING: &str = "requests-channel.json";

fn core(error: impl std::fmt::Display) -> LaneError {
    problem("requests-channel-refusal", error.to_string())
}

fn door_body(body: &Value) -> bool {
    body.as_object().is_some_and(|object| object.len() == 2)
        && body["source_id"] == body["record"]["id"]
        && RequestRecord::decode(body["record"].clone()).is_ok()
}

fn door_answer(_: &Value, answer: &Value) -> bool {
    answer.as_object().is_some_and(|object| object.len() == 1)
        && matches!(answer["outcome"].as_str(), Some("allow" | "refuse"))
}

fn object(value: &Value) -> bool {
    value.is_object()
}
fn permission_answer(_: &Value, answer: &Value) -> bool {
    answer.is_object()
}

fn kinds() -> [Kind<'static>; 4] {
    [
        request_core::gateway::kind(),
        Kind {
            name: "door-before-effect",
            service: true,
            body: door_body,
            answer: door_answer,
        },
        Kind {
            name: "door-after-effect",
            service: false,
            body: door_body,
            answer: door_answer,
        },
        Kind {
            name: "permission-case",
            service: false,
            body: object,
            answer: permission_answer,
        },
    ]
}

fn decode(value: Value) -> Result<Collection, LaneError> {
    let collection: Collection = serde_json::from_value(value).map_err(core)?;
    collection.validate(&kinds()).map_err(core)?;
    Ok(collection)
}

fn common_id(loop_name: &str, source: &str) -> String {
    request_core::request_id(format!("door\0{loop_name}\0{source}").as_bytes())
}

fn source(row: &Request) -> Result<RequestRecord, LaneError> {
    RequestRecord::decode(row.body["record"].clone())
}

fn check_source(record: &RequestRecord, saved: &RequestRecord) -> Result<(), LaneError> {
    for field in [
        "id",
        "loop",
        "run",
        "worker_uid",
        "class",
        "operation",
        "shape_key",
        "filed_at",
    ] {
        if record.value()[field] != saved.value()[field] {
            return Err(problem("requests-source-conflict", record.id()));
        }
    }
    Ok(())
}

fn project(record: &RequestRecord, row: &Request, at: &str) -> Result<RequestRecord, LaneError> {
    check_source(record, &source(row)?)?;
    if !record.value()["label"].is_null() && row.decision.is_none() {
        return Err(problem("requests-source-conflict", record.id()));
    }
    let mut value = record.value().clone();
    if matches!(row.state, State::Marked) {
        value["state"] = json!("marked");
        value["mark_reason"] = json!("common request review");
        value["review"] = row.review.as_ref().map_or(
            Value::Null,
            |review| json!({"id":review.review_id,"at":review.at}),
        );
    } else if let Some(decision) = &row.decision {
        if decision.reason.len() > 1024 {
            return Err(problem("requests-answer", &row.id));
        }
        let prior = &row.body["record"]["label"];
        let label_at = prior["at"].as_str().unwrap_or(at);
        let review_id = if row.decision_state == Some(State::Adjudicated) {
            row.review.as_ref().map(|review| review.review_id.as_str())
        } else {
            None
        };
        value["label"] = json!({"treatment":decision.answer["outcome"],"reason":decision.reason,"adjudicator":"requests-helper","at":label_at,"request_id":record.id(),"shape_key":value["shape_key"],"would_do":value["would_do"],"review_id":review_id});
        value["state"] = json!("adjudicated");
        value["decision_tier"] = json!("superloop");
        if row.decision_state == Some(State::Adjudicated) {
            value["review"] = row.review.as_ref().map_or(
                Value::Null,
                |review| json!({"id":review.review_id,"at":review.at}),
            );
        }
    }
    // The common commit may be newer than the compatibility custody projection.
    // Only the door owner can supply this validated effect evidence.
    if row.body["record"]["effect"]["state"] != "pending" {
        value["effect"] = row.body["record"]["effect"].clone();
    }
    RequestRecord::decode(value)
}

fn imported(record: &RequestRecord, loop_name: &str) -> Result<Request, LaneError> {
    let value = record.value();
    let after = value["mode"] == "allow" || value["state"] == "observed";
    let mut row = Request::filed(
        common_id(loop_name, record.id()),
        if after {
            "door-after-effect"
        } else {
            "door-before-effect"
        }
        .to_owned(),
        json!({"source_id":record.id(),"record":value}),
        value["worker_uid"].to_string(),
        record.run().to_owned(),
        value["filed_at"]
            .as_str()
            .and_then(|time| time.parse().ok())
            .ok_or_else(|| core("door filing time invalid"))?,
    );
    row.waiter_gone = !after
        && matches!(
            value["effect"]["reason"].as_str(),
            Some("door-disconnect-refusal" | "door-request-deadline")
        );
    if value["state"] == "marked" {
        row.state = State::Marked;
    }
    if value["state"] == "adjudicated" {
        row.decision = Some(Decision {
            answer: json!({"outcome":value["label"]["treatment"]}),
            reason: value["label"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        });
        row.decision_state = Some(State::TriageDecided);
        row.state = if after {
            State::TriageDecided
        } else {
            State::ServicePending
        };
        if !after && value["effect"]["state"] != "pending" {
            row.service_claim = Some(format!("legacy:{}", record.id()));
            row.service_result = Some(value["effect"].clone());
            row.state = State::Completed;
        }
    }
    Ok(row)
}

fn envelope(
    doors: &[Request],
    document: Option<&Value>,
    id: Option<&str>,
    pending: bool,
    now: u64,
) -> Value {
    json!({"schema":1,"records":doors,"document":document,"id":id,"pending":pending,"now_ns":now,"expected":null,"publication":null})
}

impl Store {
    pub(super) fn channel_bound(&self) -> Result<bool, LaneError> {
        Ok(self.bound_client()?.is_some())
    }

    /// Translate a compatibility door identity to the common identifier.
    #[must_use]
    pub fn collection_id(&self, id: &str) -> String {
        if id.len() == 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            id.to_owned()
        } else {
            common_id(&self.loop_name, id)
        }
    }

    /// Translate a compatibility triage batch without bypassing the private helper.
    ///
    /// # Errors
    /// Refuses malformed, repeated, cross-run or invalid common transitions.
    pub fn collection_legacy_triage(
        &self,
        run: &str,
        decisions: &[Value],
    ) -> Result<usize, LaneError> {
        let mut items = Vec::new();
        for item in decisions {
            let id = item["id"]
                .as_str()
                .filter(|id| id.split_once(':').is_some_and(|(prefix, _)| prefix == run))
                .ok_or_else(|| core("legacy triage source id differs"))?;
            let size = item.as_object().map_or(0, serde_json::Map::len);
            let reason = item["reason"]
                .as_str()
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| core("legacy triage reason absent"))?;
            items.push(match (item["action"].as_str(), size) {
                (Some("mark"), 3) => json!({"id":self.collection_id(id),"mark_for_review":true}),
                (Some("adjudicate"), 4) => json!({"id":self.collection_id(id),"decision":{"answer":{"outcome":item["treatment"]},"reason":reason}}),
                _ => return Err(core("legacy triage item fields differ")),
            });
        }
        self.collection_command(
            "triage",
            Some(&json!({"schema":1,"items":items})),
            None,
            false,
        )?["applied"]
            .as_u64()
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| core("triage count absent"))
    }

    pub(super) fn collection_legacy_review(&self, id: &str) -> Result<RequestRecord, LaneError> {
        let result =
            self.collection_command("review", None, Some(&self.collection_id(id)), false)?;
        RequestRecord::decode(result["body"]["record"].clone())
    }

    pub(super) fn collection_legacy_adjudicate(
        &self,
        id: &str,
        review: &str,
        outcome: &str,
        reason: &str,
    ) -> Result<RequestRecord, LaneError> {
        let document = json!({"schema":1,"id":self.collection_id(id),"review_id":review,"decision":{"answer":{"outcome":outcome},"reason":reason}});
        let result = self.collection_command("adjudicate", Some(&document), None, false)?;
        RequestRecord::decode(result["body"]["record"].clone())
    }

    fn bound_client(&self) -> Result<Option<Client>, LaneError> {
        read_leaf(self.state_dir(), BINDING, self.owner, 4096)?
            .map(|bytes| {
                let value: Value = serde_json::from_slice(&bytes).map_err(core)?;
                Client::decode(&value, &self.loop_name)
            })
            .transpose()
    }

    pub(super) fn channel_read(&self) -> Result<Option<Collection>, LaneError> {
        self.bound_client()?
            .map(|client| decode(client.call("--owner-read", "", &self.loop_name, None)?))
            .transpose()
    }

    pub(super) fn channel_project(
        &self,
        rows: &mut [RequestRecord],
        collection: Option<&Collection>,
    ) -> Result<(), LaneError> {
        let Some(collection) = collection else {
            return Ok(());
        };
        for record in rows {
            if let Some(row) = collection
                .requests
                .iter()
                .find(|row| row.id == common_id(&self.loop_name, record.id()))
            {
                *record = project(record, row, "unrecorded")?;
            }
        }
        Ok(())
    }

    fn channel_doors(&self, collection: &Collection) -> Result<Vec<Request>, LaneError> {
        let mut doors = Vec::new();
        for (_, _, records) in self.all_runs(None)? {
            for record in records {
                if !matches!(
                    record.value()["state"].as_str(),
                    Some("waiting" | "observed" | "marked" | "adjudicated")
                ) {
                    continue;
                }
                let id = common_id(&self.loop_name, record.id());
                let row = if let Some(saved) = collection.requests.iter().find(|row| row.id == id) {
                    check_source(&record, &source(saved)?)?;
                    let mut row = saved.clone();
                    row.body["record"] = record.into_value();
                    row
                } else {
                    imported(&record, &self.loop_name)?
                };
                doors.push(row);
            }
        }
        Ok(doors)
    }

    /// Execute one common collection command through the configured private helper.
    ///
    /// # Errors
    /// Refuses invalid custody, inputs, helper replies, mode preflight or a changed
    /// preimage. A published batch's subsequent maintenance failure is reported
    /// separately and never represented as an uncommitted request batch.
    pub fn collection_command(
        &self,
        action: &str,
        document: Option<&Value>,
        id: Option<&str>,
        pending: bool,
    ) -> Result<Value, LaneError> {
        let changing = !matches!(action, "status" | "list");
        let guard = if changing {
            Some(self.lock(true)?)
        } else {
            if read_leaf(self.state_dir(), super::LOCK_FILE, self.owner, 4096)?.is_none() {
                self.list_with_status()?;
            }
            if read_leaf(self.state_dir(), super::LOCK_FILE, self.owner, 4096)?.is_none() {
                None
            } else {
                Some(self.lock(false)?)
            }
        };
        let client = self.bound_client()?.map_or_else(Client::configured, Ok)?;
        let collection = decode(client.call("--owner-read", "", &self.loop_name, None)?)?;
        let doors = if guard.is_some() {
            self.channel_doors(&collection)?
        } else {
            Vec::new()
        };
        let now = request_core::now_ns().map_err(core)?;
        let mut input = envelope(&doors, document, id, pending, now);
        let preview = client.call("--owner-preview", action, &self.loop_name, Some(&input))?;
        let before = decode(preview["before"].clone())?;
        let mut next = decode(preview["collection"].clone())?;
        if !changing {
            return Ok(preview["result"].clone());
        }
        let at = request_core::utc_time(now);
        let mut changed = Vec::new();
        for row in &mut next.requests {
            if row.kind.starts_with("door-") {
                let old = before
                    .requests
                    .iter()
                    .find(|old| old.id == row.id)
                    .ok_or_else(|| core("preview source disappeared"))?;
                if old != row {
                    let record = project(&source(old)?, row, &at)?;
                    row.body["record"] = record.value().clone();
                    if old.decision != row.decision {
                        changed.push(record);
                    }
                }
            }
        }
        next.validate(&kinds()).map_err(core)?;
        self.preflight_correction_modes(&changed)?;
        let prior_index = if changed.is_empty() {
            Value::Null
        } else {
            self.read_learned()?
        };
        if !changed.is_empty() {
            self.write_learned(
                &json!({"unavailable":true,"reason":"common request publication pending"}),
            )?;
        }
        // Bind before publication, so a restarted service can never miss a
        // committed label merely because the process died after the helper.
        if self.bound_client()?.is_none() {
            replace_leaf(
                self.state_dir(),
                BINDING,
                &serde_json::to_vec(&client.value(&self.loop_name)).map_err(core)?,
                self.owner,
                4096,
            )?;
        }
        input["expected"] = serde_json::to_value(&before).map_err(core)?;
        input["publication"] = serde_json::to_value(&next).map_err(core)?;
        let committed = client.call("--owner-commit", action, &self.loop_name, Some(&input))?;
        if decode(committed["collection"].clone())? != next {
            return Err(core(
                "committed helper reply differs; inspect durable state before retry",
            ));
        }
        self.channel_mirror_report(&next);
        if !changed.is_empty() {
            self.channel_maintenance(&changed, prior_index, &before);
        }
        self.channel_complete_departed(&client, &next);
        if matches!(action, "review" | "adjudicate") {
            let id = committed["result"]["id"]
                .as_str()
                .ok_or_else(|| core("committed result id absent"))?;
            return serde_json::to_value(
                next.requests
                    .iter()
                    .find(|row| row.id == id)
                    .ok_or_else(|| core("committed result absent"))?,
            )
            .map_err(core);
        }
        Ok(committed["result"].clone())
    }

    fn channel_complete_departed(&self, client: &Client, collection: &Collection) {
        for row in &collection.requests {
            if row.waiter_gone
                && row.state == State::ServicePending
                && let Err(error) = self.channel_service_locked(
                    client,
                    "claim",
                    &json!({"schema":1,"id":row.id,"claim":format!("departed:{}", row.id)}),
                    None,
                )
            {
                use std::io::Write as _;
                let _reported = writeln!(
                    std::io::stderr().lock(),
                    "requests committed; departed waiter completion: {}",
                    error.line()
                );
            }
        }
    }

    fn channel_maintenance(
        &self,
        changed: &[RequestRecord],
        mut index: Value,
        before: &Collection,
    ) {
        use std::io::Write as _;
        for record in changed {
            let prior = before
                .requests
                .iter()
                .find(|row| row.id == common_id(&self.loop_name, record.id()));
            Self::index_judgement(
                &mut index,
                record.value(),
                prior.map(|row| &row.body["record"]),
            );
        }
        if let Err(error) = self.write_learned(&index) {
            let _reported = writeln!(
                std::io::stderr().lock(),
                "requests committed; learned index: {}",
                error.line()
            );
        }
        let reports = self.apply_corrections_locked(changed, &super::now_nanos().to_string());
        for report in reports {
            let _reported = writeln!(
                std::io::stderr().lock(),
                "requests committed; mode correction: {report}"
            );
        }
    }

    fn channel_mirror_report(&self, collection: &Collection) {
        use std::io::Write as _;
        if let Err(error) = self.channel_mirror(collection) {
            let _reported = writeln!(
                std::io::stderr().lock(),
                "requests committed; custody projection: {}",
                error.line()
            );
        }
    }

    fn channel_mirror(&self, collection: &Collection) -> Result<(), LaneError> {
        let runs = collection
            .requests
            .iter()
            .filter(|row| row.kind.starts_with("door-"))
            .map(|row| row.run.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for run in runs {
            // Retired custody is immutable; its common record remains available.
            match nix::sys::stat::fstatat(
                &self.runs,
                format!(".launch-{run}").as_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Err(nix::errno::Errno::ENOENT) => continue,
                Err(error) => return Err(core(error)),
                Ok(_) => {}
            }
            let custody = self.custody(run)?;
            let (old, revision, rows) = self.read_run_with_channel(run, Some(collection))?;
            let projected = super::encode_run(run, revision, &rows)?;
            if old.as_deref() == Some(projected.as_slice()) {
                continue;
            }
            let next = super::encode_run(
                run,
                revision
                    .checked_add(1)
                    .ok_or_else(|| core("run revision exhausted"))?,
                &rows,
            )?;
            replace_leaf(
                &custody,
                super::RUN_FILE,
                &next,
                self.owner,
                super::MAX_RUN_BYTES,
            )?;
        }
        Ok(())
    }

    fn channel_service_locked(
        &self,
        client: &Client,
        action: &str,
        document: &Value,
        record: Option<&RequestRecord>,
    ) -> Result<Value, LaneError> {
        let mut input = envelope(
            &[],
            Some(document),
            None,
            false,
            request_core::now_ns().map_err(core)?,
        );
        let preview = client.call("--owner-preview", action, &self.loop_name, Some(&input))?;
        let mut next = decode(preview["collection"].clone())?;
        if let Some(record) = record {
            let row = next
                .requests
                .iter_mut()
                .find(|row| row.id == common_id(&self.loop_name, record.id()))
                .ok_or_else(|| core("service request disappeared"))?;
            check_source(record, &source(row)?)?;
            row.body["record"] = record.value().clone();
        }
        next.validate(&kinds()).map_err(core)?;
        input["expected"] = preview["before"].clone();
        input["publication"] = serde_json::to_value(&next).map_err(core)?;
        let committed = client.call("--owner-commit", action, &self.loop_name, Some(&input))?;
        if decode(committed["collection"].clone())? != next {
            return Err(core("service publication reply differs"));
        }
        self.channel_mirror_report(&next);
        Ok(committed["result"].clone())
    }

    /// Claim an admitted common door effect once before execution.
    ///
    /// # Errors
    /// Refuses a conflicting claim, changed source or unavailable helper.
    pub fn claim_request(&self, source_id: &str) -> Result<bool, LaneError> {
        let _lock = self.lock(true)?;
        let Some(client) = self.bound_client()? else {
            return Ok(true);
        };
        let collection = decode(client.call("--owner-read", "", &self.loop_name, None)?)?;
        let id = common_id(&self.loop_name, source_id);
        if !collection.requests.iter().any(|row| row.id == id) {
            return Ok(true);
        }
        let result = self.channel_service_locked(
            &client,
            "claim",
            &json!({"schema":1,"id":id,"claim":format!("door:{source_id}")}),
            None,
        )?;
        result["claimed"]
            .as_bool()
            .ok_or_else(|| core("service claim reply absent"))
    }

    pub(super) fn channel_record_effect(
        &self,
        source_id: &str,
        effect: &Value,
    ) -> Result<Option<RequestRecord>, LaneError> {
        let Some(client) = self.bound_client()? else {
            return Ok(None);
        };
        let collection = decode(client.call("--owner-read", "", &self.loop_name, None)?)?;
        let id = common_id(&self.loop_name, source_id);
        let Some(row) = collection.requests.iter().find(|row| row.id == id) else {
            return Ok(None);
        };
        if row.kind != "door-before-effect" {
            return Ok(None);
        }
        let mut record = self
            .read_run_with_channel(&row.run, Some(&collection))?
            .2
            .into_iter()
            .find(|record| record.id() == source_id)
            .ok_or_else(|| core("effect source absent"))?;
        match completion_disposition(
            row.state == State::Completed,
            record.value()["effect"] == *effect,
        ) {
            CompletionDisposition::IdenticalRetry => return Ok(Some(record)),
            CompletionDisposition::Conflict => return Err(core("conflicting completed effect")),
            CompletionDisposition::Publish => {}
        }
        record.record_effect(effect.clone())?;
        let (action, document) = if row.service_claim.is_none() {
            if !matches!(
                effect["reason"].as_str(),
                Some("door-disconnect-refusal" | "door-request-deadline")
            ) {
                return Err(core("unjudged effect is not a waiter refusal"));
            }
            ("withdraw", json!({"schema":1,"id":id}))
        } else {
            let claim = row
                .service_claim
                .as_ref()
                .ok_or_else(|| core("effect has no durable service claim"))?;
            (
                "complete",
                json!({"schema":1,"id":id,"claim":claim,"result":effect}),
            )
        };
        self.channel_service_locked(&client, action, &document, Some(&record))?;
        if action == "withdraw" && row.state == State::ServicePending {
            self.channel_service_locked(
                &client,
                "claim",
                &json!({"schema":1,"id":id,"claim":format!("departed:{id}")}),
                None,
            )?;
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:base-agent-outcomes-decode-through-run-and-door-body´
    #[test]
    fn base_agent_outcomes_decode_through_run_and_door_body() {
        // Spell the deployed release's record, without current constructors or apply.
        let setting = json!({"mode":"audit","floor":"audit","setter":"owner",
            "evidence":"first setting from row","set_at":"1","revision":1,"citations":[]});
        let base = json!({
            "schema":4,"id":"R:1a","loop":"alpha","run":"R","worker_uid":3000,
            "class":"git","shape_key":"git:upload","operation":"git-upload",
            "mirror_ref":"refs/heads/lane/alpha","mode":"audit","floor":"audit",
            "class_setting":setting,"loop_setting":setting,
            "would_do":{"decision":"refer","reason":"door-agent-failure"},
            "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,
                "stdin_bytes":0,"bound":16_777_216,"output_bytes":0,"stdout_bytes":0,
                "stderr_bytes":0,"queue_wall_seconds":null,"mediation_wall_seconds":0.0,
                "compute_wall_seconds":0.0},
            "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1",
            "decision_tier":"agent","would_do_source":"agent","matched_rule":null,
            "agent_verdict":"refer","agent_scope":"estate","agent_reason":"door-agent-failure",
            "agent_model":null,"agent_configured_model":"configured-model","agent_wall_ms":10,
            "agent_status":"failure","rubric_digest":null,"agent_runner_exit":{"code":1},
            "agent_runner_stderr_tail":"WARNING: proceeding\nError loading config.toml\n"
        });
        for status in ["failure", "verdict"] {
            let mut record = base.clone();
            if status == "verdict" {
                record["agent_status"] = json!(status);
                record["agent_runner_exit"] = json!({"code":0});
                record
                    .as_object_mut()
                    .expect("record")
                    .remove("agent_runner_stderr_tail");
            }
            let bytes = serde_json::to_vec(&json!({"schema":1,"run":"R","revision":1,
                "requests":[record]}))
            .expect("base run");
            let (revision, records) =
                super::super::decode_run(Some(&bytes), "R").expect("base run decodes");
            assert_eq!(revision, 1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].value(), &record);
            assert!(
                records[0].value().get("agent_runner_first_line").is_none(),
                "unrecorded, not empty"
            );
            let mut body = json!({"source_id":"R:1a","record":record});
            assert!(door_body(&body), "base channel body decodes");
            body["record"]["agent_runner_first_line"] = Value::Null;
            assert!(!door_body(&body), "malformed present field still refuses");
        }
    }
}
