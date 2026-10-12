//! Digest-bound, resumable schema-three conversion. No live reader accepts it.

use super::*;
use sha2::{Digest as _, Sha256};

const JOURNAL: &str = "door-rewrite.json";
const PLAN_LIMIT: usize = 64 * 1_048_576;

fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(result, "{byte:02x}");
    }
    result
}

fn convert(before: &Value) -> Result<Value, LaneError> {
    let mut after = before.clone();
    let rows = after["requests"]
        .as_array_mut()
        .ok_or_else(|| problem("requests-rewrite-refusal", "requests array absent"))?;
    for row in rows {
        if row["schema"] == 3 {
            if !super::super::exact(row, &super::super::RECORD_KEYS) {
                return Err(problem(
                    "requests-rewrite-refusal",
                    "schema-three keys differ",
                ));
            }
            if !matches!(
                row["would_do"]["decision"].as_str(),
                Some("allow" | "refuse" | "undecided")
            ) {
                return Err(problem(
                    "requests-rewrite-refusal",
                    "schema-three would-do differs",
                ));
            }
            super::super::judgement::initialize(row);
        }
        let _validated = RequestRecord::decode(row.clone())?;
    }
    let bytes = serde_json::to_vec(&after)
        .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
    let run = after["run"]
        .as_str()
        .ok_or_else(|| problem("requests-rewrite-refusal", "run absent"))?;
    let _validated = decode_run(Some(&bytes), run)?;
    Ok(after)
}

impl Store {
    pub(super) fn has_retired_custody(&self) -> Result<bool, LaneError> {
        let mut directory = Dir::openat(
            &self.runs,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            FileMode::empty(),
        )
        .map_err(|e| problem("requests-learned-index", e.to_string()))?;
        for entry in directory.iter() {
            let entry = entry.map_err(|e| problem("requests-learned-index", e.to_string()))?;
            if entry.file_name().to_bytes().starts_with(b".retired-") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Report the atomically published index, including failures and their remedy.
    pub fn learned_status(&self) -> Value {
        let (state, reason, shapes) = match self.read_learned() {
            Ok(index) if index.is_null() => ("absent", json!("index absent"), Value::Null),
            Ok(index) if index["unavailable"] == true => (
                "unavailable",
                index["reason"].as_str().map_or_else(
                    || json!("publication incomplete or invalidated"),
                    |reason| json!(reason),
                ),
                Value::Null,
            ),
            Ok(index) => (
                "current",
                Value::Null,
                json!(index["groups"].as_object().map_or(0, serde_json::Map::len)),
            ),
            Err(error) => ("invalid", json!(error.to_string()), Value::Null),
        };
        let limit = match reason.as_str() {
            Some("shape index capacity") => json!({"shapes":512}),
            Some("index byte capacity") => json!({"bytes":MAX_LEARNED_BYTES}),
            _ => Value::Null,
        };
        json!({"state":state,"reason":reason,"shapes":shapes,"limit":limit,
            "rebuild":if limit.is_null() {json!(format!("requests rebuild-index {}", self.loop_name))} else {Value::Null},
            "remedy":if limit.is_null() {Value::Null} else {json!("index capacity exhausted; rebuilding unchanged custody cannot reduce this limit")},
            "precondition":"stop the door service before rebuilding; schema four only; older records require requests rewrite with the service stopped"})
    }

    /// Rebuild derived labels without migrating or changing request custody.
    ///
    /// # Errors
    /// Refuses a running service, unsafe, invalid or older custody. Once scanning
    /// starts, the tombstone remains on failure. Every outcome reports elapsed time.
    pub fn rebuild_index(&self) -> Result<Value, LaneError> {
        let started = std::time::Instant::now();
        let outcome = self.rebuild_index_stopped();
        let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
        match outcome {
            Ok(mut status) => {
                status["wall_ms"] = json!(wall_ms);
                Ok(status)
            }
            Err(mut error) => {
                use std::fmt::Write as _;
                let _written = write!(error.detail, "; rebuild_wall_ms={wall_ms:.3}");
                Err(error)
            }
        }
    }

    fn rebuild_index_stopped(&self) -> Result<Value, LaneError> {
        let config = self
            .state_path
            .parent()
            .ok_or_else(|| problem("requests-rebuild-idle", "configuration directory absent"))?;
        let _configuration = crate::install::lock_loop_config(config, false)?;
        let settings = crate::settings::Settings::read(&config.join("workers.toml"))?;
        let socket = settings
            .socket_dir
            .ok_or_else(|| problem("requests-rebuild-idle", "socket directory absent"))?;
        let door = crate::home::pin_parent(&socket.join("door"), self.owner)?;
        // Same directory flock as the service and rewrite. Acquire it before
        // the store lock: a live service must never wait behind this scan.
        let _stopped = nix::fcntl::Flock::lock(
            File::from(door),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| {
            problem(
                "requests-rebuild-idle",
                format!("stop the door service: {error}"),
            )
        })?;
        let _lock = self.lock(true)?;
        self.write_learned(&json!({"unavailable":true,"reason":"index rebuild incomplete"}))?;
        let mut directory = Dir::openat(
            &self.runs,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            FileMode::empty(),
        )
        .map_err(|e| problem("requests-learned-index", e.to_string()))?;
        let mut index = json!({"schema":1,"groups":{}});
        let mut seen = BTreeMap::new();
        let collection = self.channel_read()?;
        for entry in directory.iter() {
            let entry = entry.map_err(|e| problem("requests-learned-index", e.to_string()))?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if !name.starts_with(".launch-") && !name.starts_with(".retired-") {
                continue;
            }
            // Retirement also archives reservation/report files beside custody.
            // Match rewrite_plan's no-follow directory/owner filter before open.
            let stat =
                nix::sys::stat::fstatat(&self.runs, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|e| problem("requests-learned-index", e.to_string()))?;
            if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
                || stat.st_uid != self.owner
            {
                continue;
            }
            let custody = open_child(&self.runs, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)?;
            let Some(bytes) = read_leaf(&custody, RUN_FILE, self.owner, MAX_RUN_BYTES)? else {
                continue;
            };
            // Retired driver directories retain their mode but hold no requests.
            // Only request custody must satisfy the private-directory contract.
            checked_dir(&custody, self.owner)?;
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|e| problem("requests-learned-index", e.to_string()))?;
            let run = value["run"]
                .as_str()
                .filter(|run| crate::valid_run_name(run))
                .ok_or_else(|| problem("requests-learned-index", "invalid custody run"))?;
            let (_, mut rows) = decode_run(Some(&bytes), run)?;
            self.channel_project(&mut rows, collection.as_ref())?;
            for row in rows {
                if row.value()["loop"] != self.loop_name
                    || row.value()["worker_uid"] == self.owner
                    || row.value()["worker_uid"] == self.loop_uid
                {
                    return Err(problem("requests-learned-index", "request grant differs"));
                }
                let fingerprint = digest(row.value().to_string().as_bytes());
                if let Some(prior) = seen.insert(row.id().to_owned(), fingerprint.clone()) {
                    if prior != fingerprint {
                        return Err(problem(
                            "requests-learned-index",
                            "duplicate request evidence differs",
                        ));
                    }
                    continue;
                }
                Self::index_judgement(&mut index, row.value(), None);
            }
        }
        self.write_learned(&index)?;
        Ok(self.learned_status())
    }

    fn rewrite_plan(&self) -> Result<Value, LaneError> {
        let mut directory = Dir::openat(
            &self.runs,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            FileMode::empty(),
        )
        .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
        let mut names = Vec::new();
        for entry in directory.iter() {
            let entry = entry.map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name.starts_with(".launch-") || name.starts_with(".retired-") {
                names.push(name.to_owned());
            }
        }
        names.sort();
        let mut files = Vec::new();
        for name in names {
            let stat = nix::sys::stat::fstatat(
                &self.runs,
                name.as_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
            if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
                || stat.st_uid != self.owner
            {
                continue;
            }
            let custody = open_child(&self.runs, &name, OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)?;
            let Some(bytes) = read_leaf(&custody, RUN_FILE, self.owner, MAX_RUN_BYTES)? else {
                continue;
            };
            // Like rebuild, skip retired driver directories without request custody.
            checked_dir(&custody, self.owner)?;
            let before: Value = serde_json::from_slice(&bytes)
                .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
            let after = convert(&before)?;
            if after["requests"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["loop"] != self.loop_name))
            {
                return Err(problem(
                    "requests-rewrite-refusal",
                    "request belongs to another loop",
                ));
            }
            files.push(json!({"custody":name,"before_sha256":digest(&bytes),"before":before,"after":after}));
        }
        Ok(json!({"schema":1,"loop":self.loop_name,"files":files}))
    }

    /// List the whole conversion or apply exactly its supplied digest.
    ///
    /// # Errors
    /// Refuses changed evidence, unsafe custody, or an oversized migration plan.
    #[allow(clippy::too_many_lines)]
    pub fn rewrite(&self, expected: Option<&str>) -> Result<Value, LaneError> {
        let _lock = self.lock(true)?;
        let saved = read_leaf(&self.state, JOURNAL, self.owner, PLAN_LIMIT)?;
        let mut journal: Value = saved
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|e| problem("requests-rewrite-refusal", format!("journal: {e}")))?
            .unwrap_or(Value::Null);
        let pending = journal["phase"] == "pending";
        let plan = if pending {
            journal["plan"].clone()
        } else {
            self.rewrite_plan()?
        };
        let bytes = serde_json::to_vec(&plan)
            .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
        if bytes.len() > PLAN_LIMIT / 2 {
            return Err(problem("requests-rewrite-refusal", "plan exceeds bound"));
        }
        let plan_digest = digest(&bytes);
        if expected.is_none() {
            return Ok(
                json!({"dry_run":true,"preview_sha256":plan_digest,"plan":plan,"resuming":pending,
                "changed":changed_records(&plan),"predecessor_schema":3,"target_schema":4}),
            );
        }
        if expected != Some(plan_digest.as_str()) {
            return Err(problem(
                "requests-rewrite-digest",
                "plan differs; repeat the dry run",
            ));
        }
        let files = plan["files"]
            .as_array()
            .ok_or_else(|| problem("requests-rewrite-refusal", "journal files absent"))?;
        let changed = changed_records(&plan);
        if changed == 0 && !pending {
            return Ok(
                json!({"dry_run":false,"preview_sha256":plan_digest,"plan":plan,
                "complete":true,"changed":0,"predecessor_schema":3,"target_schema":4}),
            );
        }
        if pending {
            let current = self.rewrite_plan()?;
            let names: Vec<_> = current["files"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| row["custody"].clone())
                .collect();
            let expected_names: Vec<_> = files.iter().map(|row| row["custody"].clone()).collect();
            if names != expected_names {
                return Err(problem(
                    "requests-rewrite-digest",
                    "custody inventory changed during rewrite",
                ));
            }
        }
        // Check every file before the first mutation. Resume accepts only the
        // original bytes or the exact already-published target bytes.
        for file in files {
            let name = file["custody"]
                .as_str()
                .ok_or_else(|| problem("requests-rewrite-refusal", "custody absent"))?;
            let custody = open_child(&self.runs, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)?;
            checked_dir(&custody, self.owner)?;
            let current = read_leaf(&custody, RUN_FILE, self.owner, MAX_RUN_BYTES)?
                .ok_or_else(|| problem("requests-rewrite-refusal", "record disappeared"))?;
            let target = serde_json::to_vec(&file["after"])
                .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
            if digest(&current) != file["before_sha256"] && !(pending && current == target) {
                return Err(problem(
                    "requests-rewrite-digest",
                    "record changed since the bound plan",
                ));
            }
        }
        journal = json!({"schema":1,"phase":"pending","digest":plan_digest,"plan":plan});
        replace_leaf(
            &self.state,
            JOURNAL,
            &serde_json::to_vec(&journal)
                .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?,
            self.owner,
            PLAN_LIMIT,
        )?;
        for file in files {
            let name = file["custody"].as_str().unwrap_or_default();
            let custody = open_child(&self.runs, name, OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)?;
            let target = serde_json::to_vec(&file["after"])
                .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?;
            replace_leaf(&custody, RUN_FILE, &target, self.owner, MAX_RUN_BYTES)?;
        }
        self.repair_shapes(&self.all_runs(None)?)?;
        let mut learned = json!({"schema":1,"groups":{}});
        let mut indexed = HashSet::new();
        for file in files {
            for row in file["after"]["requests"].as_array().into_iter().flatten() {
                if indexed.insert(row["id"].clone().to_string()) {
                    Self::index_judgement(&mut learned, row, None);
                }
            }
        }
        self.write_learned(&learned)?;
        journal["phase"] = json!("complete");
        replace_leaf(
            &self.state,
            JOURNAL,
            &serde_json::to_vec(&journal)
                .map_err(|e| problem("requests-rewrite-refusal", e.to_string()))?,
            self.owner,
            PLAN_LIMIT,
        )?;
        Ok(
            json!({"dry_run":false,"preview_sha256":plan_digest,"plan":plan,"complete":true,
            "changed":changed,"predecessor_schema":3,"target_schema":4}),
        )
    }
}

fn changed_records(plan: &Value) -> usize {
    plan["files"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|file| {
            file["before"]["requests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| row["schema"] == 3)
                .count()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::super::tests::Fixture;
    use super::*;
    use crate::requests::{Mode, judgement, tests::waiting};

    fn old_file(fixture: &Fixture) -> std::path::PathBuf {
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("file");
        let path = fixture.home.join("runs/.launch-R/door-requests.json");
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("JSON");
        let row = &mut value["requests"][0];
        for key in judgement::KEYS {
            row.as_object_mut().expect("record").remove(key);
        }
        row["schema"] = json!(3);
        std::fs::write(&path, serde_json::to_vec(&value).expect("bytes")).expect("old record");
        path
    }

    /// ´test:unit:rewrite-binds-plan-and-preserves-historical-evidence´
    #[test]
    fn rewrite_binds_plan_and_preserves_historical_evidence() {
        let fixture = Fixture::new();
        let path = old_file(&fixture);
        let store = fixture.store();
        assert_eq!(
            store.list().expect_err("strict reader").kind,
            "requests-rewrite-required"
        );
        let before = std::fs::read(&path).expect("before");
        let preview = store.rewrite(None).expect("preview");
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
        assert_eq!(
            preview["plan"]["files"][0]["before"]["requests"][0]["schema"],
            3
        );
        assert_eq!(
            preview["plan"]["files"][0]["after"]["requests"][0]["schema"],
            4
        );
        assert_eq!(
            store.rewrite(Some("wrong")).expect_err("digest").kind,
            "requests-rewrite-digest"
        );
        store
            .rewrite(preview["preview_sha256"].as_str())
            .expect("convert");
        let row = store
            .list_run("R")
            .expect("new reader")
            .remove(0)
            .into_value();
        assert_eq!(row["decision_tier"], "fast-lane");
        assert!(row["agent_model"].is_null());
        assert_eq!(row["state"], "waiting");
        let converted = std::fs::read(&path).expect("converted bytes");
        let journal = std::fs::read(fixture.home.join(".config/loops/alpha/door-rewrite.json"));
        let repeat = store.rewrite(None).expect("repeat preview");
        assert_eq!(repeat["changed"], 0);
        assert_eq!(
            store
                .rewrite(repeat["preview_sha256"].as_str())
                .expect("repeat apply")["changed"],
            0
        );
        assert_eq!(std::fs::read(&path).expect("same bytes"), converted);
        assert_eq!(
            std::fs::read(fixture.home.join(".config/loops/alpha/door-rewrite.json")).ok(),
            journal.ok()
        );
    }

    /// ´test:unit:rewrite-preserves-reviewed-label-and-superloop-tier´
    #[test]
    fn rewrite_preserves_reviewed_label_and_superloop_tier() {
        let fixture = Fixture::new();
        let path = old_file(&fixture);
        let mut row = waiting("R", "1a", 3000, Mode::Audit);
        row.mark("review").expect("mark");
        row.review("review-1", "2").expect("review");
        row.adjudicate("review-1", "refuse", "reviewed boundary", "superloop", "3")
            .expect("label");
        let mut historical = row.into_value();
        for key in judgement::KEYS {
            historical.as_object_mut().expect("row").remove(key);
        }
        historical["schema"] = json!(3);
        let mut file: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("file")).expect("JSON");
        file["requests"][0] = historical.clone();
        std::fs::write(&path, serde_json::to_vec(&file).expect("bytes"))
            .expect("historical reviewed row");
        let store = fixture.store();
        let preview = store.rewrite(None).expect("plan");
        store
            .rewrite(preview["preview_sha256"].as_str())
            .expect("rewrite");
        let actual = store.list_run("R").expect("rows").remove(0).into_value();
        assert_eq!(actual["label"], historical["label"]);
        assert_eq!(actual["review"], historical["review"]);
        assert_eq!(actual["decision_tier"], "superloop");
        assert_eq!(actual["would_do_source"], "fast-lane");
        assert!(actual["agent_status"].is_null());
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("rebuilt labels")
                .0["decision"],
            "refuse"
        );
    }

    /// ´test:unit:rewrite-resumes-and-includes-retired-custody´
    #[test]
    fn rewrite_resumes_and_includes_retired_custody() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new();
        let path = old_file(&fixture);
        let retired = fixture.home.join("runs/.retired-R-custody");
        std::fs::create_dir(&retired).expect("retired custody");
        std::fs::set_permissions(&retired, std::fs::Permissions::from_mode(0o700))
            .expect("private");
        std::fs::copy(&path, retired.join(RUN_FILE)).expect("retained historical file");
        let store = fixture.store();
        let preview = store.rewrite(None).expect("plan");
        assert_eq!(preview["plan"]["files"].as_array().expect("files").len(), 2);
        let journal = json!({"schema":1,"phase":"pending","digest":preview["preview_sha256"],"plan":preview["plan"]});
        replace_leaf(
            &store.state,
            JOURNAL,
            &serde_json::to_vec(&journal).expect("journal"),
            store.owner,
            PLAN_LIMIT,
        )
        .expect("interrupted journal");
        std::fs::write(
            &path,
            serde_json::to_vec(&preview["plan"]["files"][0]["after"]).expect("after"),
        )
        .expect("first file installed");
        assert_eq!(
            store.rewrite(None).expect("resume preview")["preview_sha256"],
            preview["preview_sha256"]
        );
        store
            .rewrite(preview["preview_sha256"].as_str())
            .expect("resume");
        let value: Value =
            serde_json::from_slice(&std::fs::read(retired.join(RUN_FILE)).expect("retired"))
                .expect("JSON");
        assert_eq!(value["requests"][0]["schema"], 4);
        assert_eq!(store.list_run("R").expect("active").len(), 1);
    }
}
