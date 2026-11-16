//! Immutable operational evidence, independent of calibration acceptance.
use super::{Phase, Store};
use crate::{receipt, record::Result};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(in crate::launch) struct Binding {
    pub invocation: String,
    pub manager_reply_sha256: String,
    pub manager_configuration_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(tag = "evidence", rename_all = "kebab-case")]
pub(in crate::launch) enum Disposition {
    Retained,
    Unbound { class: &'static str },
    NotAttempted,
    Unknown,
    StopJobCompleted { invocation: String },
    UnitUnloaded { unit: String },
    UnlinkSucceeded,
    UnlinkedAtCapture,
    Failed { class: &'static str },
}
#[derive(Clone, Serialize)]
pub(in crate::launch) struct Recovery {
    pub holder: Disposition,
    pub sealer_exits: [Option<crate::launch::sealer::Exit>; 2],
    pub outputs: Disposition,
    pub fifos: Disposition,
    pub socket: Disposition,
    pub evidence: Disposition,
}
#[derive(Default)]
pub(super) struct Journal {
    next: u32,
    last: Option<String>,
    missing: bool,
    binding: Option<Binding>,
    recovery_recorded: bool,
}
#[derive(Clone, Serialize)]
pub(in crate::launch) struct Failure {
    pub case: String,
    pub unit: String,
    pub stage: Phase,
    pub original_cause: Option<&'static str>,
    pub last_lifecycle_receipt: Option<String>,
    pub recovery_evidence_missing: bool,
}
#[derive(Clone, Copy, Serialize)]
#[serde(tag = "kind", content = "observation", rename_all = "kebab-case")]
enum Event<'a> {
    SubmissionAcknowledged,
    StartBinding(&'a Binding),
    RecoveryIntent,
    Recovery(&'a Recovery),
}
impl Store {
    fn lifecycle(&mut self, event: Event<'_>) -> Result<()> {
        let result = (|| {
            super::super::require(self.journal.next < 16, "lifecycle-bound")?;
            self.evidence.verify()?;
            let name = format!("lifecycle-{:02}.json", self.journal.next);
            let value = serde_json::json!({
                "schema":3,"stop_request":crate::launch::stop::request(),"command":"campaign-lifecycle","case":self.case,"unit":self.unit,
                "sequence":self.journal.next,"phase":self.phase(),
                "original_cause":self.original_cause,"failure_stage":self.failure_stage,
                "policy_sha256":self.policy_sha256,"code_sha256":self.code_sha256,
                "case_sha256":self.case_sha256,"binding":self.journal.binding,"event":event,
            });
            receipt::publish_held(
                self.evidence.file(),
                &name,
                &serde_json::to_vec(&value).map_err(|_| "launch-evidence-encoding")?,
            )?;
            self.evidence.verify()?;
            self.journal.last = Some(name);
            self.journal.next += 1;
            Ok(())
        })();
        if result.is_err() {
            self.journal.missing = true;
        }
        result
    }
    pub fn submission_acknowledged(&mut self) -> Result<()> {
        self.lifecycle(Event::SubmissionAcknowledged)
    }
    pub fn retain_start(&mut self, snapshot: &crate::launch::manager::Snapshot) -> Result<()> {
        super::super::require(
            self.phase() == Phase::Submitted || self.failure_stage == Some(Phase::Submitted),
            "lifecycle-binding-order",
        )?;
        super::super::require(!snapshot.invocation.is_empty(), "lifecycle-binding-empty")?;
        if let Some(old) = &self.journal.binding {
            return super::super::require(
                old.invocation == snapshot.invocation,
                "lifecycle-binding-drift",
            );
        }
        let binding = Binding {
            invocation: snapshot.invocation.clone(),
            manager_reply_sha256: snapshot.raw_sha256.clone(),
            manager_configuration_sha256: snapshot.configuration_sha256.clone(),
        };
        // Publish before memory can authorize the next step; a kill leaves the intent.
        self.lifecycle(Event::StartBinding(&binding))?;
        self.journal.binding = Some(binding);
        Ok(())
    }
    pub fn recovery_intent(&mut self) -> Result<()> {
        self.lifecycle(Event::RecoveryIntent)
    }
    pub fn retain_recovery(&mut self, observed: &Recovery) -> Result<()> {
        self.lifecycle(Event::Recovery(observed))?;
        self.journal.recovery_recorded = true;
        Ok(())
    }
    pub fn ensure_recovery_record(&mut self) -> Result<()> {
        if self.journal.recovery_recorded {
            return Ok(());
        }
        self.retain_recovery(&Recovery {
            holder: Disposition::Unknown,
            sealer_exits: [None; 2],
            outputs: Disposition::Unknown,
            fifos: Disposition::Unknown,
            socket: Disposition::Unknown,
            evidence: Disposition::Retained,
        })
    }
    pub fn failure_context(&self) -> Failure {
        Failure {
            case: self.case.clone(),
            unit: self.unit.clone(),
            stage: self.failure_stage.unwrap_or_else(|| self.phase()),
            original_cause: self.original_cause,
            last_lifecycle_receipt: self.journal.last.clone(),
            recovery_evidence_missing: self.journal.missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::{test_support::case_guard, tests::Fixture};
    use std::{fs, os::unix::fs::MetadataExt as _};
    fn recovery() -> Recovery {
        Recovery {
            holder: Disposition::Failed {
                class: "synthetic-stop-failed",
            },
            sealer_exits: [None; 2],
            outputs: Disposition::Retained,
            fifos: Disposition::Retained,
            socket: Disposition::Retained,
            evidence: Disposition::Retained,
        }
    }
    /// ´test:unit:lifecycle-retains-secondary-facts-after-uncertainty´
    #[test]
    fn lifecycle_retains_secondary_facts_after_uncertainty() {
        let _guard = case_guard();
        let f = Fixture::new();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        store.uncertain("synthetic-first-failure").unwrap();
        store.recovery_intent().unwrap();
        store.retain_recovery(&recovery()).unwrap();
        let path = f.dir.path().join("evidence/sample/lifecycle-01.json");
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["original_cause"], "synthetic-first-failure");
        assert_eq!(value["failure_stage"], "reserved");
        assert_eq!(value["phase"], "uncertain");
        assert_eq!(
            value["event"]["observation"]["holder"]["class"],
            "synthetic-stop-failed"
        );
        assert_eq!(
            value["event"]["observation"]["outputs"]["evidence"],
            "retained"
        );
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o400);
        assert_eq!(
            store.failure_context().last_lifecycle_receipt.as_deref(),
            Some("lifecycle-01.json")
        );
        assert_eq!(store.phase(), Phase::Uncertain);
    }
    /// ´test:unit:lifecycle-publication-never-overwrites-or-follows-replacement´
    #[test]
    fn lifecycle_publication_never_overwrites_or_follows_replacement() {
        let _guard = case_guard();
        for replacement in [false, true] {
            let f = Fixture::new();
            let admission = f.admit();
            let mut store = Store::reserve(&admission, 0).unwrap();
            store.uncertain("synthetic-first-failure").unwrap();
            let directory = f.dir.path().join("evidence/sample");
            if replacement {
                fs::rename(&directory, f.dir.path().join("saved-evidence")).unwrap();
                fs::create_dir(&directory).unwrap();
            } else {
                fs::write(directory.join("lifecycle-00.json"), b"occupied").unwrap();
            }
            assert_eq!(
                store.retain_recovery(&recovery()),
                Err(if replacement {
                    "launch-directory-binding"
                } else {
                    "receipt-no-replace"
                })
            );
            assert!(store.failure_context().recovery_evidence_missing);
            assert!(store.failure_context().last_lifecycle_receipt.is_none());
            assert_eq!(
                store.failure_context().original_cause,
                Some("synthetic-first-failure")
            );
            assert_eq!(store.phase(), Phase::Uncertain);
        }
    }
    /// ´test:unit:lifecycle-sequence-is-bounded-and-binding-is-single-use´
    #[test]
    fn lifecycle_sequence_is_bounded_and_binding_is_single_use() {
        let _guard = case_guard();
        let f = Fixture::new();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut snapshot = crate::launch::manager::Snapshot {
            invocation: "a".repeat(32),
            pid: 0,
            raw_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            active: "activating".into(),
            sub: "start".into(),
            code: 0,
            status: 0,
            result: "success".into(),
            properties: Vec::new(),
            load: "loaded".into(),
            condition: true,
            assertion: true,
            exec_pid: 0,
            started: 0,
            exited: 0,
        };
        assert_eq!(
            store.retain_start(&snapshot),
            Err("lifecycle-binding-order")
        );
        store.advance(Phase::SealersStarted).unwrap();
        store.advance(Phase::Submitted).unwrap();
        snapshot.invocation.clear();
        assert_eq!(
            store.retain_start(&snapshot),
            Err("lifecycle-binding-empty")
        );
        snapshot.invocation = "a".repeat(32);
        store.retain_start(&snapshot).unwrap();
        let before = std::fs::read(f.dir.path().join("evidence/sample/lifecycle-00.json")).unwrap();
        store.retain_start(&snapshot).unwrap();
        assert_eq!(store.journal.next, 1);
        snapshot.invocation = "d".repeat(32);
        assert_eq!(
            store.retain_start(&snapshot),
            Err("lifecycle-binding-drift")
        );
        assert_eq!(
            std::fs::read(f.dir.path().join("evidence/sample/lifecycle-00.json")).unwrap(),
            before
        );
        for _ in 1..16 {
            store.recovery_intent().unwrap();
        }
        assert_eq!(store.recovery_intent(), Err("lifecycle-bound"));
        assert_eq!(store.journal.next, 16);
    }
}
