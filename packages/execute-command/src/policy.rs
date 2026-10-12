//! DoorMode/floor comparison, permitted transitions and evidence requirements.
//!
//! Callers select authoritative configuration and publish authorized changes.
//! Extraction preserves floor-derived initialization and distinct caller modes.

use std::collections::BTreeSet;

use crate::checks::{refusal, text, verdict};
use crate::request::{
    Binding, Judgement, LabelObservation, Rung, ShapeError, Text, TextList, Verdict,
};

/// Door ordering only; hook audit still has its distinct silent transport policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DoorMode {
    Audit,
    Enforce,
    Allow,
}

impl DoorMode {
    /// Decode a required stored mode without silently relaxing or repairing it.
    ///
    /// # Errors
    /// Returns `door-mode-record-refusal` for an absent or unknown mode.
    pub fn from_record(value: Option<&str>) -> Result<Self, ShapeError> {
        match value {
            Some("audit") => Ok(Self::Audit),
            Some("enforce") => Ok(Self::Enforce),
            Some("allow") => Ok(Self::Allow),
            _ => Err(ShapeError("door-mode-record-refusal")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
            Self::Allow => "allow",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Audit => 0,
            Self::Enforce => 1,
            Self::Allow => 2,
        }
    }

    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

/// Compare a selected setting with the registered floor before other policy checks.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn mode_floor(
    request: &impl AsRef<Binding>,
    selected: DoorMode,
    floor: DoorMode,
) -> Result<Option<Verdict>, ShapeError> {
    if selected.rank() <= floor.rank() {
        return Ok(None);
    }
    refusal(
        request,
        "loop",
        "door-mode-floor-refusal",
        "setting is less strict than the registry floor",
        "select a setting at least as strict as the registered floor",
    )
    .map(Some)
}

/// Combine existing class and loop settings with the current registered floor.
#[must_use]
pub const fn effective_mode(
    class: DoorMode,
    loop_mode: DoorMode,
    floor: DoorMode,
    correction_pending: bool,
) -> DoorMode {
    if correction_pending {
        DoorMode::Audit
    } else {
        class.stricter(loop_mode).stricter(floor)
    }
}

/// Proposed value for an absent setting; the caller alone can publish it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialSetting {
    pub mode: DoorMode,
    pub evidence: Text,
}

/// Offer floor-derived initialization only when the caller observed no setting.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable evidence value.
pub fn initial_setting(
    current: Option<DoorMode>,
    floor: DoorMode,
) -> Result<Option<InitialSetting>, ShapeError> {
    if current.is_some() {
        return Ok(None);
    }
    Ok(Some(InitialSetting {
        mode: floor,
        evidence: text(&format!(
            "row door_floor={} initializes absent setting",
            floor.as_str()
        ))?,
    }))
}

/// Validate first, stricter and relaxed moves after caller custody checks.
///
/// A successful verdict describes permission to publish the setting, never to
/// execute its associated command. Nonempty citations must separately pass
/// `citation_evidence`; the caller orders floor, citation and transition checks.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn mode_transition(
    request: &impl AsRef<Binding>,
    previous: Option<DoorMode>,
    selected: DoorMode,
    floor: DoorMode,
    citations: &TextList,
) -> Result<Verdict, ShapeError> {
    if let Some(refused) = mode_floor(request, selected, floor)? {
        return Ok(refused);
    }
    let cited = !citations.as_slice().is_empty();
    let direction = match previous {
        Some(previous) if previous == selected => {
            return refusal(
                request,
                "loop",
                "door-mode-setting-refusal",
                "mode is unchanged",
                "select a different mode or retain the existing setting",
            );
        }
        Some(previous) if selected.rank() > previous.rank() => {
            if !cited {
                return refusal(
                    request,
                    "loop",
                    "door-mode-evidence-refusal",
                    "relaxation needs adjudicated labels",
                    "cite current agreeing adjudicated labels for this setting",
                );
            }
            "relaxed"
        }
        Some(_) => "stricter",
        None => {
            if cited {
                return refusal(
                    request,
                    "loop",
                    "door-mode-evidence-refusal",
                    "first setting has no prior label basis",
                    "initialize the setting with its floor evidence and no prior-label citations",
                );
            }
            "first"
        }
    };
    verdict(
        request,
        "loop",
        Judgement::Allow,
        Rung::DeterministicChecks,
        direction,
        None,
        citations.clone(),
    )
}

/// Check cited labels from caller-read current and retired custody.
///
/// A loop target uses None for class. Relaxation requires agreement; tightening
/// still requires adjudication, unique IDs and matching class when applicable.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn citation_evidence(
    request: &impl AsRef<Binding>,
    class: Option<&Text>,
    citations: &[String],
    labels: &[LabelObservation],
    require_agreement: bool,
) -> Result<Option<Verdict>, ShapeError> {
    if citations.len() > 32 {
        return evidence_refusal(request, "citation list exceeds limit").map(Some);
    }
    let mut seen = BTreeSet::new();
    for id in citations {
        let Some(label) = labels.iter().find(|label| label.id.as_str() == id) else {
            return evidence_refusal(request, "cited request is absent").map(Some);
        };
        if !seen.insert(id.as_str())
            || !label.adjudicated
            || (require_agreement
                && (!matches!(label.would_do, Some(Judgement::Allow | Judgement::Refuse))
                    || label.would_do != label.treatment))
            || class.is_some_and(|class| label.class != *class)
        {
            return evidence_refusal(
                request,
                "cited request is not an agreeing label for this setting",
            )
            .map(Some);
        }
    }
    Ok(None)
}

fn evidence_refusal(request: &impl AsRef<Binding>, reason: &str) -> Result<Verdict, ShapeError> {
    refusal(
        request,
        "loop",
        "door-mode-evidence-refusal",
        reason,
        "cite at most 32 distinct adjudicated requests for this setting, with agreeing labels when relaxing",
    )
}

/// Raw setting metadata observed by the caller's strict record adapter.
pub struct SettingEvidence<'a> {
    pub setter: &'a str,
    pub evidence: &'a str,
    pub set_at: &'a str,
    pub revision: u64,
    pub citations: &'a [String],
}

/// Preserve the door setting reader's nonempty byte bounds and unique citations.
///
/// The caller still checks the exact record keys, mode spellings and floor.
/// Whitespace is not trimmed: the existing reader checks nonempty byte length.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn setting_evidence(
    request: &impl AsRef<Binding>,
    evidence: &SettingEvidence<'_>,
) -> Result<Option<Verdict>, ShapeError> {
    let word = |value: &str, bound| !value.is_empty() && value.len() <= bound;
    let ids = evidence.citations;
    if !word(evidence.setter, 128)
        || !word(evidence.evidence, 1024)
        || !word(evidence.set_at, 64)
        || evidence.revision == 0
        || ids.len() > 32
        || ids.iter().any(|id| !word(id.as_str(), 160))
        || ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            != ids.len()
    {
        return refusal(request, "loop", "requests-record-refusal", "mode setting shape differs",
            "supply bounded nonempty setter, evidence and timestamp, a positive revision and distinct bounded citations").map(Some);
    }
    Ok(None)
}

/// Gateway observations supplied from the audit, registration and caller clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunAdmission {
    pub runs: u32,
    pub run_cap: u32,
    pub has_snapshot: bool,
    pub last_run_timestamp_ms: Option<u64>,
    pub cooldown_seconds: u64,
    pub now_unix_ms: u64,
}

/// Preserve budget, snapshot, then cooldown refusal precedence without reading time.
///
/// A miss permits the caller to continue admission, not to infer execution.
/// Saturating conversion and elapsed time preserve future timestamps and overflow.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn gateway_admission(
    request: &impl AsRef<Binding>,
    observed: &RunAdmission,
) -> Result<Option<Verdict>, ShapeError> {
    if observed.runs >= observed.run_cap {
        let mut result = refusal(
            request,
            "loop",
            "run_budget_exhausted",
            "registered run cap has been consumed; continue with READY FOR VERIFY",
            "continue with READY FOR VERIFY; do not submit another run under the exhausted cap",
        )?;
        result.evidence = vec![
            text(&format!("run_cap={}", observed.run_cap))?,
            text(&format!("runs={}", observed.runs))?,
        ]
        .try_into()
        .map_err(|_| ShapeError("execute-command-verdict-shape"))?;
        return Ok(Some(result));
    }
    if !observed.has_snapshot {
        return refusal(
            request,
            "loop",
            "no_snapshot",
            "run requires a fresh successful mirror snapshot",
            "push a fresh successful mirror snapshot before requesting a run",
        )
        .map(Some);
    }
    if let Some(last_run) = observed.last_run_timestamp_ms {
        let cooldown_millis = observed.cooldown_seconds.saturating_mul(1_000);
        let elapsed = observed.now_unix_ms.saturating_sub(last_run);
        if elapsed < cooldown_millis {
            return refusal(
                request,
                "loop",
                "run_cooldown_active",
                "registered run cooldown has not elapsed",
                "wait for the registered cooldown to elapse before submitting a run",
            )
            .map(Some);
        }
    }
    Ok(None)
}
