//! Outcome/rationale grouping and evidence for reviewed policy changes.
//!
//! Callers retain journals and authorized policy publication; historical effects
//! are never replayed and a successful exit is not authority.

use crate::request::Judgement;

/// Label evidence already authenticated and decoded by the custody owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback {
    pub adjudicated: bool,
    pub enforced: bool,
    pub would_do: Option<Judgement>,
    pub treatment: Option<Judgement>,
    pub labelled_at: Option<u128>,
}

impl Feedback {
    /// A correction needs a decided prediction and an opposing reviewed label.
    #[must_use]
    pub fn is_correction(self) -> bool {
        self.adjudicated
            && matches!(self.would_do, Some(Judgement::Allow | Judgement::Refuse))
            && matches!(self.treatment, Some(Judgement::Allow | Judgement::Refuse))
            && self.would_do != self.treatment
    }

    /// Preserve audit until a setting resolves a newer enforced correction.
    #[must_use]
    pub fn correction_pending(self, setting: Option<(bool, Option<u128>)>) -> bool {
        self.enforced
            && self.is_correction()
            && setting.is_none_or(|(audit, set_at)| {
                !audit
                    && self
                        .labelled_at
                        .zip(set_at)
                        .is_none_or(|(label, set)| label >= set)
            })
    }

    /// Group reviewed evidence without treating an undecided prediction as wrong.
    #[must_use]
    pub const fn comparison_group(self) -> Option<&'static str> {
        match (self.would_do, self.treatment) {
            (_, None | Some(Judgement::Refer)) => None,
            (None, _) => Some("labels_after_undecided"),
            (Some(Judgement::Refer), _) => Some("labels_after_refer"),
            (Some(Judgement::Allow), Some(Judgement::Allow))
            | (Some(Judgement::Refuse), Some(Judgement::Refuse)) => Some("agreements"),
            _ => Some("corrections"),
        }
    }
}

/// A policy-change report is evidence for review, never an installed rule.
#[must_use]
pub const fn correction_action() -> &'static str {
    "rubric-row-needed"
}
