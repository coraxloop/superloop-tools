use execute_command::learning::Feedback;
use execute_command::record::{
    CompletionDisposition, EffectPublication, HookRecordFailure, ReviewState,
    completion_disposition, current_review, hook_emission, hook_record_failure,
};
use execute_command::request::Judgement;

/// ´test:integration:corrections-preserve-audit-until-current-setting-resolves-them´
#[test]
fn corrections_preserve_audit_until_current_setting_resolves_them() {
    let correction = Feedback {
        adjudicated: true,
        enforced: true,
        would_do: Some(Judgement::Allow),
        treatment: Some(Judgement::Refuse),
        labelled_at: Some(20),
    };
    assert!(correction.is_correction());
    assert!(correction.correction_pending(None));
    assert!(correction.correction_pending(Some((false, Some(20)))));
    assert!(correction.correction_pending(Some((false, None))));
    assert!(!correction.correction_pending(Some((false, Some(21)))));
    assert!(!correction.correction_pending(Some((true, Some(1)))));
    for would_do in [None, Some(Judgement::Refer), Some(Judgement::Refuse)] {
        assert!(
            !Feedback {
                would_do,
                ..correction
            }
            .is_correction()
        );
    }
    assert!(
        !Feedback {
            adjudicated: false,
            ..correction
        }
        .is_correction()
    );
    assert!(
        !Feedback {
            enforced: false,
            ..correction
        }
        .correction_pending(None)
    );
}

/// ´test:integration:learning-groups-distinguish-agreement-correction-and-missing-prediction´
#[test]
fn learning_groups_distinguish_agreement_correction_and_missing_prediction() {
    for (would_do, treatment, expected) in [
        (None, Some(Judgement::Allow), Some("labels_after_undecided")),
        (
            Some(Judgement::Refer),
            Some(Judgement::Refuse),
            Some("labels_after_refer"),
        ),
        (
            Some(Judgement::Allow),
            Some(Judgement::Allow),
            Some("agreements"),
        ),
        (
            Some(Judgement::Allow),
            Some(Judgement::Refuse),
            Some("corrections"),
        ),
        (Some(Judgement::Refuse), None, None),
    ] {
        let feedback = Feedback {
            adjudicated: true,
            enforced: false,
            would_do,
            treatment,
            labelled_at: None,
        };
        assert_eq!(feedback.comparison_group(), expected);
    }
    assert_eq!(
        execute_command::learning::correction_action(),
        "rubric-row-needed"
    );
}

/// ´test:integration:review-state-and-current-review-preconditions-retain-no-partial-answer´
#[test]
fn review_state_and_current_review_preconditions_retain_no_partial_answer() {
    let waiting = ReviewState {
        state: Some("waiting"),
        effect: EffectPublication::Pending,
        review: false,
        label: false,
        mark: false,
    };
    assert!(waiting.valid());
    assert!(
        !ReviewState {
            label: true,
            ..waiting
        }
        .valid()
    );
    assert!(
        !ReviewState {
            state: Some("observed"),
            ..waiting
        }
        .valid()
    );
    assert!(
        ReviewState {
            state: Some("observed"),
            effect: EffectPublication::Recorded,
            ..waiting
        }
        .valid()
    );
    assert!(
        !ReviewState {
            state: Some("marked"),
            ..waiting
        }
        .valid()
    );
    assert!(
        ReviewState {
            state: Some("marked"),
            mark: true,
            ..waiting
        }
        .valid()
    );
    assert_eq!(
        current_review(true, Some("new"), "old")
            .expect_err("stale")
            .0,
        "requests-review-id-refusal"
    );
    assert!(current_review(true, Some("current"), "current").is_ok());
    assert!(current_review(false, Some("current"), "current").is_err());
}

/// ´test:integration:completion-retry-and-hook-publication-do-not-infer-execution´
#[test]
fn completion_retry_and_hook_publication_do_not_infer_execution() {
    use execute_command::record::{Outcome, execution_outcome};
    assert_eq!(execution_outcome(None, false), Outcome::OutcomeUnknown);
    assert_eq!(execution_outcome(None, true), Outcome::RefusedBeforeEffect);
    assert_eq!(execution_outcome(Some(true), false), Outcome::Completed);
    assert_eq!(execution_outcome(Some(false), false), Outcome::Failed);
    assert_eq!(
        completion_disposition(false, false),
        CompletionDisposition::Publish
    );
    assert_eq!(
        completion_disposition(true, true),
        CompletionDisposition::IdenticalRetry
    );
    assert_eq!(
        completion_disposition(true, false),
        CompletionDisposition::Conflict
    );
    assert_eq!(
        hook_record_failure(true, false),
        HookRecordFailure::LostAuditEvent
    );
    assert_eq!(
        hook_record_failure(true, true),
        HookRecordFailure::LostAuditEvent
    );
    assert_eq!(hook_record_failure(false, false), HookRecordFailure::Refuse);
    assert_eq!(
        hook_record_failure(false, true),
        HookRecordFailure::RetainStateRootRefusal
    );
    assert_eq!(hook_emission(true, false), None);
    assert_eq!(hook_emission(true, true), None);
    assert_eq!(hook_emission(false, false), Some(Judgement::Allow));
    assert_eq!(hook_emission(false, true), Some(Judgement::Refuse));
}
