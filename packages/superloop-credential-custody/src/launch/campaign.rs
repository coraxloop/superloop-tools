//! Sequential case ownership and a bounded matrix of completed observations.
use super::{
    Result,
    measure::{Admission, ObjectIdentity},
    require,
    store::{CompletedCase, Store},
};
use crate::receipt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::File,
    time::{Duration, Instant},
};

#[derive(Serialize)]
pub(super) struct Row {
    index: usize,
    completed: CompletedCase,
}
#[derive(Serialize)]
pub(super) struct Matrix {
    schema: u32,
    command: &'static str,
    campaign: String,
    policy_sha256: String,
    code_sha256: String,
    rows: Vec<Row>,
}

fn verify_root(admission: &Admission, root: &File) -> Result<()> {
    let current = receipt::sealed_directory(&admission.policy().roots.evidence)?;
    require(
        ObjectIdentity::of(&current)? == ObjectIdentity::of(root)?,
        "campaign-root-binding",
    )
}
fn budget(deadline: Instant) -> Result<()> {
    require(Instant::now() < deadline, "campaign-deadline")
}

// The adapter must finish and drop each Keeper before returning. It cannot
// manufacture a completed Store: all acceptance remains under the C1-C5 owners.
pub(super) fn run(
    admission: &Admission,
    deadline: Instant,
    mut case: impl FnMut(usize, &mut Store, Instant) -> Result<()>,
) -> Result<Matrix> {
    budget(deadline)?;
    let policy = admission.policy();
    let root = receipt::sealed_directory(&policy.roots.evidence)?;
    let mut matrix = Matrix {
        schema: 1,
        command: "calibration-run",
        campaign: policy.campaign.clone(),
        policy_sha256: admission.policy_sha256().into(),
        code_sha256: admission.code_sha256().into(),
        rows: Vec::new(),
    };
    receipt::publish_held(
        &root,
        "campaign-start.json",
        &serde_json::to_vec(&matrix).map_err(|_| "launch-evidence-encoding")?,
    )?;
    let outcome = (|| {
        let mut invocations = BTreeSet::new();
        let mut total = 0_u64;
        for (index, expected) in policy.cases.iter().enumerate() {
            budget(deadline)?;
            verify_root(admission, &root)?;
            let mut store = Store::reserve(admission, index)?;
            let case_deadline =
                deadline.min(Instant::now() + Duration::from_millis(policy.limits.case_ms));
            let outcome = (|| {
                case(index, &mut store, case_deadline)?;
                budget(case_deadline)?;
                store.completed_case()
            })();
            let completed = match outcome {
                Ok(completed) => completed,
                Err(class) => {
                    if !matches!(
                        store.phase(),
                        super::state::Phase::Failed
                            | super::state::Phase::Uncertain
                            | super::state::Phase::Complete
                    ) {
                        store.uncertain(class)?;
                    }
                    return Err(class);
                }
            };
            require(
                completed.case == expected.id
                    && completed.policy_sha256 == admission.policy_sha256()
                    && completed.case_sha256 == admission.cases()[index].sha256
                    && completed.invocation.unit == expected.generator_unit,
                "campaign-case-binding",
            )?;
            require(
                invocations.insert(completed.invocation.id.clone()),
                "campaign-invocation-repeated",
            )?;
            total = completed
                .sealed_bytes
                .iter()
                .try_fold(total, |sum, bytes| {
                    sum.checked_add(*bytes).ok_or("campaign-output-bound")
                })?;
            require(
                total <= policy.limits.total_sealed_bytes,
                "campaign-output-bound",
            )?;
            matrix.rows.push(Row { index, completed });
        }
        budget(deadline)?;
        verify_root(admission, &root)?;
        for artifact in admission.artifacts() {
            artifact.verify_bytes()?;
        }
        require(
            matrix.rows.len() == policy.cases.len(),
            "campaign-matrix-incomplete",
        )?;
        let bytes = serde_json::to_vec(&matrix).map_err(|_| "launch-evidence-encoding")?;
        require(bytes.len() <= 256 * 1024, "campaign-matrix-size")?;
        budget(deadline)?;
        receipt::publish_held(&root, "campaign.json", &bytes)
    })();
    if let Err(class) = outcome {
        verify_root(admission, &root)?;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema":1, "command":"calibration-run", "outcome":"refused",
            "refusal_class":class, "completed_prefix":matrix,
        }))
        .map_err(|_| "launch-evidence-encoding")?;
        receipt::publish_held(&root, "campaign-failure.json", &bytes)?;
        return Err(class);
    }
    Ok(matrix)
}
