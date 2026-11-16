//! Sequential case ownership and a bounded matrix of completed observations.
use super::{
    Result,
    measure::{Admission, ObjectIdentity},
    require,
    store::{CompletedCase, Store},
};
use crate::receipt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Row {
    pub index: usize,
    pub completed: CompletedCase,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Matrix {
    pub schema: u32,
    pub command: String,
    pub campaign: String,
    pub policy_sha256: String,
    pub code_sha256: String,
    pub rows: Vec<Row>,
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
        schema: 2,
        command: "calibration-run".into(),
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
            "schema":2, "command":"calibration-run", "outcome":"refused",
            "refusal_class":class, "completed_prefix":matrix,
        }))
        .map_err(|_| "launch-evidence-encoding")?;
        receipt::publish_held(&root, "campaign-failure.json", &bytes)?;
        return Err(class);
    }
    Ok(matrix)
}

// Read only the completed campaign's bounded, protected evidence. This does
// not launch a process, reinterpret a manager result or accept asserted success.
pub(super) fn observation(admission: &Admission, expected_digest: &str) -> Result<Matrix> {
    observation_with(admission, expected_digest, || {})
}
pub(super) fn observation_with(
    admission: &Admission,
    expected_digest: &str,
    after_reads: impl FnOnce(),
) -> Result<Matrix> {
    let policy = admission.policy();
    let root = receipt::sealed_directory(&policy.roots.evidence)?;
    let sealed = receipt::sealed_directory(&policy.roots.sealed)?;
    let path = policy.roots.evidence.join("campaign.json");
    let bytes = receipt::protected_read(&path, 256 * 1024, true)?;
    require(
        crate::identity::hash(&bytes) == expected_digest,
        "campaign-handoff-digest",
    )?;
    let matrix: Matrix = serde_json::from_slice(&bytes).map_err(|_| "campaign-handoff-shape")?;
    require(
        matrix.schema == 2 && matrix.command == "calibration-run",
        "campaign-handoff-version",
    )?;
    require(
        matrix.campaign == policy.campaign
            && matrix.policy_sha256 == admission.policy_sha256()
            && matrix.code_sha256 == admission.code_sha256(),
        "campaign-handoff-identity",
    )?;
    require(
        matrix.rows.len() == policy.cases.len(),
        "campaign-handoff-roster",
    )?;
    let mut invocations = BTreeSet::new();
    for (index, (row, case)) in matrix.rows.iter().zip(&policy.cases).enumerate() {
        let completed = &row.completed;
        require(
            row.index == index
                && completed.case == case.id
                && completed.policy_sha256 == admission.policy_sha256()
                && completed.case_sha256 == admission.cases()[index].sha256
                && completed.invocation.unit == case.generator_unit
                && completed.invocation.image == admission.fixture_image(),
            "campaign-handoff-case",
        )?;
        require(
            invocations.insert(&completed.invocation.id),
            "campaign-handoff-invocation",
        )?;
        let evidence = policy.roots.evidence.join(&case.id);
        let _evidence = receipt::sealed_directory(&evidence)?;
        let completion =
            receipt::protected_read(&evidence.join("completion.json"), 64 * 1024, true)?;
        require(
            crate::identity::hash(&completion) == completed.completion_sha256,
            "campaign-handoff-completion",
        )?;
        let directory = policy.roots.sealed.join(&case.id);
        let _directory = receipt::sealed_directory(&directory)?;
        for ((output, length), stream) in completed
            .outputs
            .iter()
            .zip(completed.sealed_bytes)
            .zip(&case.streams)
        {
            require(
                output.name == stream.output && (1..=policy.limits.sealed_bytes).contains(&length),
                "campaign-handoff-output",
            )?;
            let file = receipt::walk(&directory.join(&output.name), false, true)?;
            require(
                ObjectIdentity::of(&file)? == output.object,
                "campaign-handoff-object",
            )?;
            let content = receipt::read_file(file, policy.limits.sealed_bytes, true)?;
            require(
                content.len() as u64 == length && crate::identity::hash(&content) == output.sha256,
                "campaign-handoff-content",
            )?;
        }
    }
    // Admission bounds all case pairs times the per-output ceiling by the total.
    after_reads();
    for artifact in admission.artifacts() {
        artifact.verify_bytes()?;
    }
    verify_root(admission, &root)?;
    require(
        ObjectIdentity::of(&receipt::sealed_directory(&policy.roots.sealed)?)?
            == ObjectIdentity::of(&sealed)?,
        "campaign-handoff-root",
    )?;
    require(
        receipt::protected_read(&path, 256 * 1024, true)? == bytes,
        "campaign-handoff-changed",
    )?;
    Ok(matrix)
}
