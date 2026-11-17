//! Bind an observation grid to measured campaign completion, never success assertions.
use super::{campaign, measure, policy::ArtifactRole, require};
use crate::record::{Parameters, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub campaign: String,
    pub admitted_owner_uid: u32,
    // The independently protected campaign matrix and calibration retain these
    // references. A supplier changing an analysis view or proposed parameters
    // cannot rewrite that retained evidence (sec:credentialcustody:campaign-operation).
    pub matrix_sha256: String,
    pub policy_sha256: String,
    pub code_sha256: String,
    pub configuration_sha256: String,
    pub parameters_sha256: String,
}
pub struct Sample {
    pub sealed_bytes: u64,
    pub sha256: String,
}
pub struct Binding {
    pub evidence: Evidence,
    pub samples: Vec<Sample>,
}

pub fn bind(record: &Parameters) -> Result<Binding> {
    let admission = measure::observation_admission(&record.campaign.policy)?;
    let policy = admission.policy();
    require(policy.campaign == record.case, "observation-campaign")?;
    separate_roots(record, &policy.roots)?;
    bind_admitted(record, &admission)
}

fn separate_roots(record: &Parameters, roots: &super::policy::Roots) -> Result<()> {
    require(
        roots.paths().iter().all(|root| {
            !record.sealed_root.starts_with(root) && !root.starts_with(&record.sealed_root)
        }),
        "observation-analysis-root",
    )?;
    require(
        roots.paths().iter().all(|root| {
            !record.evidence_root.starts_with(root) && !root.starts_with(&record.evidence_root)
        }),
        "observation-evidence-root",
    )?;
    Ok(())
}

fn bind_admitted(record: &Parameters, admission: &measure::Admission) -> Result<Binding> {
    let policy = admission.policy();
    let matrix = campaign::observation(admission, &record.campaign.matrix_sha256)?;
    for (role, file) in [
        (ArtifactRole::Sealer, &record.identity.files.sealer),
        (ArtifactRole::Parser, &record.identity.files.parser),
        (
            ArtifactRole::Interpreter,
            &record.identity.files.interpreter,
        ),
        (ArtifactRole::Library, &record.identity.files.library),
    ] {
        let resolved = if role == ArtifactRole::Interpreter {
            std::fs::canonicalize(&file.path)
                .map_err(|error| crate::process::io_failure("identity-path", error))?
        } else {
            file.path.clone()
        };
        let declared = policy
            .artifacts
            .iter()
            .find(|declared| declared.role == role && declared.path == resolved)
            .ok_or("observation-artifact")?;
        require(
            admission.artifacts().iter().any(|held| {
                held.id == declared.id && held.role == role && held.sha256 == file.sha256
            }),
            "observation-artifact",
        )?;
    }
    require(
        record.samples.len() == 2 * policy.cases.len(),
        "observation-roster",
    )?;
    let mut used = BTreeSet::new();
    let mut samples = Vec::new();
    for sample in &record.samples {
        let (index, case) = policy
            .cases
            .iter()
            .enumerate()
            .find(|(_, case)| case.id == sample.case)
            .ok_or("observation-case")?;
        let (slot, stream) = case
            .streams
            .iter()
            .enumerate()
            .find(|(_, stream)| stream.name == sample.name)
            .ok_or("observation-stream")?;
        require(used.insert((index, slot)), "observation-output-repeated")?;
        let pattern = if sample.content == record.contents[0] {
            "ascending"
        } else {
            "descending"
        };
        require(
            stream.length == sample.input_length && stream.pattern.id() == pattern,
            "observation-input",
        )?;
        let output = &matrix.rows[index].completed.outputs[slot];
        samples.push(Sample {
            sealed_bytes: matrix.rows[index].completed.sealed_bytes[slot],
            sha256: output.sha256.clone(),
        });
    }
    let configurations: Vec<_> = matrix
        .rows
        .iter()
        .map(|row| {
            (
                &row.completed.case,
                &row.completed.configuration,
                &row.completed.manager_configuration_sha256,
            )
        })
        .collect();
    Ok(Binding {
        evidence: Evidence {
            campaign: policy.campaign.clone(),
            admitted_owner_uid: admission.owner(),
            matrix_sha256: record.campaign.matrix_sha256.clone(),
            policy_sha256: admission.policy_sha256().into(),
            code_sha256: admission.code_sha256().into(),
            configuration_sha256: measure::canonical(
                "custody-campaign-configuration-v2",
                &configurations,
            )?,
            parameters_sha256: measure::canonical("custody-observation-parameters-v3", record)?,
        },
        samples,
    })
}
