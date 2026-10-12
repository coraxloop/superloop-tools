//! Remove an exercise client's own probe and name stale labeled probes.

use crate::build;
use crate::error::LaneError;
use nix::unistd::Uid;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

const LABEL: &str = "org.superloop.probe";
const IDENTITY_LABEL: &str = "org.superloop.probe.identity";
const CLIENT_BOUND_SECONDS: u64 = 125;

pub(super) fn identity(loop_name: &str, run: &str) -> String {
    format!("{loop_name}/{run}")
}

pub(super) fn identity_option(loop_name: &str, run: &str) -> String {
    format!("--label={IDENTITY_LABEL}={}", identity(loop_name, run))
}

pub(super) struct ProbeSurvivors {
    pub rows: Vec<Value>,
    pub total: usize,
}

pub(super) fn name<'a>(words: &'a [String], prefix: &str) -> Result<&'a str, LaneError> {
    words
        .iter()
        .find_map(|word| word.strip_prefix("--name="))
        .filter(|name| {
            name.starts_with(prefix)
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| LaneError::input("exercise-probe", "probe name is absent or invalid"))
}

/// Remove only the probe whose exact name and probe label match this client.
///
/// # Errors
///
/// Refuses an unverified Podman program, malformed identity, or failed cleanup.
pub(super) fn remove(
    program: &Path,
    owner_home: &Path,
    environment: &BTreeMap<String, String>,
    name: &str,
    kind: &str,
    loop_name: &str,
    run: &str,
) -> Result<(), LaneError> {
    crate::pinned::owner_executable(program, Uid::effective().as_raw())?;
    let output = build::run_checked(
        program,
        vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("label={LABEL}={kind}"),
            "--filter".into(),
            format!("label={IDENTITY_LABEL}={}", identity(loop_name, run)),
            "--filter".into(),
            format!("name=^{name}$"),
            "--format".into(),
            "{{.ID}}".into(),
        ],
        environment,
        owner_home,
        30,
        "exercise-probe-list",
    )?;
    let mut ids = output.lines();
    let Some(id) = ids.next() else {
        return Ok(());
    };
    if ids.next().is_some() || !valid_id(id) {
        return Err(LaneError::input(
            "exercise-probe",
            "probe lookup returned an invalid identity",
        ));
    }
    build::run_checked(
        program,
        vec![
            "rm".into(),
            "--force".into(),
            "--ignore".into(),
            "--time=0".into(),
            id.into(),
        ],
        environment,
        owner_home,
        30,
        "exercise-probe-remove",
    )?;
    Ok(())
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Find probes older than the client's run and cleanup bound for one run.
///
/// # Errors
///
/// Refuses an unverified program, failed listing, or malformed bounded output.
pub(super) fn survivors(
    program: &Path,
    owner_home: &Path,
    loop_name: &str,
    run: &str,
) -> Result<ProbeSurvivors, LaneError> {
    crate::pinned::owner_executable(program, Uid::effective().as_raw())?;
    let output = build::run_checked(
        program,
        survivor_argv(loop_name, run),
        &build::podman_environment(owner_home)?,
        owner_home,
        30,
        "reaping-probe-list",
    )?;
    parse_survivors(&output, &identity(loop_name, run))
}

fn survivor_argv(loop_name: &str, run: &str) -> Vec<String> {
    vec![
        "ps".into(),
        "--all".into(),
        "--no-trunc".into(),
        "--filter".into(),
        format!("label={LABEL}"),
        "--filter".into(),
        format!("label={IDENTITY_LABEL}={}", identity(loop_name, run)),
        "--filter".into(),
        format!("until={CLIENT_BOUND_SECONDS}s"),
        "--format".into(),
        "{{.ID}}\t{{.Names}}\t{{.CreatedHuman}}\t{{.Label \"org.superloop.probe\"}}\t{{.Label \"org.superloop.probe.identity\"}}".into(),
    ]
}

fn parse_survivors(output: &str, identity: &str) -> Result<ProbeSurvivors, LaneError> {
    let mut rows = Vec::new();
    let mut total = 0;
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5
            || !valid_id(fields[0])
            || fields[1].is_empty()
            || fields[2].is_empty()
            || fields[3].is_empty()
            || fields[4].is_empty()
        {
            return Err(LaneError::input(
                "reaping-probe-list",
                "probe listing has an invalid row",
            ));
        }
        if fields[4] != identity {
            continue;
        }
        total += 1;
        if rows.len() < 64 {
            rows.push(json!({"id":fields[0],"label":format!("{LABEL}={}",fields[3]),"identity":fields[4],"container_name":fields[1],"age":fields[2]}));
        }
    }
    Ok(ProbeSurvivors { rows, total })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:stale-probe-list-names-label-container-and-age´
    #[test]
    fn stale_probe_list_names_label_container_and_age() {
        let line = format!(
            "{}\tsuperloop-mount-probe-fixture\t2 minutes ago\tmounts\talpha/R\n",
            "a".repeat(64)
        );
        let survivors = parse_survivors(&line, "alpha/R").expect("labeled probe");
        assert_eq!(survivors.total, 1);
        assert_eq!(survivors.rows[0]["label"], "org.superloop.probe=mounts");
        assert_eq!(survivors.rows[0]["identity"], "alpha/R");
        assert_eq!(
            survivors.rows[0]["container_name"],
            "superloop-mount-probe-fixture"
        );
        assert_eq!(survivors.rows[0]["age"], "2 minutes ago");
        assert_eq!(
            parse_survivors(&line, "alpha/other")
                .expect("another run")
                .total,
            0
        );
        assert!(parse_survivors("short row", "alpha/R").is_err());
    }

    /// ´test:unit:stale-probe-list-bounds-names-and-keeps-total´
    #[test]
    fn stale_probe_list_bounds_names_and_keeps_total() {
        let line = format!(
            "{}\tprobe\t3 minutes ago\tresources\talpha/R\n",
            "a".repeat(64)
        );
        let survivors = parse_survivors(&line.repeat(65), "alpha/R").expect("many probes");
        assert_eq!(survivors.total, 65);
        assert_eq!(survivors.rows.len(), 64);
    }

    /// ´test:unit:stale-probe-list-waits-for-client-cleanup-and-scopes-run´
    #[test]
    fn stale_probe_list_waits_for_client_cleanup_and_scopes_run() {
        let words = survivor_argv("alpha", "R");
        assert!(words.iter().any(|word| word == "until=125s"));
        assert!(
            words
                .iter()
                .any(|word| word == "label=org.superloop.probe.identity=alpha/R")
        );
        assert!(
            words
                .iter()
                .all(|word| !word.contains("org.superloop.run="))
        );
    }
}
