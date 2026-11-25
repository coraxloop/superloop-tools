//! Protected workspace policy bodies, read anew for each workspace request.

use std::os::fd::OwnedFd;

use execute_command::workspace::{Blacklist, QuickPolicy, canonical_digest};

use super::{WorkspaceRequest, transport};
use crate::error::LaneError;

fn differs(file: &str, detail: impl std::fmt::Display) -> LaneError {
    LaneError::input(
        "door-workspace-context-differs",
        format!("{file}: {detail}; publish the matching workspace policy and grant"),
    )
}

fn read_table<T: serde::de::DeserializeOwned>(
    directory: &OwnedFd,
    owner: u32,
    file: &str,
) -> Result<T, LaneError> {
    let bytes = transport::read_owner_leaf(directory, file, owner)
        .map_err(|error| differs(file, error.line()))?;
    serde_json::from_slice(&bytes).map_err(|error| differs(file, error))
}

pub(super) fn digests(directory: &OwnedFd, owner: u32) -> Result<(String, String), LaneError> {
    let quick: QuickPolicy = read_table(directory, owner, "workspace-quick-policy.json")?;
    let blacklist: Blacklist = read_table(directory, owner, "workspace-blacklist.json")?;
    let quick = canonical_digest(&quick)
        .map_err(|error| differs("workspace-quick-policy.json", error.detail))?;
    let blacklist = canonical_digest(&blacklist)
        .map_err(|error| differs("workspace-blacklist.json", error.detail))?;
    Ok((quick, blacklist))
}

pub(super) fn read(
    directory: &OwnedFd,
    owner: u32,
    request: &WorkspaceRequest,
) -> Result<(QuickPolicy, Blacklist), LaneError> {
    let workers = transport::read_owner_leaf(directory, "workers.toml", owner)
        .map_err(|error| differs("workers.toml", error.line()))?;
    let workers = std::str::from_utf8(&workers).map_err(|error| differs("workers.toml", error))?;
    let workers: toml::Table =
        toml::from_str(workers).map_err(|error| differs("workers.toml", error))?;
    let published = workers
        .get("workspace_policy")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| differs("workers.toml", "workspace_policy is absent"))?;
    let quick: QuickPolicy = read_table(directory, owner, "workspace-quick-policy.json")?;
    let blacklist: Blacklist = read_table(directory, owner, "workspace-blacklist.json")?;
    for (file, field, actual, expected) in [
        (
            "workspace-quick-policy.json",
            "quick_policy_digest",
            canonical_digest(&quick)
                .map_err(|error| differs("workspace-quick-policy.json", error.detail))?,
            &request.grant().quick_policy_digest,
        ),
        (
            "workspace-blacklist.json",
            "blacklist_digest",
            canonical_digest(&blacklist)
                .map_err(|error| differs("workspace-blacklist.json", error.detail))?,
            &request.grant().blacklist_digest,
        ),
    ] {
        if &actual != expected
            || published.get(field).and_then(toml::Value::as_str) != Some(expected)
        {
            return Err(differs(
                file,
                format!("digest differs from workers.toml or the grant ({field})"),
            ));
        }
    }
    Ok((quick, blacklist))
}
