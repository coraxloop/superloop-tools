//! Neutral gateway proposal and answer schemas. Admission and execution remain
//! with the gateway service; this module grants neither filesystem authority
//! nor permission to execute an argument vector.

use serde_json::Value;

use crate::{Kind, exact, hex};

fn name(value: &Value) -> bool {
    value.as_str().is_some_and(|name| {
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    })
}

fn body(value: &Value) -> bool {
    let proposal = &value["proposal"];
    exact(
        value,
        &[
            "schema",
            "loop_name",
            "gateway_id",
            "registration_digest",
            "proposal",
        ],
    ) && value["schema"] == 1
        && name(&value["loop_name"])
        && value["gateway_id"]
            .as_str()
            .is_some_and(|value| hex(value, 64))
        && value["registration_digest"]
            .as_str()
            .is_some_and(|value| hex(value, 64))
        && exact(
            proposal,
            &[
                "schema",
                "lane",
                "seq",
                "argv",
                "reason",
                "queued_unix_ms",
                "timeout_seconds",
            ],
        )
        && proposal["schema"] == 1
        && name(&proposal["lane"])
        && proposal["seq"].as_u64().is_some_and(|seq| seq > 0)
        && proposal["argv"].as_array().is_some_and(|argv| {
            !argv.is_empty()
                && argv
                    .iter()
                    .all(|word| word.as_str().is_some_and(|word| !word.contains('\0')))
                && argv[0].as_str().is_some_and(|word| !word.is_empty())
        })
        && proposal["reason"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty())
        && proposal["queued_unix_ms"].as_u64().is_some()
        && proposal["timeout_seconds"]
            .as_u64()
            .is_some_and(|timeout| timeout > 0)
}

fn answer(_: &Value, value: &Value) -> bool {
    match value["outcome"].as_str() {
        Some("deny" | "abandon") => exact(value, &["outcome"]),
        Some("approve") => {
            exact(value, &["outcome"])
                || (exact(value, &["outcome", "promote"])
                    && (value["promote"] == true || name(&value["promote"])))
        }
        _ => false,
    }
}

/// The shared schema for a proposal awaiting a service-owned result.
#[must_use]
pub const fn kind() -> Kind<'static> {
    Kind {
        name: "gateway-proposal",
        service: true,
        body,
        answer,
    }
}
