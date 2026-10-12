use std::io::{self, Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use permission_triage::{CallerRole, Journal};
use request_core::Error;
use serde_json::{Value, json};

const CAP: u64 = 64 * 1024 * 1024;

fn failure(error: impl std::fmt::Display) -> Error {
    Error::new("requests-helper", error.to_string())
}

fn read(mut input: impl io::Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() as u64 > CAP {
        return Err(failure("input exceeds cap"));
    }
    Ok(bytes)
}

fn execute(arguments: &[String]) -> Result<Value, Error> {
    if let [flag, mode] = arguments
        && flag == "--registry-validate"
    {
        return registry_snapshot(mode, &read(io::stdin().lock())?);
    }
    if let [flag, action] = arguments
        && flag == "--snapshot"
    {
        return permission_triage::requests::snapshot(action, &read(io::stdin().lock())?);
    }
    if arguments
        .first()
        .is_some_and(|flag| flag.starts_with("--owner-"))
    {
        return owner(arguments);
    }
    let [action, flag, loop_name, rest @ ..] = arguments else {
        return Err(failure("expected COMMAND --loop NAME"));
    };
    if flag != "--loop" {
        return Err(failure("expected --loop NAME"));
    }
    let (id, pending) = match (action.as_str(), rest) {
        ("status" | "list" | "triage" | "adjudicate", []) => (None, false),
        ("status" | "list", [flag]) if flag == "--pending" => (None, true),
        ("review", [id]) => (Some(id.as_str()), false),
        _ => {
            return Err(failure(
                "status|list [--pending], triage, review ID, adjudicate",
            ));
        }
    };
    let reading = matches!(action.as_str(), "status" | "list");
    let (registry, directory, root) = configured(loop_name, reading)?;
    let scope = permission_triage::request::Scope::Loop;
    if reading {
        return Journal::from_registered_descriptor_for_review(directory, &root, scope)
            .requests(action, pending);
    }
    let journal = Journal::from_registered_descriptor(
        directory,
        &root,
        scope,
        permission_triage::journal::RootShape::Private,
    )
    .map_err(failure)?;
    let caller = caller(&registry)?;
    let document = if matches!(action.as_str(), "triage" | "adjudicate") {
        Some(serde_json::from_slice(&read(io::stdin().lock())?).map_err(failure)?)
    } else {
        None
    };
    journal.requests(&caller, action, document.as_ref(), id, pending)
}

// Validate the caller's descriptor-pinned snapshot without opening any pathname.
fn registry_snapshot(mode: &str, input: &[u8]) -> Result<Value, Error> {
    if !matches!(mode, "parse" | "deployment") {
        return Err(failure("registry validation mode"));
    }
    let texts: std::collections::BTreeMap<String, Vec<u8>> =
        serde_json::from_slice(input).map_err(failure)?;
    if texts.len() > 1024 || texts.values().any(|bytes| bytes.len() > 65_536) {
        return Err(failure("registry snapshot exceeds reader limits"));
    }
    let mut listing = String::new();
    for name in texts.keys() {
        listing.push_str(name);
        listing.push('\n');
    }
    if listing.len() > 65_536 || texts.keys().any(|name| name.contains(['\n', '\r'])) {
        return Err(failure("registry listing exceeds reader limits"));
    }
    let parsed = permission_triage::parse_registry(listing.as_bytes(), &texts);
    if parsed.entries().len() != texts.len() {
        return Err(failure(
            "incomplete registry entry under the helper's parser",
        ));
    }
    if mode == "deployment" {
        parsed
            .validate_deployment_structure(Some(
                permission_triage::role::effective_uid().map_err(failure)?,
            ))
            .map_err(failure)?;
    }
    Ok(
        json!({"schema":1,"entries":parsed.entries().iter().map(|entry| json!({
        "name":entry.name(),"state_root":entry.state_root(),"home":entry.home()
    })).collect::<Vec<_>>()}),
    )
}

fn configured(
    loop_name: &str,
    reading: bool,
) -> Result<
    (
        permission_triage::Registry,
        std::fs::File,
        std::path::PathBuf,
    ),
    Error,
> {
    let registry = permission_triage::load_registry(std::env::var_os(
        permission_triage::role::LOOP_REGISTRY_VARIABLE,
    ))
    .map_err(failure)?
    .ok_or_else(|| failure("registered collection requires loop registry"))?;
    if reading {
        registry.validate_deployment_for_review()
    } else {
        registry.validate_deployment()
    }
    .map_err(failure)?;
    let mut entries = registry
        .entries()
        .iter()
        .filter(|entry| entry.name() == loop_name);
    let entry = entries
        .next()
        .filter(|_| entries.next().is_none())
        .ok_or_else(|| failure("select exactly one registered loop"))?;
    let directory = if reading {
        entry.validated_state_root_for_review()
    } else {
        entry.validated_state_root()
    }
    .map_err(failure)?;
    let root = entry
        .state_root()
        .ok_or_else(|| failure("registered root absent"))?
        .to_path_buf();
    Ok((registry, directory, root))
}

fn owner(arguments: &[String]) -> Result<Value, Error> {
    let (phase, action, loop_name) = match arguments {
        [phase, flag, name] if phase == "--owner-read" && flag == "--loop" => {
            (phase.as_str(), "", name)
        }
        [phase, action, flag, name]
            if matches!(phase.as_str(), "--owner-preview" | "--owner-commit")
                && flag == "--loop" =>
        {
            (phase.as_str(), action.as_str(), name)
        }
        _ => return Err(failure("owner protocol arguments")),
    };
    let commit = phase == "--owner-commit";
    let (registry, directory, root) = configured(loop_name, !commit)?;
    let scope = permission_triage::request::Scope::Loop;
    if phase == "--owner-read" {
        return serde_json::to_value(
            Journal::from_registered_descriptor_for_review(directory, &root, scope).owner_read()?,
        )
        .map_err(failure);
    }
    let caller = if std::env::var_os("PERMISSION_TRIAGE_REQUEST_CONTEXT").is_some() {
        caller(&registry)?
    } else {
        CallerRole::Unknown
    };
    let input = read(io::stdin().lock())?;
    let envelope: Value = serde_json::from_slice(&input).map_err(failure)?;
    if envelope["records"].as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            row["kind"] == "gateway-proposal" && row["body"]["loop_name"] != loop_name.as_str()
        })
    }) {
        return Err(failure("gateway filing names another loop"));
    }
    if !commit {
        let journal = Journal::from_registered_descriptor_for_review(directory, &root, scope);
        return journal.owner_preview(&caller, action, &input);
    }
    let journal = Journal::from_registered_descriptor(
        directory,
        &root,
        scope,
        permission_triage::journal::RootShape::Private,
    )
    .map_err(failure)?;
    journal.owner_transaction(&caller, action, &input, true)
}

fn caller(registry: &permission_triage::Registry) -> Result<CallerRole, Error> {
    let context = std::env::var_os("PERMISSION_TRIAGE_REQUEST_CONTEXT")
        .ok_or_else(|| failure("PERMISSION_TRIAGE_REQUEST_CONTEXT is unset"))?;
    if !Path::new(&context).is_absolute() {
        return Err(failure("caller context path must be absolute"));
    }
    let bytes = read(std::fs::File::open(context).map_err(failure)?)?;
    let permission_triage::DecodeResult::Decoded(request) =
        permission_triage::decode_request(&bytes)
    else {
        return Err(failure("invalid caller context"));
    };
    let uid = permission_triage::role::effective_uid().map_err(failure)?;
    Ok(permission_triage::resolve_role(
        Some(registry),
        uid,
        request.session_id(),
        request.cwd(),
        request.transcript_path(),
        request.agent_id_truthy(),
    ))
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("requests-helper", env!("CARGO_PKG_VERSION"), None);
    let result = execute(&std::env::args().skip(1).collect::<Vec<_>>());
    match result {
        Ok(value) => {
            if writeln!(io::stdout().lock(), "{value}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            let _written = writeln!(
                io::stderr().lock(),
                "{}",
                json!({"class":error.class,"detail":error.detail})
            );
            ExitCode::from(2)
        }
    }
}
