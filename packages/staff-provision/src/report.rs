use std::io;

use crate::config::AccountClass;
use crate::error::{ProvisionError, publication_error};
use crate::keys::MergeResult;
use crate::runner::{CommandSpec, Runner, invoke};
use crate::state::{AccountState, SurfaceState};

fn write_surface<W: io::Write>(
    output: &mut W,
    label: &str,
    surface: &SurfaceState,
) -> Result<(), ProvisionError> {
    if surface.exists {
        writeln!(
            output,
            "  {label}: present kind={} mode={:04o} uid={} gid={}",
            surface.kind,
            surface.mode.unwrap_or(0),
            surface.uid.unwrap_or(0),
            surface.gid.unwrap_or(0)
        )
    } else {
        writeln!(output, "  {label}: absent")
    }
    .map_err(publication_error)
}

pub(crate) fn write_account_report<R: Runner, W: io::Write>(
    state: &AccountState,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    writeln!(output, "[account] account={}", state.name).map_err(publication_error)?;
    writeln!(
        output,
        "  exists: {}",
        if state.exists { "yes" } else { "no" }
    )
    .map_err(publication_error)?;
    if !state.exists {
        return Ok(());
    }
    writeln!(output, "  uid: {}", state.uid.unwrap_or(0)).map_err(publication_error)?;
    let groups = state
        .groups
        .iter()
        .map(|group| {
            if group == "wheel" {
                String::from("wheel[ADMIN]")
            } else {
                group.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    writeln!(output, "  groups: {groups}").map_err(publication_error)?;
    match (state.mapping.as_deref(), state.default_mapping.as_deref()) {
        (Some(mapping), _) => writeln!(output, "  selinux-login: {mapping} (explicit)"),
        (None, Some(mapping)) => writeln!(
            output,
            "  selinux-login: __default__ {mapping} (no explicit row)"
        ),
        (None, None) => writeln!(
            output,
            "  selinux-login: missing (no explicit or __default__ row)"
        ),
    }
    .map_err(publication_error)?;
    writeln!(
        output,
        "  home: {}",
        state.home.as_deref().unwrap_or("missing")
    )
    .map_err(publication_error)?;
    write_surface(output, ".ssh/", &state.ssh)?;
    write_surface(output, "authorized_keys", &state.authorized_keys)?;
    write_surface(output, "git/", &state.git)?;
    write_surface(output, "loops/", &state.loops)?;
    write_surface(output, "correspondence/", &state.correspondence)?;
    writeln!(output, "  authorized-key fingerprints:").map_err(publication_error)?;
    let installed = state
        .authorized_text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>();
    if installed.is_empty() {
        writeln!(output, "    (none)").map_err(publication_error)?;
    }
    for (index, line) in installed.iter().enumerate() {
        let command = CommandSpec::local(
            format!("fingerprint-{}-{}", state.name, index + 1),
            vec![
                String::from("ssh-keygen"),
                String::from("-lf"),
                String::from("/dev/stdin"),
            ],
            format!("{line}\n").into_bytes(),
            false,
        );
        let result = invoke("account", runner, &command, output)?;
        if result.status == 0 {
            let fingerprint = String::from_utf8_lossy(&result.stdout);
            writeln!(output, "    {}: {}", index + 1, fingerprint.trim_end())
                .map_err(publication_error)?;
        } else {
            writeln!(
                output,
                "    {}: unavailable (ssh-keygen exit {})",
                index + 1,
                result.status
            )
            .map_err(publication_error)?;
        }
    }
    Ok(())
}

pub(crate) fn write_merge_report<W: io::Write>(
    account: &str,
    merge: &MergeResult,
    output: &mut W,
) -> Result<(), ProvisionError> {
    for line in &merge.lines {
        writeln!(
            output,
            "[account] account={account} {} {} line {}: {}",
            if line.added { "added" } else { "skipped" },
            line.source,
            line.number,
            line.text
        )
        .map_err(publication_error)?;
    }
    Ok(())
}

pub(crate) fn write_registry<W: io::Write>(
    account: &str,
    uid: u32,
    class: AccountClass,
    authorized_keys: &str,
    output: &mut W,
) -> Result<(), ProvisionError> {
    writeln!(output, "[account] bootstrap registry block:")
        .and_then(|()| writeln!(output, "accounts/{account}/uid:"))
        .and_then(|()| writeln!(output, "{uid}"))
        .and_then(|()| writeln!(output, "accounts/{account}/class:"))
        .and_then(|()| writeln!(output, "{}", class.as_str()))
        .and_then(|()| writeln!(output, "accounts/{account}/authorized_keys:"))
        .map_err(publication_error)?;
    output
        .write_all(authorized_keys.as_bytes())
        .map_err(publication_error)?;
    if !authorized_keys.is_empty() && !authorized_keys.ends_with('\n') {
        writeln!(output).map_err(publication_error)?;
    }
    Ok(())
}
