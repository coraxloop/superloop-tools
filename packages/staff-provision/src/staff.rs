use std::io;
use std::path::PathBuf;

use crate::config::AccountClass;
use crate::error::{ProvisionError, publication_error};
use crate::keys::{load_admit_keys, load_key_files, merge_keys};
use crate::planner::{
    create_setup_plan, execute_mutations, plan_key_mutation, surface_completion_plan,
    validate_create_prestate, verify_created_state,
};
use crate::probe::{planned_post_create_probes, probe_account, sudo_preflight, uid_owner};
use crate::report::{write_account_report, write_merge_report, write_registry};
use crate::runner::{Runner, print_plan};
use crate::state::{account_home, guard_account};

pub(crate) fn run_check<R: Runner, W: io::Write>(
    alias: &str,
    account: &str,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    sudo_preflight(alias, account, runner, output)?;
    let state = probe_account(alias, account, runner, output)?;
    write_account_report(&state, runner, output)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn run_create<R: Runner, W: io::Write>(
    alias: &str,
    account: &str,
    class: AccountClass,
    uid: u32,
    key_paths: &[PathBuf],
    showcase: Option<&str>,
    dry_run: bool,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    let keys = load_key_files(key_paths)?;
    sudo_preflight(alias, account, runner, output)?;
    let target = probe_account(alias, account, runner, output)?;
    let owner = uid_owner(alias, uid, runner, output)?;
    validate_create_prestate(&target, uid, owner.as_deref())?;
    let showcase_plan = if let Some(showcase_name) = showcase {
        let state = probe_account(alias, showcase_name, runner, output)?;
        Some((state.clone(), plan_key_mutation(alias, &state, &keys)?))
    } else {
        None
    };
    let preview = create_setup_plan(alias, account, class, uid, &keys);
    if dry_run {
        print_plan(&preview[..3], output)?;
        print_plan(&planned_post_create_probes(alias, account), output)?;
        print_plan(&preview[3..], output)?;
        if let Some((_state, plan)) = &showcase_plan {
            print_plan(&plan.commands, output)?;
        }
        writeln!(
            output,
            "[account] dry-run complete; zero mutations executed"
        )
        .map_err(publication_error)?;
        return Ok(());
    }
    execute_mutations(runner, &preview[..3], output)?;
    let created = probe_account(alias, account, runner, output)?;
    verify_created_state(&created, uid, &account_home(account))?;
    let surface = surface_completion_plan(alias, &created, class, &keys)?;
    execute_mutations(runner, &surface, output)?;
    if let Some((state, plan)) = &showcase_plan {
        execute_mutations(runner, &plan.commands, output)?;
        write_merge_report(&state.name, &plan.merge, output)?;
    }
    let final_state = probe_account(alias, account, runner, output)?;
    verify_created_state(&final_state, uid, &account_home(account))?;
    if let Some((state, _plan)) = &showcase_plan {
        let final_showcase = probe_account(alias, &state.name, runner, output)?;
        guard_account(&final_showcase).map_err(|error| {
            ProvisionError::runtime(
                "critical_divergence",
                format!(
                    "mutated showcase {} failed {}: {}",
                    state.name, error.class, error.detail
                ),
            )
        })?;
    }
    write_account_report(&final_state, runner, output)?;
    let desired_keys = merge_keys("", &keys).content;
    write_registry(account, uid, class, &desired_keys, output)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn run_admit<R: Runner, I: io::Read, W: io::Write>(
    alias: &str,
    account: &str,
    mirror_showcase: Option<&str>,
    key_paths: &[PathBuf],
    dry_run: bool,
    runner: &mut R,
    input: &mut I,
    output: &mut W,
) -> Result<(), ProvisionError> {
    let keys = load_admit_keys(key_paths, input)?;
    sudo_preflight(alias, account, runner, output)?;
    let target = probe_account(alias, account, runner, output)?;
    let target_plan = plan_key_mutation(alias, &target, &keys)?;
    let mirror = if let Some(showcase_name) = mirror_showcase {
        let state = probe_account(alias, showcase_name, runner, output)?;
        Some((state.clone(), plan_key_mutation(alias, &state, &keys)?))
    } else {
        None
    };
    if dry_run {
        print_plan(&target_plan.commands, output)?;
        if let Some((_state, plan)) = &mirror {
            print_plan(&plan.commands, output)?;
        }
        write_merge_report(account, &target_plan.merge, output)?;
        if let Some((state, plan)) = &mirror {
            write_merge_report(&state.name, &plan.merge, output)?;
        }
        writeln!(
            output,
            "[account] dry-run complete; zero mutations executed"
        )
        .map_err(publication_error)?;
        return Ok(());
    }
    execute_mutations(runner, &target_plan.commands, output)?;
    if let Some((_state, plan)) = &mirror {
        execute_mutations(runner, &plan.commands, output)?;
    }
    write_merge_report(account, &target_plan.merge, output)?;
    if let Some((state, plan)) = &mirror {
        write_merge_report(&state.name, &plan.merge, output)?;
    }
    let final_state = probe_account(alias, account, runner, output)?;
    guard_account(&final_state).map_err(|error| {
        ProvisionError::runtime(
            "critical_divergence",
            format!(
                "mutated account {account} failed {}: {}",
                error.class, error.detail
            ),
        )
    })?;
    if let Some((state, _plan)) = &mirror {
        let final_showcase = probe_account(alias, &state.name, runner, output)?;
        guard_account(&final_showcase).map_err(|error| {
            ProvisionError::runtime(
                "critical_divergence",
                format!(
                    "mutated showcase {} failed {}: {}",
                    state.name, error.class, error.detail
                ),
            )
        })?;
    }
    write_account_report(&final_state, runner, output)?;
    let class = if mirror_showcase.is_some() {
        AccountClass::Loop
    } else {
        AccountClass::Human
    };
    write_registry(
        account,
        final_state.uid.unwrap_or(0),
        class,
        &target_plan.merge.content,
        output,
    )
}
