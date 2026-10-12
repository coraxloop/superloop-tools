use std::ffi::OsString;
use std::io;

use crate::config::{
    LOOP_KEYGEN_HELP, STAFF_PROVISION_HELP, StaffAction, parse_loop_args, parse_staff_args,
};
use crate::error::{ProvisionError, publication_error};
use crate::loop_keygen::run_loop_keygen;
use crate::runner::Runner;
use crate::staff::{run_admit, run_check, run_create};

fn publish_failure<E: io::Write>(program: &str, failure: &ProvisionError, error: &mut E) -> u8 {
    let status = failure.status();
    let diagnostic = failure.diagnostic(program);
    if error.write_all(diagnostic.as_bytes()).is_err() {
        1
    } else {
        status
    }
}

/// Run `loop-keygen` with an injected runner and owned output streams.
#[must_use]
pub fn loop_keygen_entry<I, A, R, W, E>(
    arguments: I,
    runner: &mut R,
    output: &mut W,
    error: &mut E,
) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
    R: Runner,
    W: io::Write,
    E: io::Write,
{
    let result = match parse_loop_args(arguments) {
        Ok(None) => output
            .write_all(LOOP_KEYGEN_HELP.as_bytes())
            .map_err(publication_error),
        Ok(Some(options)) => run_loop_keygen(&options, runner, output),
        Err(failure) => Err(failure),
    };
    match result {
        Ok(()) => 0,
        Err(failure) => publish_failure("account keygen", &failure, error),
    }
}

/// Run `staff-provision` with an injected runner and owned streams.
#[must_use]
pub fn staff_provision_entry<I, A, R, N, W, E>(
    arguments: I,
    runner: &mut R,
    input: &mut N,
    output: &mut W,
    error: &mut E,
) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
    R: Runner,
    N: io::Read,
    W: io::Write,
    E: io::Write,
{
    let result = match parse_staff_args(arguments) {
        Ok(None) => output
            .write_all(STAFF_PROVISION_HELP.as_bytes())
            .map_err(publication_error),
        Ok(Some(options)) => match &options.action {
            StaffAction::Check { account } => run_check(&options.alias, account, runner, output),
            StaffAction::Create {
                account,
                class,
                uid,
                key_paths,
                showcase,
                dry_run,
            } => run_create(
                &options.alias,
                account,
                *class,
                *uid,
                key_paths,
                showcase.as_deref(),
                *dry_run,
                runner,
                output,
            ),
            StaffAction::Admit {
                account,
                mirror_showcase,
                key_paths,
                dry_run,
            } => run_admit(
                &options.alias,
                account,
                mirror_showcase.as_deref(),
                key_paths,
                *dry_run,
                runner,
                input,
                output,
            ),
        },
        Err(failure) => Err(failure),
    };
    match result {
        Ok(()) => 0,
        Err(failure) => publish_failure("account", &failure, error),
    }
}
