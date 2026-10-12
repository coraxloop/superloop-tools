use std::env;
use std::io::{self, Read as _, Write as _};
use std::time::Instant;

use crate::{
    HookInputError, InvocationOutput, MAX_HOOK_INPUT_BYTES, Mode, execute_invocation,
    execute_non_hook_invocation, last_resort_deny,
};

/// Run the bounded permission hook command with the current process streams.
#[must_use]
pub fn execute() -> u8 {
    let started = Instant::now();
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let reads_hook_input = matches!(arguments.as_slice(), [command] if command == "hook");
    let mut input = Vec::new();
    let input_error = if reads_hook_input {
        let stdin = io::stdin();
        let mut bounded = stdin.lock().take(MAX_HOOK_INPUT_BYTES + 1);
        match bounded.read_to_end(&mut input) {
            Ok(_) if input.len() as u64 > MAX_HOOK_INPUT_BYTES => Some(HookInputError::TooLarge),
            Ok(_) => None,
            Err(_error) => Some(HookInputError::ReadFailure),
        }
    } else {
        None
    };
    let hook_input = input_error.map_or_else(|| Ok(input.as_slice()), Err);
    let output = if reads_hook_input {
        let nesting_token = env::var_os("PERMISSION_TRIAGE_NESTED");
        let mut journal = crate::journal::RoutedJournal::from_environment();
        Mode::from_environment().map_or_else(invalid_mode_output, |mode| {
            execute_invocation(
                mode,
                &arguments,
                hook_input,
                nesting_token.as_deref(),
                &started,
                &mut journal,
            )
        })
    } else {
        execute_non_hook_invocation(&arguments)
    };
    publish(&output)
}

fn invalid_mode_output() -> InvocationOutput {
    InvocationOutput::fail_closed(
        "infrastructure-failure: permission triage mode is missing or malformed; no policy judgment was made",
    )
}

fn publish(output: &InvocationOutput) -> u8 {
    if !output.stdout().is_empty() {
        let mut stdout = io::stdout().lock();
        if stdout.write_all(output.stdout()).is_err() || stdout.flush().is_err() {
            write_stderr(last_resort_deny());
            return 2;
        }
    }
    if !output.stderr().is_empty() {
        write_stderr(output.stderr());
    }
    output.status()
}

fn write_stderr(bytes: &[u8]) {
    let mut stderr = io::stderr().lock();
    if stderr.write_all(bytes).is_ok() && stderr.flush().is_err() {}
}
