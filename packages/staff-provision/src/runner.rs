use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{ProvisionError, publication_error};

fn quote_remote_argument(argument: &str) -> String {
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('\'');
    quoted.push_str(&argument.replace('\'', "'\\''"));
    quoted.push('\'');
    quoted
}

/// Exact external command request passed to a runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    /// Human-readable step identity.
    pub label: String,
    /// Exact local argv, including `ssh` for every remote command.
    pub argv: Vec<String>,
    /// Bytes supplied on standard input.
    pub input: Vec<u8>,
    /// Whether this command changes remote or local durable state.
    pub mutation: bool,
    /// Whether this command executes remotely.
    pub remote: bool,
    /// Whether the remote command passes through `sudo -n`.
    pub privileged: bool,
}

impl CommandSpec {
    pub(crate) fn local(
        label: impl Into<String>,
        argv: Vec<String>,
        input: Vec<u8>,
        mutation: bool,
    ) -> Self {
        Self {
            label: label.into(),
            argv,
            input,
            mutation,
            remote: false,
            privileged: false,
        }
    }

    pub(crate) fn remote(
        alias: &str,
        label: impl Into<String>,
        privileged: bool,
        arguments: impl IntoIterator<Item = String>,
        input: Vec<u8>,
        mutation: bool,
    ) -> Self {
        let mut argv = vec![String::from("ssh"), alias.to_owned()];
        if privileged {
            argv.extend(
                [String::from("sudo"), String::from("-n")]
                    .into_iter()
                    .map(|argument| quote_remote_argument(&argument)),
            );
        }
        argv.extend(
            arguments
                .into_iter()
                .map(|argument| quote_remote_argument(&argument)),
        );
        Self {
            label: label.into(),
            argv,
            input,
            mutation,
            remote: true,
            privileged,
        }
    }
}

/// Captured command result and its measured wall duration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit status, with signal exits normalized to one.
    pub status: i32,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Monotonic wall duration.
    pub wall: Duration,
}

/// Command-spawn failure retaining the measured wall duration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunError {
    /// Stable I/O detail.
    pub detail: String,
    /// Monotonic wall duration before failure.
    pub wall: Duration,
}

/// Injectable command boundary used by both binaries and all tests.
pub trait Runner {
    /// Execute one exact command request.
    ///
    /// # Errors
    ///
    /// Returns a timed spawn, standard-input, or wait failure.
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RunError>;
}

/// Real `std::process` runner.
#[derive(Default)]
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(&mut self, request: &CommandSpec) -> Result<CommandOutput, RunError> {
        let started = Instant::now();
        let Some(program) = request.argv.first() else {
            return Err(RunError {
                detail: String::from("empty argv"),
                wall: started.elapsed(),
            });
        };
        let mut command = Command::new(program);
        command
            .args(&request.argv[1..])
            .env("LC_ALL", "C")
            .stdin(if request.input.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| RunError {
            detail: error.to_string(),
            wall: started.elapsed(),
        })?;
        if !request.input.is_empty() {
            let write_result = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "missing child stdin"))
                .and_then(|mut input| input.write_all(&request.input));
            if let Err(error) = write_result {
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(RunError {
                    detail: error.to_string(),
                    wall: started.elapsed(),
                });
            }
        }
        let output = child.wait_with_output().map_err(|error| RunError {
            detail: error.to_string(),
            wall: started.elapsed(),
        })?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
            wall: started.elapsed(),
        })
    }
}

pub(crate) fn render_argv(argv: &[String]) -> String {
    let mut rendered = String::from("[");
    for (index, argument) in argv.iter().enumerate() {
        if index > 0 {
            rendered.push_str(", ");
        }
        write!(&mut rendered, "{argument:?}").expect("writing to a String cannot fail");
    }
    rendered.push(']');
    rendered
}

fn render_input(input: &[u8]) -> String {
    String::from_utf8(input.to_vec()).map_or_else(
        |_error| format!("[{} non-UTF-8 bytes]", input.len()),
        |text| format!("{text:?}"),
    )
}

pub(crate) fn invoke<R: Runner, W: io::Write>(
    tool: &str,
    runner: &mut R,
    command: &CommandSpec,
    output: &mut W,
) -> Result<CommandOutput, ProvisionError> {
    let result = runner.run(command);
    let wall = result
        .as_ref()
        .map_or_else(|error| error.wall, |completed| completed.wall);
    writeln!(
        output,
        "[{tool}] step={} wall={:.3}s argv={}",
        command.label,
        wall.as_secs_f64(),
        render_argv(&command.argv)
    )
    .map_err(publication_error)?;
    result.map_err(|error| {
        ProvisionError::runtime(
            "command_failure",
            format!("{}: {}", command.label, error.detail),
        )
    })
}

pub(crate) fn failed_command(command: &CommandSpec, output: &CommandOutput) -> ProvisionError {
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let detail = if detail.is_empty() {
        format!("exit {}", output.status)
    } else {
        format!("exit {}: {detail}", output.status)
    };
    if command.remote && output.status == 255 {
        ProvisionError::runtime("ssh_failure", format!("{} through {detail}", command.label))
    } else if command.privileged {
        ProvisionError::refusal(
            "sudo_refused",
            format!("{} through {detail}", command.label),
        )
    } else if command.remote {
        ProvisionError::runtime("ssh_failure", format!("{} through {detail}", command.label))
    } else {
        ProvisionError::runtime("command_failure", format!("{}: {detail}", command.label))
    }
}

pub(crate) fn require_success(
    command: &CommandSpec,
    output: CommandOutput,
) -> Result<CommandOutput, ProvisionError> {
    if output.status == 0 {
        Ok(output)
    } else {
        Err(failed_command(command, &output))
    }
}

pub(crate) fn print_plan<W: io::Write>(
    commands: &[CommandSpec],
    output: &mut W,
) -> Result<(), ProvisionError> {
    for command in commands {
        writeln!(
            output,
            "[account] plan={} argv={} stdin={}",
            if command.mutation { "MUTATE" } else { "PROBE" },
            render_argv(&command.argv),
            render_input(&command.input)
        )
        .map_err(publication_error)?;
    }
    Ok(())
}
