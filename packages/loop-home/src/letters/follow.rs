use std::collections::BTreeSet;
use std::io::Write;
use std::time::{Duration, Instant};

use super::io_error;
use super::store::{Context, Observation, directory, observations, readable_directory, usage};
use super::wake::{Ready, Signals, Wake};
use crate::LoopError;

struct Options<'a> {
    peer: Option<&'a str>,
    interval: Duration,
    once: bool,
    next: bool,
    excluded: BTreeSet<String>,
    wall: Option<Duration>,
}

fn options<'a>(context: &'a Context, arguments: &'a [String]) -> Result<Options<'a>, LoopError> {
    let mut peer = None;
    let mut interval = None;
    let mut once = false;
    let mut next = false;
    let mut excluded = BTreeSet::new();
    let mut wall = None;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--wall" if wall.is_none() => {
                let value = arguments.next().ok_or_else(usage)?;
                let seconds = value
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| {
                        (1..=86_400).contains(seconds)
                            && value.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .ok_or_else(|| {
                        LoopError::refusal(format!(
                            "letters wall out of range: \"{}\"; expected whole seconds 1..=86400",
                            value.escape_debug()
                        ))
                    })?;
                wall = Some(Duration::from_secs(seconds));
            }
            "--peer" if peer.is_none() => {
                peer = Some(
                    context
                        .row(arguments.next().ok_or_else(usage)?)?
                        .name
                        .as_str(),
                );
            }
            "--interval" if interval.is_none() => {
                let value = arguments.next().ok_or_else(usage)?;
                let seconds = value.parse::<u64>().ok().filter(|seconds| {
                    (1..=86_400).contains(seconds)
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                }).ok_or_else(|| LoopError::refusal(format!(
                    "letters interval out of range: \"{}\"; expected whole seconds 1..=86400",
                    value.escape_debug()
                )))?;
                interval = Some(Duration::from_secs(seconds));
            }
            "--once" if !once => once = true,
            "--next" if !next => next = true,
            "--exclude" => {
                let name = arguments.next().ok_or_else(usage)?;
                super::record::parse_name(name)?;
                excluded.insert(name.clone());
            }
            _ => return Err(usage()),
        }
    }
    if once && next || !next && (wall.is_some() || !excluded.is_empty()) {
        return Err(usage());
    }
    Ok(Options {
        peer,
        interval: interval.unwrap_or(Duration::from_secs(30)),
        once,
        next,
        excluded,
        wall,
    })
}

pub(super) fn run(
    context: &Context,
    arguments: &[String],
    output: &mut impl Write,
    report: &mut impl Write,
) -> Result<(), LoopError> {
    let options = options(context, arguments)?;
    let started = Instant::now();
    let me = context.me()?;
    let inbox = context.inbox(me)?;
    let new = directory(&inbox, "new", me.uid, context.gid, 0o1730)?;
    let new = readable_directory(&new)?;
    if options.once {
        // Keep termination safe through the scan/report, without any inode watch.
        let _signals = Signals::new()?;
        for entry in observations(context, &new, "new", options.peer)? {
            writeln!(output, "{}", bare_line(&entry.entry().line)).map_err(io_error)?;
            output.flush().map_err(io_error)?;
        }
        return Ok(());
    }
    let wake = Wake::new(&inbox, &new)?;
    #[cfg(test)]
    super::store::race("follow-armed");
    let mut seen = BTreeSet::new();
    loop {
        let remaining = options
            .wall
            .map(|wall| wall.saturating_sub(started.elapsed()));
        if remaining == Some(Duration::ZERO) {
            return Err(LoopError::deadline(
                "letters follow wall expired before notification",
            ));
        }
        if matches!(wake.wait(Duration::ZERO)?, Ready::Stop) {
            return stopped(options.next);
        }
        if !wake.attached()? {
            return detached(output, options.next);
        }
        let entries = observations(context, &new, "new", options.peer)?;
        if !wake.attached()? {
            return detached(output, options.next);
        }
        for observation in entries {
            let entry = match observation {
                Observation::Refused(entry) if options.next => {
                    if seen.insert(entry.identity.0) {
                        writeln!(report, "{}", bare_line(&entry.line)).map_err(io_error)?;
                        report.flush().map_err(io_error)?;
                    }
                    continue;
                }
                Observation::Letter(entry) | Observation::Refused(entry) => entry,
            };
            if options.next {
                let metadata = super::parse_letter_metadata(&entry.line)?;
                if options.excluded.contains(&metadata.name) {
                    continue;
                }
                writeln!(output, "{}", bare_line(&entry.line)).map_err(io_error)?;
                output.flush().map_err(io_error)?;
                return Ok(());
            }
            if seen.insert(entry.identity.0) {
                writeln!(output, "{}", bare_line(&entry.line)).map_err(io_error)?;
                output.flush().map_err(io_error)?;
            }
        }
        #[cfg(test)]
        super::store::race("follow-wait");
        let wait = options.wall.map_or(options.interval, |wall| {
            options.interval.min(wall.saturating_sub(started.elapsed()))
        });
        if matches!(wake.wait(wait)?, Ready::Stop) {
            return stopped(options.next);
        }
    }
}

fn bare_line(line: &str) -> &str {
    line.strip_prefix("new/").unwrap_or(line)
}

fn stopped(next: bool) -> Result<(), LoopError> {
    if next {
        Err(LoopError::refusal(
            "letters follow interrupted before notification",
        ))
    } else {
        Ok(())
    }
}

fn detached(output: &mut impl Write, next: bool) -> Result<(), LoopError> {
    if next {
        return Err(LoopError::refusal(
            "letters follow inbox/new detached before notification",
        ));
    }
    writeln!(output, "LETTERS follow name=inbox/new detached actions=0").map_err(io_error)?;
    output.flush().map_err(io_error)
}
