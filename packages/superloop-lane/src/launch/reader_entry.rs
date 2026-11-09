//! Configuration custody for private harvest and home-layout readers.
use super::exercise;
use crate::{container_entry, error::LaneError};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

struct Selection<'a> {
    operation: &'static str,
    scope: &'a str,
    run: &'a str,
    identity: &'a str,
    home: &'a Path,
}
fn operation(word: &str) -> Option<&'static str> {
    match word {
        "_exercise-measure" => Some("exercise-measure"),
        "_exercise-harvest" => Some("exercise-harvest"),
        "_exercise-home-layout" => Some("exercise-home-layout"),
        _ => None,
    }
}
/// Identify the private readers requiring configuration custody.
#[must_use]
pub fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|word| operation(word).is_some())
}
fn refused(operation: &str, kind: &str, purpose: &str) -> LaneError {
    container_entry::operation_error(
        operation,
        format!("{kind}: operation={operation} purpose={purpose}"),
    )
}
fn parse(args: &[String]) -> Result<Selection<'_>, LaneError> {
    let mode = args
        .first()
        .and_then(|word| operation(word))
        .ok_or_else(|| refused("exercise", "anchor-declaration", "operation"))?;
    if mode == "exercise-measure" {
        let [_, scope, run, option, home] = args else {
            return Err(refused(mode, "anchor-declaration", "vector"));
        };
        if run != "all" || option != "--owner-home" {
            return Err(refused(mode, "anchor-declaration", "vector"));
        }
        loop_home::validate_name(scope).map_err(|_| refused(mode, "anchor-declaration", "loop"))?;
        return Ok(Selection {
            operation: mode,
            scope,
            run,
            identity: "",
            home: Path::new(home),
        });
    }
    if args.len() != 7 {
        return Err(refused(mode, "anchor-declaration", "vector"));
    }
    let (scope, run, identity, home) = if mode == "exercise-harvest" {
        exercise::parse_harvest_private_argv(args)?
    } else {
        exercise::parse_home_layout_private_argv(args)?
    };
    Ok(Selection {
        operation: mode,
        scope,
        run,
        identity,
        home,
    })
}

/// Bind the reader's configuration alongside the existing home, runs and entry identities.
/// # Errors
/// Refuses unsafe custody, ambient registry overrides or a mismatched private vector.
pub fn command(
    namespace: &Path,
    argv: &[String],
    home: &Path,
    held_home: &OwnedFd,
    runs: &Path,
    held_runs: &OwnedFd,
) -> Result<CommandSpec, LaneError> {
    let [unshare, entry, body @ ..] = argv else {
        return Err(refused("exercise", "anchor-declaration", "vector"));
    };
    let selection = parse(body)?;
    if unshare != "unshare" || selection.home != home {
        return Err(refused(selection.operation, "anchor-declaration", "vector"));
    }
    let bundle = container_entry::pin_reader(
        selection.operation,
        selection.scope,
        (home, held_home),
        (runs, held_runs),
        Path::new(entry),
    )
    .map_err(|error| container_entry::operation_error(selection.operation, error.detail))?;
    let (sender, input) = UnixStream::pair().map_err(|error| {
        container_entry::operation_error(
            selection.operation,
            format!(
                "anchor-io: operation={} purpose=rights check=socket-pair: {error}",
                selection.operation
            ),
        )
    })?;
    loop_home::anchor::transport::send(&sender, &bundle.descriptors).map_err(|error| {
        container_entry::operation_error(
            selection.operation,
            error.context(selection.operation, "rights"),
        )
    })?;
    let mut words = vec![crate::pinned::path_word(namespace, "namespace-program")?];
    words.extend(argv.iter().cloned());
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs, "runs-root")?,
        "--anchor-manifest".into(),
        bundle.manifest,
    ]);
    Ok(CommandSpec {
        label: selection.operation.into(),
        argv: words,
        io: IoMode::Capture,
        descriptors: CommandDescriptors::default().with_input(input.into()),
    })
}

/// Receive the exact reader bundle before any plan or reservation read.
/// # Errors
/// Refuses missing, substituted or mismatched capabilities and unsupported namespace identity.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    let mode = args
        .first()
        .and_then(|word| operation(word))
        .unwrap_or("exercise");
    if args.len() < 9 {
        return Err(refused(mode, "anchor-missing", "manifest"));
    }
    let (body, suffix) = args.split_at(args.len() - 4);
    let selection = parse(body)?;
    let [root_flag, root, manifest_flag, source] = suffix else {
        return Err(refused(mode, "anchor-declaration", "vector"));
    };
    if root_flag != "--verified-runs-root"
        || manifest_flag != "--anchor-manifest"
        || !Path::new(root).is_absolute()
    {
        return Err(refused(mode, "anchor-declaration", "vector"));
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Err(refused(mode, "anchor-owner", "namespace"));
    }
    let (_, anchors) =
        container_entry::receive_for(source, &std::io::stdin(), mode, Some(selection.scope))
            .map_err(|error| container_entry::operation_error(mode, error.detail))?;
    loop_home::anchor::transport::replace_stdin(mode)
        .map_err(|error| container_entry::operation_error(mode, error))?;
    let mut anchors = anchors.into_iter();
    let mut next = || {
        anchors
            .next()
            .ok_or_else(|| refused(mode, "anchor-missing", "bundle"))
    };
    let home_anchor = next()?;
    let runs_anchor = next()?;
    let _entry = next()?;
    let hash = next()?;
    let git = next()?;
    let configuration = next()?;
    let _programs = container_entry::activate_program_map(
        mode,
        [
            (
                std::path::PathBuf::from("/usr/bin/sha256sum"),
                std::sync::Arc::new(hash),
            ),
            (
                std::path::PathBuf::from("/usr/bin/git"),
                std::sync::Arc::new(git),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let _home = crate::home::activate_private_launch(
        selection.home,
        &home_anchor,
        Path::new(root),
        &runs_anchor,
        None,
        0,
    )?;
    let _configuration =
        container_entry::configuration(selection.home, selection.scope, mode, configuration)?;
    if mode == "exercise-measure" {
        exercise::private_measure(selection.home, selection.scope)
    } else if mode == "exercise-harvest" {
        exercise::private_harvest_audit(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        )
    } else {
        exercise::private_home_layout(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        )
    }
}
