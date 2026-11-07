//! Container-backed exercises retain the program selected by the protected reservation.
use super::exercise;
use crate::error::LaneError;
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

struct Selection<'a> {
    operation: &'static str,
    scope: &'a str,
    run: &'a str,
    identity: &'a str,
    home: &'a Path,
}
fn operation(command: &str) -> Option<&'static str> {
    match command {
        "_exercise-mounts" => Some("exercise-mounts"),
        "_exercise-network" => Some("exercise-network"),
        "_exercise-door-shape" => Some("exercise-door-shape"),
        "_exercise-door-attribution" => Some("exercise-door-attribution"),
        _ => None,
    }
}
/// Identify the private forms whose executable custody is carried in one bundle.
#[must_use]
pub fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|word| operation(word).is_some())
}
fn refusal(operation: &str, kind: &str, purpose: &str) -> LaneError {
    LaneError::input(
        "exercise-anchor",
        format!("{kind}: operation={operation} purpose={purpose}"),
    )
}
fn parse(args: &[String]) -> Result<Selection<'_>, LaneError> {
    let mode = args
        .first()
        .and_then(|word| operation(word))
        .ok_or_else(|| refusal("exercise", "anchor-declaration", "operation"))?;
    let (scope, run, identity, home) = match mode {
        "exercise-mounts" => exercise::mounts::parse_private_argv(args)?,
        "exercise-network" => exercise::network::parse_private_argv(args)?,
        "exercise-door-shape" => exercise::door_shape::parse_private_argv(args)?,
        _ => exercise::door_attribution::parse_private_argv(args)?,
    };
    Ok(Selection {
        operation: mode,
        scope,
        run,
        identity,
        home,
    })
}
fn selected_program(
    root: &OwnedFd,
    selection: &Selection<'_>,
    owner: u32,
) -> Result<PathBuf, LaneError> {
    let (record, identity) = super::checkout::read_record_bound(root, selection.run, owner)?;
    if identity != selection.identity
        || record["loop"] != selection.scope
        || record["run"] != selection.run
    {
        return Err(refusal(selection.operation, "anchor-declaration", "record"));
    }
    record["plan"]["runtime_argv"][0]
        .as_str()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| refusal(selection.operation, "anchor-declaration", "record-program"))
}

/// Compose an exercise entry from the same protected reservation identity as its caller.
/// # Errors
/// Refuses stale records, mismatched home custody, unsafe programs or a failed rights transfer.
pub fn command(
    namespace: &Path,
    argv: &[String],
    home: &Path,
    held_home: &OwnedFd,
    runs: &Path,
    held_runs: &OwnedFd,
) -> Result<CommandSpec, LaneError> {
    let [unshare, entry, body @ ..] = argv else {
        return Err(refusal("exercise", "anchor-declaration", "vector"));
    };
    let selection = parse(body)?;
    if unshare != "unshare" || home != selection.home {
        return Err(refusal(selection.operation, "anchor-declaration", "vector"));
    }
    let program = selected_program(
        held_runs,
        &selection,
        nix::unistd::Uid::effective().as_raw(),
    )?;
    let bundle = crate::container_entry::pin_for(
        selection.operation,
        selection.scope,
        (home, held_home),
        (runs, held_runs),
        Path::new(entry),
        &program,
    )?;
    let (sender, input) = UnixStream::pair().map_err(|error| {
        LaneError::operation(
            "anchor-io",
            format!(
                "operation={} purpose=rights check=socket-pair: {error}",
                selection.operation
            ),
        )
    })?;
    loop_home::anchor::transport::send(&sender, &bundle.descriptors).map_err(|error| {
        LaneError::input(
            "exercise-anchor",
            error.context(selection.operation, "rights").to_string(),
        )
    })?;
    let mut words = vec![crate::pinned::path_word(namespace, "namespace-program")?];
    words.extend(argv.iter().cloned());
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs, "runs-root")?,
        "--anchored-program".into(),
        crate::pinned::path_word(&program, "container-program")?,
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

/// Validate the bundle and protected record before measuring the selected exercise.
/// # Errors
/// Refuses missing or changed capabilities and records before a container program runs.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    if args.len() < 13 {
        return Err(refusal(
            args.first()
                .and_then(|word| operation(word))
                .unwrap_or("exercise"),
            "anchor-missing",
            "manifest",
        ));
    }
    let (body, suffix) = args.split_at(args.len().saturating_sub(6));
    let selection = parse(body)?;
    let [
        root_flag,
        root,
        program_flag,
        program,
        manifest_flag,
        source,
    ] = suffix
    else {
        return Err(refusal(selection.operation, "anchor-missing", "manifest"));
    };
    if root_flag != "--verified-runs-root"
        || program_flag != "--anchored-program"
        || manifest_flag != "--anchor-manifest"
        || !Path::new(root).is_absolute()
        || !Path::new(program).is_absolute()
    {
        return Err(refusal(selection.operation, "anchor-declaration", "vector"));
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Err(refusal(selection.operation, "anchor-owner", "namespace"));
    }
    let (_, anchors) = crate::container_entry::receive_for(
        source,
        &std::io::stdin(),
        selection.operation,
        Some(selection.scope),
    )?;
    loop_home::anchor::transport::replace_stdin(selection.operation)
        .map_err(|error| LaneError::input("exercise-anchor", error.to_string()))?;
    let mut anchors = anchors.into_iter();
    let mut next = || {
        anchors
            .next()
            .ok_or_else(|| refusal(selection.operation, "anchor-missing", "bundle"))
    };
    let home_anchor = next()?;
    let runs_anchor = next()?;
    let _entry = next()?;
    let executable = next()?;
    let hash = next()?;
    let _home = crate::home::activate_private_launch(
        selection.home,
        &home_anchor,
        Path::new(root),
        &runs_anchor,
        None,
        0,
    )?;
    let _programs = crate::container_entry::activate_programs(
        selection.operation,
        Path::new(program),
        executable,
        hash,
    );
    let held_runs = runs_anchor.as_fd().try_clone_to_owned().map_err(|error| {
        LaneError::operation(
            "anchor-io",
            format!(
                "operation={} purpose=runs-root check=descriptor-duplicate: {error}",
                selection.operation
            ),
        )
    })?;
    if selected_program(&held_runs, &selection, 0)? != Path::new(program) {
        return Err(refusal(
            selection.operation,
            "anchor-declaration",
            "record-program",
        ));
    }
    measure(&selection)
}

fn measure(selection: &Selection<'_>) -> Result<serde_json::Value, LaneError> {
    match selection.operation {
        "exercise-mounts" => exercise::mounts::private_measure(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        ),
        "exercise-network" => exercise::network::private_measure(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        ),
        "exercise-door-shape" => exercise::door_shape::private_measure(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        ),
        _ => exercise::door_attribution::private_measure(
            selection.home,
            selection.scope,
            selection.run,
            selection.identity,
        ),
    }
}
