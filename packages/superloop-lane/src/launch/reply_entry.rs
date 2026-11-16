//! Complete reply handoff; mail and lane custody are admitted as one frame.
use crate::{error::LaneError, home};
use loop_home::anchor::{self, Manifest, Receiver, Transport};
use loop_home::mail::steering::{BindingCustody, BindingSelection, REPLY_PURPOSES};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

fn failure(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("mail-delivery", error.to_string())
}
fn named(mode: BindingSelection, kind: &str, purpose: &str) -> LaneError {
    failure(format!(
        "{kind}: operation={} purpose={purpose}",
        mode.operation()
    ))
}
fn io(
    mode: BindingSelection,
    purpose: &str,
    check: &str,
    error: impl std::fmt::Display,
) -> LaneError {
    failure(format!(
        "anchor-io: operation={} purpose={purpose} check={check}: {error}",
        mode.operation()
    ))
}
fn vector_mode(args: &[String]) -> Result<BindingSelection, LaneError> {
    let word = args.first().map_or("", String::as_str);
    let flag = args
        .get(9)
        .filter(|word| Some(word.as_str()) == BindingSelection::InboundVerify.private_flag());
    let mode = BindingSelection::from_private(word, None)
        .ok_or_else(|| named(BindingSelection::Reply, "anchor-declaration", "vector"))?;
    BindingSelection::from_private(word, flag.map(String::as_str))
        .ok_or_else(|| named(mode, "anchor-declaration", "vector"))
}
fn selection(
    args: &[String],
) -> Result<(BindingSelection, &Path, super::steering::Request), LaneError> {
    let mode = vector_mode(args)?;
    let body = if mode.private_flag().is_some() {
        &args[..args.len() - 1]
    } else {
        args
    };
    let [
        _word,
        scope,
        run,
        home_flag,
        home,
        step_flag,
        step,
        delivery_flag,
        delivery,
    ] = body
    else {
        return Err(named(mode, "anchor-declaration", "vector"));
    };
    if home_flag != "--owner-home" || !Path::new(home).is_absolute() {
        return Err(named(mode, "anchor-declaration", "vector"));
    }
    let request = super::steering::Request::parse(&[
        scope.clone(),
        run.clone(),
        step_flag.clone(),
        step.clone(),
        delivery_flag.clone(),
        delivery.clone(),
    ])?;
    Ok((mode, Path::new(home), request))
}

/// Compose the exact operation-bound reply frame using the mail library's policies.
/// # Errors
/// Refuses inconsistent vectors, declarations or host custody before spawning.
pub fn command(
    program: &Path,
    argv: &[String],
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
) -> Result<CommandSpec, LaneError> {
    let mode = vector_mode(argv.get(2..).unwrap_or_default())?;
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(named(mode, "anchor-declaration", "registry-override"));
    }
    if argv.len() != 11 + usize::from(mode.private_flag().is_some()) || argv[0] != "unshare" {
        return Err(named(mode, "anchor-declaration", "vector"));
    }
    let (_, selected_home, request) = selection(&argv[2..])?;
    if selected_home != home.0 {
        return Err(named(mode, "anchor-identity", "owner-home"));
    }
    crate::pinned::owner_executable(program, nix::unistd::Uid::effective().as_raw())?;
    let pins = loop_home::mail::reply_entry::pins_for(
        home,
        runs,
        Path::new(&argv[1]),
        &request.loop_name,
        mode,
    )
    .map_err(failure)?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: mode.operation().into(),
        loop_name: request.loop_name,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let declaration = serde_json::to_string(&manifest).map_err(failure)?;
    Manifest::parse(&declaration).map_err(failure)?;
    let (sender, input) = UnixStream::pair().map_err(|e| io(mode, "rights", "socket-pair", e))?;
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| failure(e.context(mode.operation(), "rights")))?;
    let mut words = vec![crate::pinned::path_word(program, "namespace-program")?];
    words.extend_from_slice(argv);
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs.0, "runs-root")?,
        "--anchor-manifest".into(),
        declaration,
    ]);
    Ok(CommandSpec {
        label: mode.operation().into(),
        argv: words,
        io: IoMode::Capture,
        descriptors: CommandDescriptors::default().with_input(input.into()),
    })
}

/// Receive and activate all custody before reading a reservation or repairing a worker.
/// # Errors
/// Refuses malformed frames, replaced roots, changed entry image or binding custody.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    let mode = vector_mode(args)?;
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(named(mode, "anchor-declaration", "registry-override"));
    }
    if !args.iter().any(|word| word == "--anchor-manifest") {
        return Err(named(mode, "anchor-missing", "manifest"));
    }
    if args.len() != 13 + usize::from(mode.private_flag().is_some()) {
        return Err(named(mode, "anchor-declaration", "vector"));
    }
    let (body, suffix) = args.split_at(args.len() - 4);
    let (_, declared_home, request) = selection(body)?;
    let [root_flag, root, flag, source] = suffix else {
        unreachable!()
    };
    if root_flag != "--verified-runs-root"
        || flag != "--anchor-manifest"
        || !Path::new(root).is_absolute()
    {
        return Err(named(mode, "anchor-declaration", "vector"));
    }
    let manifest = Manifest::parse(source).map_err(failure)?;
    if manifest.records.len() != REPLY_PURPOSES.len() {
        return Err(named(mode, "anchor-declaration", "count"));
    }
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| io(mode, "rights", "input-duplicate", e))?;
    let status =
        nix::sys::stat::fstat(&input).map_err(|e| io(mode, "rights", "socket-inspect", e))?;
    if status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(named(mode, "anchor-missing", "rights"));
    }
    let fds = anchor::transport::receive(
        &UnixStream::from(input),
        REPLY_PURPOSES.len(),
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| failure(e.context(mode.operation(), "rights")))?;
    anchor::transport::replace_stdin(mode.operation()).map_err(failure)?;
    let custody = BindingCustody::receive(
        &Receiver::current().map_err(failure)?,
        &manifest,
        fds,
        &request.loop_name,
        mode,
    )
    .map_err(failure)?;
    if custody.home() != declared_home {
        return Err(named(mode, "anchor-identity", "owner-home"));
    }
    let (owner, runs, entry) = custody.entry_anchors();
    crate::container_entry::check_image(mode.operation(), entry).map_err(|e| failure(e.detail))?;
    let _roots =
        home::activate_private_launch(custody.home(), owner, Path::new(root), runs, None, 0)?;
    let (configuration, directory) = custody.configuration();
    let _configuration = crate::runtime_entry::activate_configuration(
        custody.home(),
        configuration,
        directory,
        mode.operation(),
    );
    super::steering::private_selected(custody, &request)
}
