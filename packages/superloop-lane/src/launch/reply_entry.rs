//! Complete reply handoff; mail and lane custody are admitted as one frame.
use crate::{error::LaneError, home};
use loop_home::anchor::{self, Manifest, Receiver, Transport};
use loop_home::mail::steering::{REPLY_PURPOSES, ReplyCustody};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

fn failure(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("mail-delivery", error.to_string())
}
fn named(kind: &str, purpose: &str) -> LaneError {
    failure(format!("{kind}: operation=mail-binding purpose={purpose}"))
}
fn io(purpose: &str, check: &str, error: impl std::fmt::Display) -> LaneError {
    failure(format!(
        "anchor-io: operation=mail-binding purpose={purpose} check={check}: {error}"
    ))
}
fn selection(args: &[String]) -> Result<(&Path, super::steering::Request), LaneError> {
    let [
        word,
        scope,
        run,
        home_flag,
        home,
        step_flag,
        step,
        delivery_flag,
        delivery,
    ] = args
    else {
        return Err(named("anchor-declaration", "vector"));
    };
    if word != "_bind-reply" || home_flag != "--owner-home" || !Path::new(home).is_absolute() {
        return Err(named("anchor-declaration", "vector"));
    }
    let request = super::steering::Request::parse(&[
        scope.clone(),
        run.clone(),
        step_flag.clone(),
        step.clone(),
        delivery_flag.clone(),
        delivery.clone(),
    ])?;
    Ok((Path::new(home), request))
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
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(named("anchor-declaration", "registry-override"));
    }
    if argv.len() != 11 || argv[0] != "unshare" {
        return Err(named("anchor-declaration", "vector"));
    }
    let (selected_home, request) = selection(&argv[2..])?;
    if selected_home != home.0 {
        return Err(named("anchor-identity", "owner-home"));
    }
    crate::pinned::owner_executable(program, nix::unistd::Uid::effective().as_raw())?;
    let pins =
        loop_home::mail::reply_entry::pins(home, runs, Path::new(&argv[1]), &request.loop_name)
            .map_err(failure)?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: "mail-binding".into(),
        loop_name: request.loop_name,
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let declaration = serde_json::to_string(&manifest).map_err(failure)?;
    Manifest::parse(&declaration).map_err(failure)?;
    let (sender, input) = UnixStream::pair().map_err(|e| io("rights", "socket-pair", e))?;
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| failure(e.context("mail-binding", "rights")))?;
    let mut words = vec![crate::pinned::path_word(program, "namespace-program")?];
    words.extend_from_slice(argv);
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs.0, "runs-root")?,
        "--anchor-manifest".into(),
        declaration,
    ]);
    Ok(CommandSpec {
        label: "mail-binding".into(),
        argv: words,
        io: IoMode::Capture,
        descriptors: CommandDescriptors::default().with_input(input.into()),
    })
}

/// Receive and activate all custody before reading a reservation or repairing a worker.
/// # Errors
/// Refuses malformed frames, replaced roots, changed entry image or binding custody.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(named("anchor-declaration", "registry-override"));
    }
    if !args.iter().any(|word| word == "--anchor-manifest") {
        return Err(named("anchor-missing", "manifest"));
    }
    if args.len() != 13 {
        return Err(named("anchor-declaration", "vector"));
    }
    let (body, suffix) = args.split_at(9);
    let (declared_home, request) = selection(body)?;
    let [root_flag, root, flag, source] = suffix else {
        unreachable!()
    };
    if root_flag != "--verified-runs-root"
        || flag != "--anchor-manifest"
        || !Path::new(root).is_absolute()
    {
        return Err(named("anchor-declaration", "vector"));
    }
    let manifest = Manifest::parse(source).map_err(failure)?;
    if manifest.records.len() != REPLY_PURPOSES.len() {
        return Err(named("anchor-declaration", "count"));
    }
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| io("rights", "input-duplicate", e))?;
    let status = nix::sys::stat::fstat(&input).map_err(|e| io("rights", "socket-inspect", e))?;
    if status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(named("anchor-missing", "rights"));
    }
    let fds = anchor::transport::receive(
        &UnixStream::from(input),
        REPLY_PURPOSES.len(),
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| failure(e.context("mail-binding", "rights")))?;
    anchor::transport::replace_stdin("mail-binding").map_err(failure)?;
    let custody = ReplyCustody::receive(
        &Receiver::current().map_err(failure)?,
        &manifest,
        fds,
        &request.loop_name,
    )
    .map_err(failure)?;
    if custody.home() != declared_home {
        return Err(named("anchor-identity", "owner-home"));
    }
    let (owner, runs, entry) = custody.entry_anchors();
    crate::container_entry::check_image("mail-binding", entry).map_err(|e| failure(e.detail))?;
    let _roots =
        home::activate_private_launch(custody.home(), owner, Path::new(root), runs, None, 0)?;
    let (configuration, directory) = custody.configuration();
    let _configuration = crate::runtime_entry::activate_configuration(
        custody.home(),
        configuration,
        directory,
        "mail-binding",
    );
    super::steering::private_reply(custody, &request)
}
