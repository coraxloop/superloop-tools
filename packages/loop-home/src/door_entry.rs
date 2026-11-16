//! Dedicated door receiver. No door caller selects this route until D3.
use crate::anchor::{self, Anchor, Manifest, Owner, Receiver, Transport};
use crate::door_frame::{self, Operation};
use crate::{CommandDescriptors, LoopError};
use nix::sys::stat::fstat;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

mod identity;

/// Host-authored consumer code and input, carried only in the sealed invocation.
///
/// This is not a worker-selected program: the receiving host-file policy grants it.
/// The receiver appends the registered loop name and uid to `arguments`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub source: String,
    pub arguments: Vec<String>,
    pub input: String,
}

fn refusal(operation: Operation, purpose: &str, check: &str) -> LoopError {
    LoopError::refusal(format!(
        "anchor-declaration: operation={} purpose={purpose} check={check}",
        operation.name()
    ))
}
fn failure(operation: Operation, purpose: &str, error: impl std::fmt::Display) -> LoopError {
    LoopError::refusal(format!(
        "anchor-io: operation={} purpose={purpose}: {error}",
        operation.name()
    ))
}
fn anchored(operation: Operation, error: anchor::Error) -> LoopError {
    let purpose = error.purpose().to_owned();
    LoopError::refusal(error.context(operation.name(), &purpose).to_string())
}

struct Entered {
    operation: Operation,
    name: String,
    uid: u32,
    anchors: Vec<Anchor>,
}

fn receive(arguments: &[OsString]) -> Result<Entered, LoopError> {
    // Dispatcher word, override, socket, receive, frame, configuration-derived
    // requirements, anchor receipt, then the sole invocation reader, in that order.
    let operation =
        Operation::from_private(arguments.first().and_then(|w| w.to_str()).unwrap_or(""))?;
    operation.check_override()?;
    let input = nix::unistd::dup(std::io::stdin().as_fd())
        .map_err(|e| failure(operation, "rights-socket", e))?;
    if fstat(&input)
        .map_err(|e| failure(operation, "rights-socket", e))?
        .st_mode
        & libc::S_IFMT
        != libc::S_IFSOCK
    {
        return Err(LoopError::refusal(format!(
            "anchor-missing: operation={} purpose=rights-socket",
            operation.name()
        )));
    }
    let [_, home, name, flag, declaration] = arguments else {
        return Err(refusal(operation, "manifest", "arguments"));
    };
    if flag != "--anchor-manifest" {
        return Err(refusal(operation, "manifest", "arguments"));
    }
    let descriptors = anchor::transport::receive(
        &UnixStream::from(input),
        door_frame::PURPOSES.len(),
        Duration::from_secs(30),
    )
    .map_err(|e| anchored(operation, e))?;
    anchor::transport::replace_stdin(operation.name()).map_err(|e| anchored(operation, e))?;
    let manifest = Manifest::parse(
        declaration
            .to_str()
            .ok_or_else(|| refusal(operation, "manifest", "encoding"))?,
    )
    .map_err(|e| anchored(operation, e))?;
    let name = name
        .to_str()
        .ok_or_else(|| refusal(operation, "manifest", "loop-name"))?;
    operation.check_frame(name, &manifest)?;
    let receiver = Receiver::current().map_err(|e| anchored(operation, e))?;
    let configuration = receiver
        .configuration(
            &manifest,
            &descriptors,
            anchor::Entry {
                operation: operation.name(),
                loop_name: name,
                transport: Transport::Rights,
            },
            Path::new(home),
            false,
        )
        .map_err(|e| anchored(operation, e))?;
    let row = configuration
        .registry
        .row(name, Path::new(home))
        .map_err(|error| failure(operation, "registry", error))?;
    let anchors = validate(&receiver, &manifest, &descriptors, operation, name, row.uid)?;
    // No other code reads slot 6, including the self re-exec below.
    let bytes = door_frame::read_invocation(operation, &anchors[6])?;
    parse_invocation(operation, &bytes)?;
    if !nix::unistd::Uid::effective().is_root() {
        return Err(refusal(operation, "receiver", "namespace-root"));
    }
    let image =
        File::open("/proc/self/exe").map_err(|e| failure(operation, "entry-executable", e))?;
    let actual = fstat(&image).map_err(|e| failure(operation, "entry-executable", e))?;
    let held = fstat(&anchors[1]).map_err(|e| failure(operation, "entry-executable", e))?;
    if (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino) {
        return Err(LoopError::refusal(format!(
            "anchor-identity: operation={} purpose=entry-executable",
            operation.name()
        )));
    }
    Ok(Entered {
        operation,
        name: name.into(),
        uid: row.uid,
        anchors,
    })
}

fn validate(
    receiver: &Receiver,
    manifest: &Manifest,
    descriptors: &[OwnedFd],
    operation: Operation,
    name: &str,
    uid: u32,
) -> Result<Vec<Anchor>, LoopError> {
    let mut last = None;
    for (entry, namespace) in [
        (Owner::Host, Owner::Host),
        (Owner::RootFile, Owner::Host),
        (Owner::Host, Owner::RootFile),
        (Owner::RootFile, Owner::RootFile),
    ] {
        let required = operation.requirements(uid, entry, namespace)?;
        let copies = descriptors
            .iter()
            .map(OwnedFd::try_clone)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| failure(operation, "rights", e))?;
        match receiver.validate(
            manifest,
            copies,
            operation.name(),
            name,
            Transport::Rights,
            &required,
        ) {
            Ok(anchors) => return Ok(anchors),
            Err(e)
                if e.kind == "anchor-owner"
                    && matches!(e.purpose(), "entry-executable" | "namespace-entry") =>
            {
                last = Some(e);
            }
            Err(e) => return Err(anchored(operation, e)),
        }
    }
    Err(anchored(
        operation,
        last.expect("four owner policies attempted"),
    ))
}

fn parse_invocation(operation: Operation, bytes: &[u8]) -> Result<Invocation, LoopError> {
    let invocation: Invocation = serde_json::from_slice(bytes)
        .map_err(|_| refusal(operation, "invocation", "consumer-document"))?;
    if invocation.source.is_empty()
        || invocation.source.len() > 65_536
        || invocation.arguments.len() > 32
        || invocation
            .arguments
            .iter()
            .any(|a| a.len() > 8192 || a.contains('\0'))
    {
        return Err(refusal(operation, "invocation", "consumer-bound"));
    }
    Ok(invocation)
}

fn launch(entered: Entered) -> Result<(), LoopError> {
    let Entered {
        operation,
        name,
        uid,
        anchors,
    } = entered;
    let private = &anchors[3];
    let home = private
        .directory_path()
        .map_err(|e| anchored(operation, e))?;
    let temporary = private
        .open_beneath(
            Path::new(".run"),
            anchor::Policy {
                kind: anchor::Kind::Directory,
                owner: Owner::Mapped(uid),
                mode: anchor::ModePolicy::Exact(0o700),
            },
            0o700,
        )
        .map_err(|e| anchored(operation, e))?;
    drop(temporary);
    identity::account(&name, uid, &home).map_err(|e| failure(operation, "account", e))?;
    private.revalidate().map_err(|e| anchored(operation, e))?;
    nix::unistd::fchdir(private).map_err(|e| failure(operation, "private-storage", e))?;
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let (_, image) = anchors[1].relay().map_err(|e| anchored(operation, e))?;
    let (_, invocation) = anchors[6].relay().map_err(|e| anchored(operation, e))?;
    let environment = vec![
        (OsString::from("HOME"), home.as_os_str().to_owned()),
        (OsString::from("TMPDIR"), home.join(".run").into_os_string()),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
    ];
    let argv: Vec<OsString> = vec![
        "setpriv".into(),
        format!("--reuid={uid}").into(),
        format!("--regid={uid}").into(),
        "--clear-groups".into(),
        "--no-new-privs".into(),
        format!("/proc/self/fd/{}", image.as_raw_fd()).into(),
        "_door-consumer".into(),
        operation.name().into(),
        name.into(),
        uid.to_string().into(),
        invocation.as_raw_fd().to_string().into(),
        nix::unistd::getppid().as_raw().to_string().into(),
    ];
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .args(&argv[1..])
        .env_clear()
        .envs(environment.clone());
    CommandDescriptors::inherit(vec![image, invocation])
        .and_then(|d| d.configure(&mut command))
        .map_err(|e| failure(operation, "inherit", e))?;
    anchors[4]
        .configure_exec(&mut command, &argv, &environment)
        .map_err(|e| anchored(operation, e))?;
    Err(failure(operation, "identity-executable", command.exec()))
}

#[allow(unsafe_code)]
fn consume(arguments: &[OsString]) -> Result<(), LoopError> {
    let [_, operation, name, uid, descriptor, parent] = arguments else {
        return Err(LoopError::refusal(
            "anchor-declaration: operation=door-consumer purpose=arguments",
        ));
    };
    let operation = Operation::from_private(&format!("_{}", operation.to_string_lossy()))?;
    let uid: u32 = uid
        .to_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| refusal(operation, "identity", "uid"))?;
    if nix::unistd::getuid().as_raw() != uid || nix::unistd::geteuid().as_raw() != uid {
        return Err(refusal(operation, "identity", "loop-uid"));
    }
    let descriptor: i32 = descriptor
        .to_str()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 2)
        .ok_or_else(|| refusal(operation, "invocation", "descriptor"))?;
    // SAFETY: duplicate only the inherited descriptor; do not adopt its caller's ownership.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(descriptor) };
    let parent: i32 = parent
        .to_str()
        .and_then(|s| s.parse().ok())
        .filter(|p| *p > 1)
        .ok_or_else(|| refusal(operation, "parent-watch", "parent"))?;
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM)
        .and_then(|()| nix::sys::prctl::set_child_subreaper(true))
        .map_err(|e| failure(operation, "parent-watch", e))?;
    if nix::unistd::getppid().as_raw() != parent {
        return Err(refusal(operation, "parent-watch", "changed-parent"));
    }
    let bytes = door_frame::read_invocation(operation, &borrowed)?;
    let invocation = parse_invocation(operation, &bytes)?;
    let mut command = Command::new("/usr/bin/python3");
    command.args(["-I", "-c", include_str!("door_entry/consumer.py")]);
    // The consumer receives the validated immutable document as standard input,
    // not an inherited capability. Its expected identity is receiver-derived.
    let input = door_frame::invocation(operation, &bytes)?;
    command.stdin(input).arg(name).arg(uid.to_string());
    drop(invocation);
    CommandDescriptors::default()
        .configure(&mut command)
        .map_err(|e| failure(operation, "consumer", e))?;
    Err(failure(operation, "consumer", command.exec()))
}

/// Dispatch only the dedicated private door words; existing callers remain on ordinary entry.
#[must_use]
pub fn entry(arguments: &[OsString], error: &mut impl std::io::Write) -> u8 {
    let result = if arguments.first().is_some_and(|w| w == "_door-consumer") {
        consume(arguments)
    } else {
        receive(arguments).and_then(launch)
    };
    match result {
        Ok(()) => 0,
        Err(failure) => {
            let _written = writeln!(error, "{failure}");
            failure.status()
        }
    }
}
