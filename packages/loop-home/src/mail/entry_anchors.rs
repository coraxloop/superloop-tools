//! Configuration capabilities for the mail service's host-to-namespace entry.
use super::command::{Settings, parse_settings};
use super::journal::{MailError, Result};
use crate::anchor::{
    self, Anchor, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement,
    Transport,
};
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

pub(super) const OPERATION: &str = "mail-serve";
fn refusal(kind: &str, purpose: &str) -> MailError {
    MailError::Entry(format!("{kind}: operation={OPERATION} purpose={purpose}"))
}
const fn directory_policy() -> Policy {
    Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(0o700),
    }
}
const fn executable_policy(owner: Owner) -> Policy {
    Policy {
        kind: Kind::File,
        owner,
        mode: ModePolicy::Executable,
    }
}
fn executable(
    host: &HostVerifier,
    path: &Path,
    purpose: &str,
    slot: u32,
) -> Result<anchor::HostPin> {
    host.pin(path, purpose, slot, executable_policy(Owner::Host))
        .or_else(|_| host.pin(path, purpose, slot, executable_policy(Owner::RootFile)))
        .map_err(MailError::from)
}
fn namespace_program(word: &std::ffi::OsStr) -> Result<PathBuf> {
    let path = Path::new(word);
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    if path.components().count() != 1 {
        return Err(refusal("anchor-exec", "namespace-entry"));
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|p| p.join(path))
        .find(|p| p.is_absolute() && p.is_file())
        .ok_or_else(|| refusal("anchor-exec", "namespace-entry"))
}

/// Compose the production host launcher with an explicitly supplied namespace command.
///
/// This is also the fixture injection boundary: it uses the real verifier and
/// handoff while letting an integration test select unshare instead of Podman.
/// The caller owns the command vector; no new environment override selects it.
/// # Errors
/// Refuses unsafe host custody, missing entry machinery or a failed descriptor handoff.
pub fn serve_command(home: &Path, entry: &Path, namespace: &[OsString]) -> Result<Command> {
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(refusal("anchor-declaration", "registry-override"));
    }
    let (word, arguments) = namespace
        .split_first()
        .ok_or_else(|| refusal("anchor-exec", "namespace-entry"))?;
    let host = HostVerifier::current()
        .map_err(|e| e.context(OPERATION, "host-map"))?
        .for_operation(OPERATION);
    let program = namespace_program(word)?;
    let _namespace_pin = executable(&host, &program, "namespace-entry", 0)?;
    let configuration = host.pin(
        &home.join(".config/loops"),
        "configuration",
        0,
        directory_policy(),
    )?;
    let entry_pin = executable(&host, entry, "entry-executable", 1)?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: OPERATION.into(),
        loop_name: String::new(),
        records: vec![configuration.record(), entry_pin.record()],
    };
    let declaration =
        serde_json::to_string(&manifest).map_err(|_| refusal("anchor-declaration", "manifest"))?;
    Manifest::parse(&declaration).map_err(|e| e.context(OPERATION, "manifest"))?;
    let (sender, receiver) = UnixStream::pair()?;
    // Queueing the bounded frame before exec preserves serve's process semantics.
    // The queued rights hold both objects across Podman and the entry-word exec.
    anchor::transport::send(&sender, &[configuration.into_fd(), entry_pin.into_fd()])
        .map_err(|e| e.context(OPERATION, "rights"))?;
    drop(sender);
    let input: OwnedFd = receiver.into();
    let mut command = Command::new(&program);
    command
        .args(arguments)
        .arg(entry)
        .arg("_serve")
        .arg(home)
        .arg("--anchor-manifest")
        .arg(declaration)
        .stdin(input);
    Ok(command)
}
fn requirements(owner: Owner) -> [Requirement; 2] {
    [
        Requirement {
            purpose: "configuration".into(),
            policy: directory_policy(),
            alias_group: None,
        },
        Requirement {
            purpose: "entry-executable".into(),
            policy: executable_policy(owner),
            alias_group: None,
        },
    ]
}

pub(super) struct Entered {
    pub settings: Settings,
    pub configuration: anchor::Configuration,
    pub anchor: Arc<Anchor>,
}

pub(super) fn receive(home: &Path, declaration: &str) -> Result<Entered> {
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(refusal("anchor-declaration", "registry-override"));
    }
    let manifest = Manifest::parse(declaration).map_err(|e| e.context(OPERATION, "manifest"))?;
    let input = nix::unistd::dup(std::io::stdin().as_fd())
        .map_err(|_| refusal("anchor-missing", "rights-socket"))?;
    let stat =
        nix::sys::stat::fstat(&input).map_err(|_| refusal("anchor-missing", "rights-socket"))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(refusal("anchor-missing", "rights-socket"));
    }
    let socket = UnixStream::from(input);
    let descriptors =
        anchor::transport::receive(&socket, manifest.records.len(), Duration::from_secs(30))
            .map_err(|e| e.context(OPERATION, "rights"))?;
    drop(socket);
    // The private receiver owns stdin; the consumed socket is setup-only.
    nix::unistd::close(0)?;
    let receiver = Receiver::current().map_err(|e| e.context(OPERATION, "receiver-map"))?;
    let configuration = receiver.configuration(
        &manifest,
        &descriptors,
        anchor::Entry {
            operation: OPERATION,
            loop_name: "",
            transport: Transport::Rights,
        },
        home,
        false,
    )?;
    let copies = descriptors
        .iter()
        .map(OwnedFd::try_clone)
        .collect::<std::io::Result<Vec<_>>>()?;
    // The operation admits host-installed and system-installed entry executables.
    // A declaration cannot add another owner to this independent two-role policy.
    let mut anchors = match receiver.validate(
        &manifest,
        copies,
        OPERATION,
        "",
        Transport::Rights,
        &requirements(Owner::Host),
    ) {
        Ok(anchors) => anchors,
        Err(error) if error.kind == "anchor-owner" => receiver.validate(
            &manifest,
            descriptors,
            OPERATION,
            "",
            Transport::Rights,
            &requirements(Owner::RootFile),
        )?,
        Err(error) => return Err(error.into()),
    };
    let entry = anchors
        .iter()
        .position(|a| {
            nix::sys::stat::fstat(a.as_fd())
                .is_ok_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFREG)
        })
        .ok_or_else(|| refusal("anchor-kind", "entry-executable"))?;
    let executable = anchors.remove(entry);
    let running = nix::fcntl::open(
        "/proc/self/exe",
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?;
    let actual = nix::sys::stat::fstat(&running)?;
    let expected = nix::sys::stat::fstat(executable.as_fd())?;
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) {
        return Err(refusal("anchor-identity", "entry-executable"));
    }
    let anchor = Arc::new(
        anchors
            .pop()
            .ok_or_else(|| refusal("anchor-missing", "configuration"))?,
    );
    let file = configuration_file(&anchor, Path::new("mail-service.toml"))?;
    let settings = parse_settings(&super::io::bounded(&file, 4096)?)?;
    Ok(Entered {
        settings,
        configuration,
        anchor,
    })
}

pub(super) fn configuration_file(anchor: &Anchor, path: &Path) -> Result<File> {
    let fd = anchor.open_beneath(
        path,
        Policy {
            kind: Kind::File,
            owner: Owner::Host,
            mode: ModePolicy::Exact(0o600),
        },
        0o700,
    )?;
    Ok(File::from(fd))
}

pub(super) fn check_ancestry(home: &Path) -> Result<()> {
    let owner = nix::unistd::Uid::effective().as_raw();
    let owners = crate::ancestor::Owners::current(owner)
        .map_err(|e| MailError::Entry(format!("ancestor-uid-map: {e}")))?;
    let root = nix::fcntl::open(
        "/",
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?;
    owners
        .check(nix::sys::stat::fstat(&root)?.st_uid)
        .map_err(|e| MailError::Entry(format!("ancestor-unmapped-uid: /: {e}")))?;
    let pin = HostVerifier::current()?.pin(
        &home.join(".config/loops"),
        "configuration",
        0,
        directory_policy(),
    )?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: OPERATION.into(),
        loop_name: String::new(),
        records: vec![pin.record()],
    };
    Receiver::current()?.configuration(
        &manifest,
        &[pin.into_fd()],
        anchor::Entry {
            operation: OPERATION,
            loop_name: "",
            transport: Transport::Rights,
        },
        home,
        false,
    )?;
    Ok(())
}
