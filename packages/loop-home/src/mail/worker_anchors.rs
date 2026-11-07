//! Worker lifetime capabilities across namespace entry and identity children.
use super::birth::Identity;
use super::journal::{MailError, Result};
use crate::anchor::{
    self, Anchor, Configuration, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver,
    Requirement, Transport,
};
use crate::{CommandDescriptors, CommandSpec, IoMode, LoopRecord};
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

fn refusal(operation: &str, purpose: &str, kind: &str) -> MailError {
    MailError::Entry(format!("{kind}: operation={operation} purpose={purpose}"))
}
fn operation(mode: &str, phase: &str) -> Result<String> {
    if mode == "_mail-worker-birth"
        && matches!(
            phase,
            "reserve" | "finish" | "retire" | "verify" | "verify-only"
        )
    {
        Ok(format!("mail-worker-birth-{phase}"))
    } else if mode == "_mail-worker-home" && super::valid_identity_name(phase) {
        Ok("mail-worker-home".into())
    } else {
        Err(refusal("mail-worker", "operation", "anchor-declaration"))
    }
}
const fn directory(owner: Owner, mode: u32) -> Policy {
    Policy {
        kind: Kind::Directory,
        owner,
        mode: ModePolicy::Exact(mode),
    }
}
const fn executable(owner: Owner) -> Policy {
    Policy {
        kind: Kind::File,
        owner,
        mode: ModePolicy::Executable,
    }
}
fn pin_executable(
    host: &HostVerifier,
    path: &Path,
    purpose: &str,
    slot: u32,
) -> Result<anchor::HostPin> {
    host.pin(path, purpose, slot, executable(Owner::Host))
        .or_else(|error| {
            if error.kind == "anchor-owner" {
                host.pin(path, purpose, slot, executable(Owner::RootFile))
            } else {
                Err(error)
            }
        })
        .map_err(Into::into)
}
fn requirement(purpose: &str, policy: Policy) -> Requirement {
    Requirement {
        purpose: purpose.into(),
        policy,
        alias_group: None,
    }
}
fn policies(
    row: &LoopRecord,
    service: u32,
    mode: &str,
    phase: &str,
    entry_owner: Owner,
) -> Vec<Requirement> {
    let mut result = vec![
        requirement("configuration", directory(Owner::Host, 0o700)),
        requirement("entry-executable", executable(entry_owner)),
        requirement("loop-storage", directory(Owner::Host, 0o711)),
    ];
    if mode == "_mail-worker-birth" {
        result.push(requirement(
            "private-storage",
            directory(Owner::Mapped(row.uid), 0o700),
        ));
        result.push(requirement(
            "identity-executable",
            executable(Owner::RootFile),
        ));
    }
    if mode == "_mail-worker-birth" && phase == "retire" {
        result.push(requirement(
            "journal-storage",
            directory(Owner::Mapped(service), 0o700),
        ));
    }
    result
}

fn host_configuration(
    host: &HostVerifier,
    home: &Path,
    loop_name: &str,
    operation: &str,
) -> Result<Configuration> {
    let config = host.pin(
        &home.join(".config/loops"),
        "configuration",
        0,
        directory(Owner::Host, 0o700),
    )?;
    let bootstrap = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.into(),
        loop_name: loop_name.into(),
        records: vec![config.record()],
    };
    let descriptors = vec![config.into_fd()];
    Receiver::current()?
        .configuration(
            &bootstrap,
            &descriptors,
            anchor::Entry {
                operation,
                loop_name,
                transport: Transport::Rights,
            },
            home,
            false,
        )
        .map_err(Into::into)
}

/// Compose the host-owned worker birth or retirement entry with its capability bundle.
/// The namespace vector is supplied by the owning launcher, not by worker input.
/// # Errors
/// Refuses invalid grants, unsafe custody, missing programs and failed descriptor transport.
pub fn command(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    mode: &str,
    phase: &str,
    entry: &Path,
    namespace: &[String],
) -> Result<CommandSpec> {
    let operation = operation(mode, phase)?;
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(refusal(
            &operation,
            "registry-override",
            "anchor-declaration",
        ));
    }
    let host = HostVerifier::current()
        .map_err(|e| e.context(&operation, "host-map"))?
        .for_operation(&operation);
    let word = namespace
        .first()
        .ok_or_else(|| refusal(&operation, "namespace-entry", "anchor-exec"))?;
    let program = if Path::new(word).is_absolute() {
        std::path::PathBuf::from(word)
    } else if Path::new(word).components().count() == 1 {
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .map(|path| path.join(word))
            .find(|path| path.is_absolute() && path.is_file())
            .ok_or_else(|| refusal(&operation, "namespace-entry", "anchor-exec"))?
    } else {
        return Err(refusal(&operation, "namespace-entry", "anchor-exec"));
    };
    let _namespace = pin_executable(&host, &program, "namespace-entry", 0)?;
    let configuration = host_configuration(&host, home, loop_name, &operation)?;
    let row = configuration
        .registry
        .row(loop_name, home)
        .map_err(|e| MailError::Entry(e.to_string()))?;
    let service = configuration
        .allocations
        .mail_uid()
        .ok_or_else(|| refusal(&operation, "mail-grant", "anchor-owner"))?;
    let required = policies(&row, service, mode, phase, Owner::Host);
    let mut pins = Vec::new();
    for (index, requirement) in required.iter().enumerate() {
        let slot =
            u32::try_from(index).map_err(|_| refusal(&operation, "slot", "anchor-declaration"))?;
        let path = match requirement.purpose.as_str() {
            "configuration" => home.join(".config/loops"),
            "entry-executable" => entry.to_path_buf(),
            "loop-storage" => row.home.clone(),
            "private-storage" => row.home.join("private"),
            "identity-executable" => Path::new("/usr/bin/setpriv").to_path_buf(),
            "journal-storage" => home.join(".var/loops/.mail-service"),
            _ => return Err(refusal(&operation, "purpose", "anchor-declaration")),
        };
        pins.push(if requirement.purpose == "entry-executable" {
            pin_executable(&host, &path, &requirement.purpose, slot)?
        } else {
            host.pin(&path, &requirement.purpose, slot, requirement.policy)?
        });
    }
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.clone(),
        loop_name: loop_name.into(),
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let declaration =
        serde_json::to_string(&manifest).map_err(|e| MailError::Entry(e.to_string()))?;
    Manifest::parse(&declaration)?;
    let (sender, input) = UnixStream::pair()?;
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| e.context(&operation, "rights"))?;
    let mut argv = namespace.to_vec();
    argv[0] = program.to_string_lossy().into_owned();
    argv.extend([
        entry.to_string_lossy().into_owned(),
        mode.into(),
        home.to_string_lossy().into_owned(),
        loop_name.into(),
        phase.into(),
        identity.name.clone(),
        identity.uid.to_string(),
        identity.reservation.clone(),
        "--anchor-manifest".into(),
        declaration,
    ]);
    Ok(CommandSpec {
        label: operation,
        argv,
        io: IoMode::Inherit,
        descriptors: CommandDescriptors::default().with_input(input.into()),
    })
}

pub(super) struct Entered {
    pub row: LoopRecord,
    pub configuration: Configuration,
    pub root: File,
    pub private: Option<Anchor>,
    pub journal: Option<Anchor>,
    pub identity_executable: Option<Anchor>,
}
pub(super) fn receive(
    home: &Path,
    loop_name: &str,
    mode: &str,
    phase: &str,
    declaration: &str,
) -> Result<Entered> {
    let operation = operation(mode, phase)?;
    let manifest = Manifest::parse(declaration).map_err(|e| e.context(&operation, "manifest"))?;
    let input = nix::unistd::dup(std::io::stdin().as_fd())?;
    if nix::sys::stat::fstat(&input)?.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(refusal(&operation, "rights", "anchor-missing"));
    }
    let descriptors = anchor::transport::receive(
        &UnixStream::from(input),
        manifest.records.len(),
        Duration::from_secs(30),
    )
    .map_err(|e| e.context(&operation, "rights"))?;
    nix::unistd::close(0)?;
    let receiver = Receiver::current().map_err(|e| e.context(&operation, "receiver-map"))?;
    let configuration = receiver.configuration(
        &manifest,
        &descriptors,
        anchor::Entry {
            operation: &operation,
            loop_name,
            transport: Transport::Rights,
        },
        home,
        false,
    )?;
    let row = configuration
        .registry
        .row(loop_name, home)
        .map_err(|e| MailError::Entry(e.to_string()))?;
    let service = configuration
        .allocations
        .mail_uid()
        .ok_or_else(|| refusal(&operation, "mail-grant", "anchor-owner"))?;
    let copies = descriptors
        .iter()
        .map(OwnedFd::try_clone)
        .collect::<std::io::Result<Vec<_>>>()?;
    let anchors = match receiver.validate(
        &manifest,
        copies,
        &operation,
        loop_name,
        Transport::Rights,
        &policies(&row, service, mode, phase, Owner::Host),
    ) {
        Ok(anchors) => anchors,
        Err(e) if e.kind == "anchor-owner" && e.purpose() == "entry-executable" => receiver
            .validate(
                &manifest,
                descriptors,
                &operation,
                loop_name,
                Transport::Rights,
                &policies(&row, service, mode, phase, Owner::RootFile),
            )?,
        Err(e) => return Err(e.into()),
    };
    let mut named = std::collections::BTreeMap::new();
    for (record, anchor) in manifest.records.iter().zip(anchors) {
        named.insert(record.purpose.as_str(), anchor);
    }
    let entry = named
        .remove("entry-executable")
        .ok_or_else(|| refusal(&operation, "entry-executable", "anchor-missing"))?;
    let image = File::open("/proc/self/exe")?;
    let actual = nix::sys::stat::fstat(&image)?;
    let expected = nix::sys::stat::fstat(entry.as_fd())?;
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) {
        return Err(refusal(&operation, "entry-executable", "anchor-identity"));
    }
    if mode == "_mail-worker-birth" && phase == "retire" {
        let config = named
            .get("configuration")
            .ok_or_else(|| refusal(&operation, "configuration", "anchor-missing"))?;
        let settings =
            super::entry_anchors::configuration_file(config, Path::new("mail-service.toml"))?;
        if super::command::parse_settings(&super::io::bounded(&settings, 4096)?)?.uid != service {
            return Err(refusal(&operation, "mail-settings", "anchor-owner"));
        }
    }
    let root = named
        .remove("loop-storage")
        .ok_or_else(|| refusal(&operation, "loop-storage", "anchor-missing"))?;
    let root = File::from(nix::unistd::dup(root.as_fd())?);
    let root = super::io::child(&root, Path::new("."), true)?;
    Ok(Entered {
        row,
        configuration,
        root,
        private: named.remove("private-storage"),
        journal: named.remove("journal-storage"),
        identity_executable: named.remove("identity-executable"),
    })
}

pub(super) fn relay(anchor: &Anchor, mode: &str) -> Result<(String, OwnedFd)> {
    let (record, fd) = anchor.relay()?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Inherit,
        operation: mode.trim_start_matches('_').into(),
        loop_name: String::new(),
        records: vec![record],
    };
    Ok((
        serde_json::to_string(&manifest).map_err(|e| MailError::Entry(e.to_string()))?,
        fd,
    ))
}

#[allow(unsafe_code)]
pub(super) fn receive_child(mode: &str, declaration: &str) -> Result<Anchor> {
    use std::os::fd::FromRawFd as _;
    let operation = mode.trim_start_matches('_');
    let mut manifest =
        Manifest::parse(declaration).map_err(|e| e.context(operation, "manifest"))?;
    if manifest.records.len() != 1 || manifest.records[0].slot < 3 {
        return Err(refusal(operation, "inherit", "anchor-declaration"));
    }
    let number = i32::try_from(manifest.records[0].slot)
        .map_err(|_| refusal(operation, "inherit", "anchor-declaration"))?;
    // Keep ownership of the caller's descriptor with the caller. The duplicate
    // binds the same open description, and both handles become close-on-exec.
    let fd = unsafe {
        let duplicate = libc::fcntl(number, libc::F_DUPFD_CLOEXEC, 3);
        if duplicate == -1 {
            return Err(refusal(operation, "inherit", "anchor-missing"));
        }
        let fd = OwnedFd::from_raw_fd(duplicate);
        if libc::fcntl(number, libc::F_SETFD, libc::FD_CLOEXEC) == -1 {
            return Err(refusal(operation, "inherit", "anchor-missing"));
        }
        fd
    };
    manifest.records[0].slot = u32::try_from(fd.as_raw_fd())
        .map_err(|_| refusal(operation, "inherit", "anchor-declaration"))?;
    let purpose = if mode == "_mail-worker-state" {
        "private-storage"
    } else {
        "journal-storage"
    };
    let mut anchors = Receiver::current()?.validate(
        &manifest,
        vec![fd],
        operation,
        "",
        Transport::Inherit,
        &[requirement(
            purpose,
            directory(Owner::Mapped(nix::unistd::geteuid().as_raw()), 0o700),
        )],
    )?;
    anchors
        .pop()
        .ok_or_else(|| refusal(operation, purpose, "anchor-missing"))
}

pub(super) fn child(
    uid: u32,
    group: u32,
    anchor: &Anchor,
    executor: &Anchor,
    arguments: &[OsString],
) -> Result<()> {
    let mode = arguments
        .first()
        .and_then(|s| s.to_str())
        .ok_or_else(|| refusal("mail-worker", "child", "anchor-declaration"))?;
    let (declaration, fd) = relay(anchor, mode)?;
    let image = File::open("/proc/self/exe")?;
    let mut command = std::process::Command::new("/usr/bin/setpriv");
    let mut argv = vec![
        OsString::from("setpriv"),
        format!("--reuid={uid}").into(),
        format!("--regid={uid}").into(),
        format!("--groups={group}").into(),
        "--no-new-privs".into(),
        format!("/proc/self/fd/{}", image.as_raw_fd()).into(),
    ];
    argv.extend_from_slice(arguments);
    argv.extend(["--anchor-manifest".into(), declaration.into()]);
    command.args(&argv[1..]);
    CommandDescriptors::inherit(vec![image.into(), fd])?.configure(&mut command)?;
    executor.configure_exec(
        &mut command,
        &argv,
        &std::env::vars_os().collect::<Vec<_>>(),
    )?;
    let status = command.status().map_err(|error| {
        MailError::Entry(format!(
            "anchor-exec: operation=mail-worker purpose=identity-executable: {error}"
        ))
    })?;
    // The child reports its own anchor cause; its exit keeps the legacy outer refusal.
    if !status.success() {
        return Err(MailError::Invalid(
            "unsafe-storage: identity provisioning step refused",
        ));
    }
    Ok(())
}
