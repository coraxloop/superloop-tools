//! Runtime preparation keeps executable and worker-verification custody across entry.
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::error::LaneError;
use loop_home::anchor::{
    self, Anchor, Configuration, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver,
    Requirement, Transport,
};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use nix::sys::stat::fstat;

const OPERATION: &str = "prepare-runtime";
const PURPOSES: [&str; 9] = [
    "owner-home",
    "runs-root",
    "entry-executable",
    "podman-executable",
    "hash-executable",
    "configuration",
    "loop-storage",
    "private-storage",
    "identity-executable",
];
fn refusal(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("runtime-anchor", error.to_string())
}
fn named(kind: &str, purpose: &str) -> LaneError {
    named_for(OPERATION, kind, purpose)
}
fn named_for(operation: &str, kind: &str, purpose: &str) -> LaneError {
    refusal(format!("{kind}: operation={operation} purpose={purpose}"))
}
fn io(purpose: &str, check: &str, cause: impl std::fmt::Display) -> LaneError {
    io_for(OPERATION, purpose, check, cause)
}
fn io_for(operation: &str, purpose: &str, check: &str, cause: impl std::fmt::Display) -> LaneError {
    refusal(format!(
        "anchor-io: operation={operation} purpose={purpose} check={check}: {cause}"
    ))
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
pub(crate) fn directory_policy_for(
    operation: &str,
    fd: &impl AsFd,
    purpose: &str,
) -> Result<Policy, LaneError> {
    let mode = fstat(fd)
        .map_err(|e| io_for(operation, purpose, "fstat", e))?
        .st_mode
        & 0o7777;
    if mode & 0o7022 != 0 || mode & 0o700 != 0o700 {
        return Err(refusal(format_args!(
            "anchor-mode: operation={operation} purpose={purpose} check=directory-mode observed={mode:04o}"
        )));
    }
    Ok(directory(Owner::Host, mode))
}
fn pin_file(
    host: &HostVerifier,
    path: &Path,
    purpose: &str,
    slot: u32,
) -> Result<anchor::HostPin, LaneError> {
    host.pin(path, purpose, slot, executable(Owner::Host))
        .or_else(|e| {
            if e.kind == "anchor-owner" {
                host.pin(path, purpose, slot, executable(Owner::RootFile))
            } else {
                Err(e)
            }
        })
        .map_err(refusal)
}

fn pins(
    operation: &str,
    host: &HostVerifier,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    program: &Path,
    row: &loop_home::LoopRecord,
) -> Result<Vec<anchor::HostPin>, LaneError> {
    let (home, held_home) = home;
    let (runs, held_runs) = runs;
    let mut pins = Vec::new();
    for (slot, (path, held)) in [(home, held_home), (runs, held_runs)]
        .into_iter()
        .enumerate()
    {
        let pin = host
            .pin(
                path,
                PURPOSES[slot],
                u32::try_from(slot).map_err(refusal)?,
                directory_policy_for(operation, held, PURPOSES[slot])?,
            )
            .map_err(refusal)?;
        let expected =
            fstat(held).map_err(|e| io_for(operation, PURPOSES[slot], "held-stat", e))?;
        if (pin.record().device, pin.record().inode) != (expected.st_dev, expected.st_ino) {
            return Err(named_for(operation, "anchor-identity", PURPOSES[slot]));
        }
        pins.push(pin);
    }
    for (slot, path) in [
        (2, entry),
        (3, program),
        (4, Path::new("/usr/bin/sha256sum")),
    ] {
        pins.push(pin_file(
            host,
            path,
            PURPOSES[slot],
            u32::try_from(slot).map_err(refusal)?,
        )?);
    }
    for (slot, path, policy) in [
        (5, home.join(".config/loops"), directory(Owner::Host, 0o700)),
        (6, row.home.clone(), directory(Owner::Host, 0o711)),
        (
            7,
            row.home.join("private"),
            directory(Owner::Mapped(row.uid), 0o700),
        ),
        (8, "/usr/bin/setpriv".into(), executable(Owner::RootFile)),
    ] {
        pins.push(
            host.pin(
                &path,
                PURPOSES[slot],
                u32::try_from(slot).map_err(refusal)?,
                policy,
            )
            .map_err(refusal)?,
        );
    }
    Ok(pins)
}

/// Compose the production runtime vector with one complete rights frame.
/// # Errors
/// Refuses unsafe host custody, a mismatched private vector or invalid configuration.
pub fn command(
    program: &Path,
    argv: &[String],
    home: &Path,
    held_home: &OwnedFd,
    runs: &Path,
    held_runs: &OwnedFd,
) -> Result<CommandSpec, LaneError> {
    let [
        unshare,
        entry,
        mode,
        scope,
        _run,
        home_flag,
        home_word,
        podman_flag,
        podman,
    ] = argv
    else {
        return Err(named("anchor-declaration", "vector"));
    };
    if unshare != "unshare"
        || mode != "_prepare-runtime"
        || home_flag != "--owner-home"
        || Path::new(home_word) != home
        || podman_flag != "--podman-bin"
        || Path::new(podman) != program
    {
        return Err(named("anchor-declaration", "vector"));
    }
    let pins = core_pins(
        OPERATION,
        scope,
        (home, held_home),
        (runs, held_runs),
        Path::new(entry),
        program,
    )?;
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: OPERATION.into(),
        loop_name: scope.into(),
        records: pins.iter().map(anchor::HostPin::record).collect(),
    };
    let declaration = serde_json::to_string(&manifest).map_err(refusal)?;
    Manifest::parse(&declaration).map_err(refusal)?;
    let (sender, input) = UnixStream::pair().map_err(|e| io("rights", "socket-pair", e))?;
    anchor::transport::send(
        &sender,
        &pins
            .into_iter()
            .map(anchor::HostPin::into_fd)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| refusal(e.context(OPERATION, "rights")))?;
    let mut words = vec![crate::pinned::path_word(program, "namespace-program")?];
    words.extend(argv.iter().cloned());
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs, "runs-root")?,
        "--anchor-manifest".into(),
        declaration,
    ]);
    Ok(CommandSpec {
        label: OPERATION.into(),
        argv: words,
        io: IoMode::Capture,
        descriptors: CommandDescriptors::default().with_input(input.into()),
    })
}

pub(crate) fn core_pins(
    operation: &str,
    scope: &str,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    program: &Path,
) -> Result<Vec<anchor::HostPin>, LaneError> {
    let (home, held_home) = home;
    let (runs, held_runs) = runs;
    let host = HostVerifier::current()
        .map_err(refusal)?
        .for_operation(operation);
    let config = host
        .pin(
            &home.join(".config/loops"),
            "configuration",
            0,
            directory(Owner::Host, 0o700),
        )
        .map_err(refusal)?;
    let bootstrap = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.into(),
        loop_name: scope.into(),
        records: vec![config.record()],
    };
    let config = Receiver::current()
        .map_err(refusal)?
        .configuration(
            &bootstrap,
            &[config.into_fd()],
            anchor::Entry {
                operation,
                loop_name: scope,
                transport: Transport::Rights,
            },
            home,
            false,
        )
        .map_err(refusal)?;
    let row = config.registry.row(scope, home).map_err(refusal)?;
    pins(
        operation,
        &host,
        (home, held_home),
        (runs, held_runs),
        entry,
        program,
        &row,
    )
}

/// Validated configuration and worker storage for the runtime's one birth check.
pub struct Custody {
    pub(crate) configuration: Configuration,
    pub(crate) root: Anchor,
    pub(crate) private: Anchor,
    pub(crate) executor: Anchor,
}
impl Custody {
    pub(crate) fn create_birth(
        &self,
        home: &Path,
        scope: &str,
        identity: &loop_home::mail::birth::Identity,
        phase: &str,
    ) -> Result<(), loop_home::mail::journal::MailError> {
        loop_home::mail::worker_provision::creation_beneath(
            home,
            scope,
            identity,
            phase,
            &self.configuration,
            &self.root,
            &self.private,
            &self.executor,
        )
    }
    pub(crate) fn verify_birth(
        &self,
        home: &Path,
        scope: &str,
        identity: &loop_home::mail::birth::Identity,
    ) -> Result<(), loop_home::mail::journal::MailError> {
        loop_home::mail::worker_provision::verify_beneath(
            home,
            scope,
            identity,
            &self.configuration,
            &self.root,
            &self.private,
            &self.executor,
        )
    }
}

fn receive(
    source: &str,
    scope: &str,
    home: &str,
) -> Result<(Configuration, Vec<Anchor>), LaneError> {
    receive_bundle(source, scope, home, OPERATION, &[])
}

pub(crate) fn receive_bundle(
    source: &str,
    scope: &str,
    home: &str,
    operation: &str,
    extras: &[Requirement],
) -> Result<(Configuration, Vec<Anchor>), LaneError> {
    let manifest = Manifest::parse(source).map_err(refusal)?;
    if manifest.records.len() != PURPOSES.len() + extras.len() {
        return Err(named_for(operation, "anchor-declaration", "count"));
    }
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| io_for(operation, "rights", "input-duplicate", e))?;
    let descriptors = anchor::transport::receive(
        &UnixStream::from(input),
        PURPOSES.len() + extras.len(),
        Duration::from_secs(30),
    )
    .map_err(|e| refusal(e.context(operation, "rights")))?;
    anchor::transport::replace_stdin(operation).map_err(refusal)?;
    let receiver = Receiver::current().map_err(refusal)?;
    let configuration = receiver
        .configuration(
            &manifest,
            &descriptors,
            anchor::Entry {
                operation,
                loop_name: scope,
                transport: Transport::Rights,
            },
            Path::new(home),
            false,
        )
        .map_err(refusal)?;
    let row = configuration
        .registry
        .row(scope, Path::new(home))
        .map_err(refusal)?;
    let mut policies = Vec::new();
    for (slot, purpose) in PURPOSES.iter().enumerate() {
        let record = manifest
            .records
            .iter()
            .find(|r| r.purpose == *purpose)
            .ok_or_else(|| named_for(operation, "anchor-declaration", "roles"))?;
        if usize::try_from(record.slot).map_err(refusal)? != slot {
            return Err(named_for(operation, "anchor-declaration", "slots"));
        }
        let policy = match slot {
            0 | 1 => directory_policy_for(operation, &descriptors[slot], purpose)?,
            2..=4 => executable(if record.owner_uid == 0 {
                Owner::RootFile
            } else {
                Owner::Host
            }),
            5 => directory(Owner::Host, 0o700),
            6 => directory(Owner::Host, 0o711),
            7 => directory(Owner::Mapped(row.uid), 0o700),
            _ => executable(Owner::RootFile),
        };
        policies.push(Requirement {
            purpose: (*purpose).into(),
            policy,
            alias_group: (slot < 2
                && extras
                    .iter()
                    .any(|extra| extra.policy.kind == Kind::Directory))
            .then(|| "launch-directory".into()),
        });
    }
    for (index, requirement) in extras.iter().enumerate() {
        let record = manifest
            .records
            .iter()
            .find(|record| record.purpose == requirement.purpose)
            .ok_or_else(|| named_for(operation, "anchor-declaration", "roles"))?;
        if usize::try_from(record.slot).map_err(refusal)? != PURPOSES.len() + index {
            return Err(named_for(operation, "anchor-declaration", "slots"));
        }
        let mut requirement = requirement.clone();
        if requirement.policy.kind == Kind::Directory {
            requirement.policy = directory_policy_for(
                operation,
                &descriptors[PURPOSES.len() + index],
                &requirement.purpose,
            )?;
            requirement.alias_group = Some("launch-directory".into());
        }
        policies.push(requirement);
    }
    let anchors = receiver
        .validate(
            &manifest,
            descriptors,
            operation,
            scope,
            Transport::Rights,
            &policies,
        )
        .map_err(refusal)?;
    Ok((configuration, anchors))
}

/// Validate the complete runtime bundle before invoking preparation.
/// # Errors
/// Refuses absent, substituted or inconsistent custody before reading a protected plan.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    let [
        mode,
        scope,
        run,
        home_flag,
        home,
        podman_flag,
        podman,
        runs_flag,
        runs,
        manifest_flag,
        source,
    ] = args
    else {
        // A word beyond the complete frame is a malformed declaration, not a missing one.
        return Err(if args.len() > 11 {
            named("anchor-declaration", "vector")
        } else {
            named("anchor-missing", "manifest")
        });
    };
    if mode != "_prepare-runtime"
        || home_flag != "--owner-home"
        || podman_flag != "--podman-bin"
        || runs_flag != "--verified-runs-root"
        || manifest_flag != "--anchor-manifest"
        || !Path::new(home).is_absolute()
        || !Path::new(runs).is_absolute()
        || !Path::new(podman).is_absolute()
    {
        return Err(named("anchor-declaration", "vector"));
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Err(named("anchor-owner", "namespace"));
    }
    let (configuration, anchors) = receive(source, scope, home)?;
    let mut anchors = anchors.into_iter();
    let mut next = || {
        anchors
            .next()
            .ok_or_else(|| named("anchor-missing", "bundle"))
    };
    let home_anchor = next()?;
    let runs_anchor = next()?;
    let entry = next()?;
    let podman_anchor = next()?;
    let hash = next()?;
    let _config = next()?;
    let custody = Custody {
        configuration,
        root: next()?,
        private: next()?,
        executor: next()?,
    };
    let image = std::fs::File::open("/proc/self/exe")
        .map_err(|e| io("entry-executable", "self-image-open", e))?;
    let actual = fstat(&image).map_err(|e| io("entry-executable", "self-image-stat", e))?;
    let expected = fstat(&entry).map_err(|e| io("entry-executable", "held-stat", e))?;
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) {
        return Err(named("anchor-identity", "entry-executable"));
    }
    let _home = crate::home::activate_private_launch(
        Path::new(home),
        &home_anchor,
        Path::new(runs),
        &runs_anchor,
        None,
        0,
    )?;
    let _programs = crate::container_entry::activate_programs(
        OPERATION,
        Path::new(podman),
        podman_anchor,
        hash,
    );
    crate::launch::private_prepare_runtime(Path::new(home), scope, run, Path::new(podman), &custody)
}

/// Describe custody that is pinned only by the changing launch.
pub(crate) fn preview() -> serde_json::Value {
    serde_json::json!({"state":"bound-on-launch","transport":"rights","operation":OPERATION,"purposes":PURPOSES})
}
