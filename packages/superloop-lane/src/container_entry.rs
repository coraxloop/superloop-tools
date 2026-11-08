//! Operation-bound executable custody for the namespace container helper.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use loop_home::anchor::{
    self, Anchor, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement,
    Transport,
};
use nix::sys::stat::fstat;

use crate::{error::LaneError, settings::BoxBackend};

const OPERATION: &str = "container-helper";
const PURPOSES: [&str; 8] = [
    "owner-home",
    "runs-root",
    "entry-executable",
    "podman-executable",
    "hash-executable",
    "credential-client",
    "credential-clock",
    "configuration",
];
const EXERCISE_PURPOSES: [&str; 6] = [
    "owner-home",
    "runs-root",
    "entry-executable",
    "podman-executable",
    "hash-executable",
    "configuration",
];
const CLAUDE_PURPOSES: [&str; 8] = [
    "owner-home",
    "runs-root",
    "entry-executable",
    "podman-executable",
    "hash-executable",
    "credential-claude",
    "credential-clock",
    "configuration",
];
pub(crate) const fn credential_client(backend: BoxBackend) -> &'static str {
    match backend {
        BoxBackend::Codex => "/usr/bin/curl",
        BoxBackend::Claude => "/usr/bin/claude",
    }
}
fn purposes(operation: &str, backend: BoxBackend) -> &'static [&'static str] {
    if operation == OPERATION {
        if backend == BoxBackend::Claude {
            &CLAUDE_PURPOSES
        } else {
            &PURPOSES
        }
    } else {
        &EXERCISE_PURPOSES
    }
}
/// Name the helper bundle's roles in slot order for the protected backend.
pub(crate) fn helper_purposes(backend: BoxBackend) -> &'static [&'static str] {
    purposes(OPERATION, backend)
}

const fn configuration_policy() -> Policy {
    Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(0o700),
    }
}
pub(crate) fn operation_error(operation: &str, error: impl std::fmt::Display) -> LaneError {
    let kind = match operation {
        "prepare-runtime" => "runtime-anchor",
        "make-home" => "creation-anchor",
        op if op.starts_with("exercise-") => "exercise-anchor",
        _ => "container-anchor",
    };
    LaneError::input(kind, error.to_string())
}
pub(crate) fn registry_override(operation: &str) -> Result<(), LaneError> {
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        return Err(operation_error(
            operation,
            format!("anchor-declaration: operation={operation} purpose=registry-override"),
        ));
    }
    Ok(())
}
pub(crate) fn configuration(
    home: &Path,
    scope: &str,
    operation: &'static str,
    anchor: Anchor,
) -> Result<crate::runtime_entry::ConfigurationGuard, LaneError> {
    registry_override(operation)?;
    let configuration = anchor
        .read_configuration(home, false)
        .map_err(|error| operation_error(operation, error))?;
    configuration
        .registry
        .row(scope, home)
        .map_err(|error| operation_error(operation, format!(
            "anchor-declaration: operation={operation} purpose=configuration check=registry-row: {error}"
        )))?;
    Ok(crate::runtime_entry::activate_configuration(
        home,
        &configuration,
        Arc::new(anchor),
        operation,
    ))
}
fn refusal(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("container-anchor", error.to_string())
}

fn io_refusal(
    operation: &str,
    purpose: &str,
    check: &str,
    cause: impl std::fmt::Display,
) -> LaneError {
    refusal(format!(
        "anchor-io: operation={operation} purpose={purpose} check={check}: {cause}"
    ))
}

pub(crate) fn directory_policy(
    operation: &str,
    fd: &impl AsFd,
    purpose: &str,
) -> Result<Policy, LaneError> {
    let stat = fstat(fd).map_err(|error| io_refusal(operation, purpose, "fstat", error))?;
    let mode = stat.st_mode & 0o7777;
    if mode & 0o7022 != 0 || mode & 0o700 != 0o700 {
        return Err(refusal(format_args!(
            "anchor-mode: operation={operation} purpose={purpose} check=directory-mode observed={mode:04o}"
        )));
    }
    Ok(Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(mode),
    })
}

pub(crate) const fn executable_policy(owner: Owner) -> Policy {
    Policy {
        kind: Kind::File,
        owner,
        mode: ModePolicy::Executable,
    }
}

/// Keep the complete transfer live through bootstrap and sending.
pub(crate) struct Bundle {
    pub(crate) manifest: String,
    pub(crate) descriptors: Vec<OwnedFd>,
}

/// Verify the host chain and bind existing directory custody to the same identities.
pub(crate) fn pin(
    loop_name: &str,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    podman: &Path,
    backend: BoxBackend,
) -> Result<Bundle, LaneError> {
    pin_for_backend(OPERATION, loop_name, home, runs, entry, podman, backend)
}

pub(crate) fn core_pins(
    verifier: &HostVerifier,
    operation: &str,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    podman: &Path,
) -> Result<Vec<anchor::HostPin>, LaneError> {
    let mut pins = Vec::new();
    for (slot, (path, held)) in [home, runs].into_iter().enumerate() {
        let pin = verifier
            .pin(
                path,
                PURPOSES[slot],
                u32::try_from(slot).map_err(refusal)?,
                directory_policy(operation, held, PURPOSES[slot])?,
            )
            .map_err(refusal)?;
        let record = pin.record();
        let actual = fstat(held)
            .map_err(|error| io_refusal(operation, PURPOSES[slot], "held-stat", error))?;
        if (record.device, record.inode) != (actual.st_dev, actual.st_ino) {
            return Err(refusal(format!(
                "anchor-identity: operation={operation} purpose={}",
                PURPOSES[slot]
            )));
        }
        pins.push(pin);
    }
    for (slot, path) in [
        (2, entry),
        (3, podman),
        (4, Path::new("/usr/bin/sha256sum")),
    ] {
        let index = u32::try_from(slot).map_err(refusal)?;
        let pin = verifier
            .pin(path, PURPOSES[slot], index, executable_policy(Owner::Host))
            .or_else(|error| {
                if error.kind == "anchor-owner" {
                    verifier.pin(
                        path,
                        PURPOSES[slot],
                        index,
                        executable_policy(Owner::RootFile),
                    )
                } else {
                    Err(error)
                }
            })
            .map_err(refusal)?;
        pins.push(pin);
    }
    Ok(pins)
}

pub(crate) fn pin_for(
    operation: &'static str,
    loop_name: &str,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    podman: &Path,
) -> Result<Bundle, LaneError> {
    pin_for_backend(
        operation,
        loop_name,
        home,
        runs,
        entry,
        podman,
        BoxBackend::Codex,
    )
}

fn pin_for_backend(
    operation: &'static str,
    loop_name: &str,
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    entry: &Path,
    podman: &Path,
    backend: BoxBackend,
) -> Result<Bundle, LaneError> {
    registry_override(operation)?;
    let verifier = HostVerifier::current()
        .map_err(refusal)?
        .for_operation(operation);
    let pins = core_pins(&verifier, operation, home, runs, entry, podman)?;
    let mut records = Vec::new();
    let mut descriptors = Vec::new();
    for pin in pins {
        records.push(pin.record());
        descriptors.push(pin.into_fd());
    }
    if operation == OPERATION {
        for (slot, path) in [(5, credential_client(backend)), (6, "/usr/bin/date")] {
            let pin = verifier
                .pin(
                    Path::new(path),
                    purposes(operation, backend)[slot],
                    u32::try_from(slot).map_err(refusal)?,
                    executable_policy(Owner::RootFile),
                )
                .map_err(refusal)?;
            records.push(pin.record());
            descriptors.push(pin.into_fd());
        }
    }
    let pin = verifier
        .pin(
            &home.0.join(".config/loops"),
            "configuration",
            u32::try_from(records.len()).map_err(refusal)?,
            configuration_policy(),
        )
        .map_err(refusal)?;
    records.push(pin.record());
    descriptors.push(pin.into_fd());
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.into(),
        loop_name: loop_name.into(),
        records,
    };
    Ok(Bundle {
        manifest: serde_json::to_string(&manifest).map_err(refusal)?,
        descriptors,
    })
}

thread_local! {
    static ACTIVE_OPERATION: Cell<&'static str> = const { Cell::new(OPERATION) };
    static EXECUTABLE: RefCell<Option<BTreeMap<PathBuf, Arc<Anchor>>>> = const { RefCell::new(None) };
}

pub(crate) struct ExecutableGuard;
impl Drop for ExecutableGuard {
    fn drop(&mut self) {
        EXECUTABLE.with(|active| *active.borrow_mut() = None);
        ACTIVE_OPERATION.with(|operation| operation.set(OPERATION));
    }
}

/// Bind only the named executable capabilities for this private operation.
pub(crate) fn activate_programs(
    operation: &'static str,
    podman: &Path,
    executable: Anchor,
    hash: Anchor,
) -> ExecutableGuard {
    activate_program_map(
        operation,
        BTreeMap::from([
            (podman.to_path_buf(), Arc::new(executable)),
            (PathBuf::from("/usr/bin/sha256sum"), Arc::new(hash)),
        ]),
    )
}

pub(crate) fn activate_program_map(
    operation: &'static str,
    programs: BTreeMap<PathBuf, Arc<Anchor>>,
) -> ExecutableGuard {
    ACTIVE_OPERATION.with(|active| active.set(operation));
    EXECUTABLE.with(|active| *active.borrow_mut() = Some(programs));
    ExecutableGuard
}

/// Transfer only the credential executables to the authority thread.
pub(crate) fn credential_programs(
    backend: BoxBackend,
) -> Result<Option<BTreeMap<PathBuf, Arc<Anchor>>>, LaneError> {
    EXECUTABLE.with(|active| {
        let active = active.borrow();
        let Some(programs) = active.as_ref() else {
            return Ok(None);
        };
        [credential_client(backend), "/usr/bin/date"]
            .into_iter()
            .map(|path| {
                let key = PathBuf::from(path);
                let anchor = programs.get(&key).ok_or_else(|| active_error(format!(
                    "anchor-missing: operation={} purpose=credential-executable backend={} program={path}",
                    ACTIVE_OPERATION.with(Cell::get), backend.name()
                )))?;
                Ok((key, Arc::clone(anchor)))
            })
            .collect::<Result<BTreeMap<_, _>, LaneError>>()
            .map(Some)
    })
}

fn active_error(error: impl std::fmt::Display) -> LaneError {
    operation_error(ACTIVE_OPERATION.with(Cell::get), error)
}

fn active_refusal() -> LaneError {
    active_error(format!(
        "anchor-declaration: operation={} purpose=program",
        ACTIVE_OPERATION.with(Cell::get)
    ))
}

/// Recheck the held executable when this operation selected the program.
pub(crate) fn check(program: &Path) -> Option<Result<(), LaneError>> {
    EXECUTABLE.with(|active| {
        active.borrow().as_ref().map(|programs| {
            programs
                .get(program)
                .ok_or_else(active_refusal)?
                .revalidate()
                .map_err(active_error)
        })
    })
}

/// Keep a failed descriptor execution named at the runner's spawn boundary.
pub(crate) fn spawn_error(program: &Path, kind: &'static str, error: &std::io::Error) -> LaneError {
    EXECUTABLE.with(|active| {
        if active
            .borrow()
            .as_ref()
            .is_some_and(|programs| programs.contains_key(program))
        {
            let purpose = if program == Path::new("/usr/bin/sha256sum") {
                "hash-executable"
            } else if program == Path::new("/usr/bin/curl") {
                "credential-client"
            } else if program == Path::new("/usr/bin/claude") {
                "credential-claude"
            } else if program == Path::new("/usr/bin/date") {
                "credential-clock"
            } else {
                "podman-executable"
            };
            LaneError::operation(
                "anchor-exec",
                format!(
                    "operation={} purpose={purpose} check=child-spawn: {error}",
                    ACTIVE_OPERATION.with(Cell::get)
                ),
            )
        } else {
            LaneError::operation(kind, format!("{}: {error}", program.display()))
        }
    })
}

/// Install descriptor execution after every other child setup hook.
pub(crate) fn configure(
    command: &mut Command,
    program: &Path,
    argv: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<(), LaneError> {
    EXECUTABLE.with(|active| {
        let active = active.borrow();
        let Some(programs) = active.as_ref() else {
            return Ok(());
        };
        let anchor = programs.get(program).ok_or_else(active_refusal)?;
        let arguments = std::iter::once(program.as_os_str().to_owned())
            .chain(argv.iter().map(OsString::from))
            .collect::<Vec<_>>();
        let environment = environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect::<Vec<_>>();
        anchor
            .configure_exec(command, &arguments, &environment)
            .map_err(active_error)
    })
}

/// Receive the helper's one complete bundle before activating directory custody.
///
/// # Errors
/// Refuses missing or inconsistent private vectors, descriptors and custody.
#[allow(clippy::too_many_lines)]
pub fn serve(args: &[String]) -> Result<i32, LaneError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(LaneError::input(
            "helper-identity",
            "rootless namespace owner is required",
        ));
    }
    let [
        command,
        driver_flag,
        run,
        home_flag,
        home,
        home_fd_flag,
        home_slot,
        runs_flag,
        runs,
        runs_fd_flag,
        runs_slot,
        manifest_flag,
        source,
    ] = args
    else {
        return Err(refusal(
            "anchor-missing: operation=container-helper purpose=manifest",
        ));
    };
    if command != "_container-helper"
        || driver_flag != "--run-dir"
        || home_flag != "--owner-home"
        || home_fd_flag != "--verified-home-fd"
        || home_slot != "0"
        || runs_flag != "--verified-runs-root"
        || runs_fd_flag != "--verified-runs-root-fd"
        || runs_slot != "1"
        || manifest_flag != "--anchor-manifest"
        || !Path::new(run).is_absolute()
        || !Path::new(home).is_absolute()
        || !Path::new(runs).is_absolute()
    {
        return Err(refusal(
            "anchor-declaration: operation=container-helper purpose=vector",
        ));
    }
    let (manifest, mut anchors) = receive(source, &std::io::stdin())?;
    // The private entry owns stdin; the completed capability channel is setup-only.
    anchor::transport::replace_stdin(OPERATION).map_err(refusal)?;
    let configuration_anchor = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=configuration")
    })?;
    let _configuration = configuration(
        Path::new(home),
        &manifest.loop_name,
        OPERATION,
        configuration_anchor,
    )?;
    let backend = manifest_backend(&manifest);
    let (podman, support) = take_support_programs(&mut anchors, backend)?;
    let _home = crate::home::activate_private_launch(
        Path::new(home),
        &anchors[0],
        Path::new(runs),
        &anchors[1],
        None,
        0,
    )?;
    EXECUTABLE.with(|active| *active.borrow_mut() = Some(support));
    let _executable = ExecutableGuard;
    let (record_home, loop_name, _, program) =
        crate::container_helper::run_identity(Path::new(run))?;
    if record_home != Path::new(home) || loop_name != manifest.loop_name {
        return Err(refusal(
            "anchor-declaration: operation=container-helper purpose=run",
        ));
    }
    EXECUTABLE.with(|active| {
        drop(
            active
                .borrow_mut()
                .as_mut()
                .ok_or_else(|| {
                    refusal("anchor-missing: operation=container-helper purpose=programs")
                })?
                .insert(program, Arc::new(podman)),
        );
        Ok::<(), LaneError>(())
    })?;
    crate::container_helper::serve(Path::new(run)).map(|()| 0)
}

/// Extract the selected support roles after validating the complete helper bundle.
pub(crate) fn take_support_programs(
    anchors: &mut Vec<Anchor>,
    backend: BoxBackend,
) -> Result<(Anchor, BTreeMap<PathBuf, Arc<Anchor>>), LaneError> {
    let date = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=credential-clock")
    })?;
    let client = anchors.pop().ok_or_else(|| {
        refusal(format!(
            "anchor-missing: operation=container-helper purpose={}",
            purposes(OPERATION, backend)[5]
        ))
    })?;
    let hash = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=hash-executable")
    })?;
    let podman = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=podman-executable")
    })?;
    Ok((
        podman,
        BTreeMap::from([
            (PathBuf::from("/usr/bin/sha256sum"), Arc::new(hash)),
            (PathBuf::from(credential_client(backend)), Arc::new(client)),
            (PathBuf::from("/usr/bin/date"), Arc::new(date)),
        ]),
    ))
}

fn manifest_backend(manifest: &Manifest) -> BoxBackend {
    if manifest
        .records
        .iter()
        .any(|record| record.purpose == "credential-claude")
    {
        BoxBackend::Claude
    } else {
        BoxBackend::Codex
    }
}

fn receive(source: &str, input: &impl AsFd) -> Result<(Manifest, Vec<Anchor>), LaneError> {
    receive_for(source, input, OPERATION, None)
}

pub(crate) fn receive_for(
    source: &str,
    input: &impl AsFd,
    operation: &'static str,
    scope: Option<&str>,
) -> Result<(Manifest, Vec<Anchor>), LaneError> {
    registry_override(operation)?;
    let manifest =
        Manifest::parse(source).map_err(|error| refusal(error.context(operation, "manifest")))?;
    let purposes = purposes(operation, manifest_backend(&manifest));
    if manifest.records.len() != purposes.len() {
        return Err(refusal(format!(
            "anchor-declaration: operation={operation} purpose=count"
        )));
    }
    let stream = UnixStream::from(
        input
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| io_refusal(operation, "rights", "input-duplicate", error))?,
    );
    let descriptors = anchor::transport::receive(&stream, purposes.len(), Duration::from_secs(30))
        .map_err(|error| refusal(error.context(operation, "rights")))?;
    let mut required = Vec::new();
    for (slot, purpose) in purposes.iter().enumerate() {
        let record = manifest
            .records
            .iter()
            .find(|record| record.purpose == *purpose)
            .ok_or_else(|| {
                refusal(format!(
                    "anchor-declaration: operation={operation} purpose=roles"
                ))
            })?;
        if usize::try_from(record.slot).map_err(refusal)? != slot {
            return Err(refusal(format!(
                "anchor-declaration: operation={operation} purpose=slots"
            )));
        }
        required.push(Requirement {
            purpose: (*purpose).into(),
            policy: if *purpose == "configuration" {
                configuration_policy()
            } else if slot < 2 {
                directory_policy(operation, &descriptors[slot], purpose)?
            } else {
                executable_policy(if slot >= 5 || record.owner_uid == 0 {
                    Owner::RootFile
                } else {
                    Owner::Host
                })
            },
            alias_group: None,
        });
    }
    crate::runtime_entry::distinct_roots(&manifest, operation)
        .map_err(|error| operation_error(operation, error.detail))?;
    let anchors = Receiver::current()
        .map_err(|error| refusal(error.context(operation, "receiver-map")))?
        .validate(
            &manifest,
            descriptors,
            operation,
            scope.unwrap_or(&manifest.loop_name),
            Transport::Rights,
            &required,
        )
        .map_err(refusal)?;
    let entry = &anchors[2];
    check_image(operation, entry)?;
    Ok((manifest, anchors))
}

pub(crate) fn check_image(operation: &str, entry: &Anchor) -> Result<(), LaneError> {
    let current = std::fs::File::open("/proc/self/exe")
        .map_err(|error| io_refusal(operation, "entry-executable", "self-image-open", error))?;
    let expected = fstat(entry)
        .map_err(|error| io_refusal(operation, "entry-executable", "held-stat", error))?;
    let actual = fstat(&current)
        .map_err(|error| io_refusal(operation, "entry-executable", "self-image-stat", error))?;
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino) {
        return Err(refusal(format!(
            "anchor-identity: operation={operation} purpose=entry-executable"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::process::Stdio;

    /// # Panics
    /// Panics if an active operation loses its refusal envelope or failed custody check.
    /// ´claim:superlooplane:active-program-refusals-name-the-operation´
    /// ´test:unit:active-program-refusals-name-the-operation´
    #[test]
    fn active_program_refusals_name_the_operation() {
        for (operation, kind) in [
            ("prepare-runtime", "runtime-anchor"),
            ("make-home", "creation-anchor"),
            ("exercise-mounts", "exercise-anchor"),
            (OPERATION, "container-anchor"),
        ] {
            let _guard = activate_program_map(operation, BTreeMap::new());
            let program = Path::new("/ungranted-program");
            let error = check(program).expect("active").expect_err("ungranted");
            assert_eq!(error.kind, kind);
            assert!(error.detail.contains("purpose=program"));
            let error = crate::build::sha256_bytes(b"", Path::new("/"))
                .expect_err("ungranted hashing capability");
            assert_eq!(error.kind, kind);
            assert!(error.detail.contains("anchor-declaration"));
        }
        let fixture = tempfile::tempdir().expect("fixture");
        let program = fixture.path().join("program");
        fs::copy("/usr/bin/true", &program).expect("native program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        let pin = HostVerifier::current()
            .expect("map")
            .for_operation("prepare-runtime")
            .pin(
                &program,
                "podman-executable",
                0,
                executable_policy(Owner::Host),
            )
            .expect("host pin");
        let manifest = Manifest {
            version: 1,
            transport: Transport::Rights,
            operation: "prepare-runtime".into(),
            loop_name: "alpha".into(),
            records: vec![pin.record()],
        };
        let mut anchors = Receiver::current()
            .expect("receiver")
            .validate(
                &manifest,
                vec![pin.into_fd()],
                "prepare-runtime",
                "alpha",
                Transport::Rights,
                &[Requirement {
                    purpose: "podman-executable".into(),
                    policy: executable_policy(Owner::Host),
                    alias_group: None,
                }],
            )
            .expect("anchor");
        let _guard = activate_program_map(
            "prepare-runtime",
            BTreeMap::from([(
                program.clone(),
                Arc::new(anchors.pop().expect("one anchor")),
            )]),
        );
        fs::set_permissions(&program, fs::Permissions::from_mode(0o777)).expect("unsafe mode");
        let error = check(&program).expect("active").expect_err("changed mode");
        assert_eq!(error.kind, "runtime-anchor");
        assert!(error.detail.contains("anchor-mode"));
    }

    const CHILD: &str = "SUPERLOOP_CONTAINER_ANCHOR_TEST";

    /// # Panics
    /// Panics if a helper or exercise override reaches any pin or descriptor receive.
    fn assert_override_refusals() {
        let held = fs::File::open("/dev/null")
            .expect("placeholder descriptor")
            .into();
        let absent = Path::new("/absent-anchor-override-fixture");
        for operation in [
            OPERATION,
            "exercise-mounts",
            "exercise-network",
            "exercise-door-shape",
            "exercise-door-attribution",
        ] {
            let Err(error) = pin_for(
                operation,
                "alpha",
                (absent, &held),
                (absent, &held),
                absent,
                absent,
            ) else {
                panic!("override reached composer pins");
            };
            let expected =
                format!("anchor-declaration: operation={operation} purpose=registry-override");
            assert_eq!(error.detail, expected);
            let error = receive_for(
                "not a manifest",
                &std::io::stdin(),
                operation,
                Some("alpha"),
            )
            .expect_err("override precedes parsing and receiving");
            assert_eq!(error.detail, expected);
        }
    }

    /// # Panics
    /// Panics if the real namespace or a named custody check is not measured.
    ///
    /// ´claim:superlooplane:container-entry-retains-system-executable-custody´
    /// ´test:unit:container-entry-retains-system-executable-custody´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn container_entry_retains_system_executable_custody() {
        if let Ok(case) = std::env::var(CHILD) {
            let source = std::env::var("SUPERLOOP_CONTAINER_ANCHOR_MANIFEST").expect("manifest");
            if std::env::var("SUPERLOOP_CONTAINER_ANCHOR_NAMESPACE").as_deref() == Ok("yes") {
                let root = fs::metadata("/").expect("root");
                let overflow: u32 = fs::read_to_string("/proc/sys/kernel/overflowuid")
                    .expect("overflow")
                    .trim()
                    .parse()
                    .expect("uid");
                assert_eq!(root.uid(), overflow);
                assert_eq!(nix::unistd::geteuid().as_raw(), 0);
                assert_ne!(
                    fs::read_to_string("/proc/self/uid_map")
                        .expect("map")
                        .split_whitespace()
                        .collect::<Vec<_>>(),
                    ["0", "0", "4294967295"]
                );
            }
            if case == "override" {
                assert_override_refusals();
                return;
            }
            let operation = match case.as_str() {
                "exercise-mounts" => "exercise-mounts",
                "exercise-network" => "exercise-network",
                "exercise-door-shape" => "exercise-door-shape",
                "exercise-door-attribution" => "exercise-door-attribution",
                _ => OPERATION,
            };
            let result = receive_for(&source, &std::io::stdin(), operation, None);
            if !matches!(case.as_str(), "valid" | "replaced" | "claude") {
                let error = result.expect_err("custody refusal");
                let expected = match case.as_str() {
                    "identity" | "entry" => "anchor-identity",
                    "operation"
                    | "home-runs-alias"
                    | "exercise-mounts"
                    | "exercise-network"
                    | "exercise-door-shape"
                    | "exercise-door-attribution" => "anchor-declaration",
                    "mode" => "anchor-mode",
                    "substituted" => "anchor-kind",
                    "owner" => "anchor-owner",
                    "extra" | "missing" => "anchor-transport",
                    _ => panic!("unknown case"),
                };
                assert!(error.detail.contains(expected), "{error:?}");
                if case == "home-runs-alias" || case.starts_with("exercise-") {
                    assert_eq!(
                        error.kind,
                        if case == "home-runs-alias" {
                            "container-anchor"
                        } else {
                            "exercise-anchor"
                        }
                    );
                    assert_eq!(
                        error.detail,
                        format!("anchor-declaration: operation={operation} purpose=runs-root")
                    );
                }
                return;
            }
            let (manifest, mut anchors) = result.expect("production receiver");
            let backend = manifest_backend(&manifest);
            let program =
                PathBuf::from(std::env::var_os("SUPERLOOP_CONTAINER_PROGRAM").expect("program"));
            let _configuration = anchors.pop().expect("configuration");
            let (podman, mut support) = take_support_programs(&mut anchors, backend)
                .expect("selected helper support roles");
            support.insert(program.clone(), Arc::new(podman));
            EXECUTABLE.with(|active| *active.borrow_mut() = Some(support));
            let _guard = ExecutableGuard;
            let foreign = if backend == BoxBackend::Claude {
                BoxBackend::Codex
            } else {
                BoxBackend::Claude
            };
            let error = credential_programs(foreign).expect_err("foreign client must refuse");
            assert!(
                error
                    .detail
                    .contains(&format!("backend={}", foreign.name())),
                "{error:?}"
            );
            assert!(
                error.detail.contains(credential_client(foreign)),
                "{error:?}"
            );
            let credentials = credential_programs(backend)
                .expect("credential handoff")
                .expect("active bundle");
            assert_eq!(credentials.len(), 2);
            std::thread::spawn(move || {
                let _guard = activate_program_map(OPERATION, credentials);
                for program in [credential_client(backend), "/usr/bin/date"] {
                    let result = crate::build::run_checked(
                        Path::new(program),
                        vec!["--version".into()],
                        &std::env::vars().collect(),
                        Path::new("/"),
                        10,
                        "credential-anchor-test",
                    )
                    .expect("credential thread uses held system file");
                    assert_ne!(result, "");
                }
            })
            .join()
            .expect("credential thread");
            let environment = std::env::vars().collect::<BTreeMap<_, _>>();
            let result = crate::build::run_checked(
                &program,
                if case == "replaced" {
                    Vec::new()
                } else {
                    vec!["--version".into()]
                },
                &environment,
                Path::new("/"),
                30,
                "container-anchor-test",
            )
            .expect("held root-owned program executes");
            if case == "replaced" {
                assert!(result.is_empty(), "{result}");
            } else {
                assert!(result.contains("podman version"), "{result}");
            }
            let expected =
                crate::build::sha256_bytes(b"", Path::new("/")).expect("held hash program");
            assert_eq!(
                expected,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            return;
        }
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("home mode");
        let runs = fixture.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        for path in [
            fixture.path().join(".config"),
            fixture.path().join(".config/loops"),
        ] {
            fs::create_dir(&path).expect("configuration directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let home = fs::File::open(fixture.path()).expect("home").into();
        let held_runs = fs::File::open(&runs).expect("runs").into();
        let image = std::env::current_exe().expect("test image");
        for namespace in [false, true] {
            for case in [
                "valid",
                "override",
                "claude",
                "replaced",
                "identity",
                "entry",
                "operation",
                "home-runs-alias",
                "exercise-mounts",
                "exercise-network",
                "exercise-door-shape",
                "exercise-door-attribution",
                "mode",
                "substituted",
                "owner",
                "extra",
                "missing",
            ] {
                let program = if case == "replaced" {
                    let path = fixture.path().join(format!("program-{namespace}"));
                    fs::copy("/usr/bin/true", &path).expect("original program");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("program mode");
                    path
                } else {
                    PathBuf::from("/usr/bin/podman")
                };
                let mut bundle = pin_for_backend(
                    if case.starts_with("exercise-") {
                        case
                    } else {
                        OPERATION
                    },
                    "alpha",
                    (fixture.path(), &home),
                    (&runs, &held_runs),
                    &image,
                    &program,
                    BoxBackend::Codex,
                )
                .expect("host composer");
                if case == "replaced" {
                    let replacement = fixture.path().join(format!("replacement-{namespace}"));
                    fs::copy("/usr/bin/false", &replacement).expect("replacement program");
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
                        .expect("replacement mode");
                    fs::rename(replacement, &program)
                        .expect("replace pathname while retaining old file");
                }
                let mut declaration = Manifest::parse(&bundle.manifest).expect("manifest");
                if case == "claude" {
                    // A real root-owned executable stands in for the unavailable vendor;
                    // no Claude output or credential acceptance is asserted.
                    let pin = HostVerifier::current()
                        .expect("host map")
                        .for_operation(OPERATION)
                        .pin(
                            Path::new("/usr/bin/true"),
                            "credential-claude",
                            5,
                            executable_policy(Owner::RootFile),
                        )
                        .expect("Claude role stand-in");
                    declaration.records[5] = pin.record();
                    bundle.descriptors[5] = pin.into_fd();
                }
                if matches!(case, "mode" | "entry") {
                    let copy = fixture.path().join(format!("image-{namespace}-{case}"));
                    fs::copy("/usr/bin/true", &copy).expect("native fixture image");
                    fs::set_permissions(&copy, fs::Permissions::from_mode(0o700))
                        .expect("image mode");
                    let slot = if case == "entry" { 2 } else { 3 };
                    let pin = HostVerifier::current()
                        .expect("host map")
                        .for_operation(OPERATION)
                        .pin(
                            &copy,
                            PURPOSES[slot],
                            u32::try_from(slot).expect("slot"),
                            executable_policy(Owner::Host),
                        )
                        .expect("fixture pin");
                    declaration.records[slot] = pin.record();
                    bundle.descriptors[slot] = pin.into_fd();
                    if case == "mode" {
                        fs::set_permissions(&copy, fs::Permissions::from_mode(0o777))
                            .expect("unsafe live mode");
                    }
                }
                match case {
                    "home-runs-alias"
                    | "exercise-mounts"
                    | "exercise-network"
                    | "exercise-door-shape"
                    | "exercise-door-attribution" => {
                        let mut record = declaration.records[0].clone();
                        record.purpose = "runs-root".into();
                        record.slot = 1;
                        declaration.records[1] = record;
                        bundle.descriptors[1] =
                            bundle.descriptors[0].try_clone().expect("same held root");
                    }
                    "identity" => declaration.records[3].inode ^= 1,
                    "operation" => declaration.operation = "other-operation".into(),
                    "owner" => declaration.records[3].owner_uid = 1,
                    "substituted" => {
                        bundle.descriptors[3] =
                            bundle.descriptors[0].try_clone().expect("substitute");
                    }
                    "extra" => bundle
                        .descriptors
                        .push(bundle.descriptors[0].try_clone().expect("extra")),
                    "missing" => {
                        drop(bundle.descriptors.pop());
                    }
                    _ => {}
                }
                bundle.manifest = serde_json::to_string(&declaration).expect("encode");
                let (sender, receiver) = UnixStream::pair().expect("channel");
                let mut command = if namespace {
                    let mut command = Command::new("/usr/bin/unshare");
                    command.args(["--user", "--map-root-user"]).arg(&image);
                    command
                } else {
                    Command::new(&image)
                };
                command
                    .args([
                        "--exact",
                        "container_entry::tests::container_entry_retains_system_executable_custody",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, case)
                    .env("SUPERLOOP_CONTAINER_PROGRAM", &program)
                    .env("SUPERLOOP_CONTAINER_ANCHOR_MANIFEST", &bundle.manifest)
                    .env(
                        "SUPERLOOP_CONTAINER_ANCHOR_NAMESPACE",
                        if namespace { "yes" } else { "no" },
                    )
                    .stdin(Stdio::from(OwnedFd::from(receiver)))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if case == "override" {
                    command.env("ENTER_LOOP_REGISTRY", "");
                }
                anchor::transport::send(&sender, &bundle.descriptors).expect("bundle");
                let child = command.spawn().expect("fixture child");
                let output = child.wait_with_output().expect("child end");
                assert!(
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                    "namespace={namespace} case={case}; unavailable namespaces are unmeasured, not passed: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}
