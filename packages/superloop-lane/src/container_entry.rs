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

use crate::error::LaneError;

const OPERATION: &str = "container-helper";
const PURPOSES: [&str; 5] = [
    "owner-home",
    "runs-root",
    "entry-executable",
    "podman-executable",
    "hash-executable",
];

fn refusal(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("container-anchor", error.to_string())
}

fn io_refusal(purpose: &str, check: &str, cause: impl std::fmt::Display) -> LaneError {
    refusal(format!(
        "anchor-io: operation={OPERATION} purpose={purpose} check={check}: {cause}"
    ))
}

fn directory_policy(fd: &impl AsFd, purpose: &str) -> Result<Policy, LaneError> {
    let stat = fstat(fd).map_err(|error| io_refusal(purpose, "fstat", error))?;
    let mode = stat.st_mode & 0o7777;
    if mode & 0o7022 != 0 || mode & 0o700 != 0o700 {
        return Err(refusal(format_args!(
            "anchor-mode: operation=container-helper purpose={purpose} check=directory-mode observed={mode:04o}"
        )));
    }
    Ok(Policy {
        kind: Kind::Directory,
        owner: Owner::Host,
        mode: ModePolicy::Exact(mode),
    })
}

const fn executable_policy(root: bool) -> Policy {
    Policy {
        kind: Kind::File,
        owner: if root { Owner::RootFile } else { Owner::Host },
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
) -> Result<Bundle, LaneError> {
    let verifier = HostVerifier::current()
        .map_err(refusal)?
        .for_operation(OPERATION);
    let mut records = Vec::new();
    let mut descriptors = Vec::new();
    for (slot, (path, held)) in [home, runs].into_iter().enumerate() {
        let pin = verifier
            .pin(
                path,
                PURPOSES[slot],
                u32::try_from(slot).map_err(refusal)?,
                directory_policy(held, PURPOSES[slot])?,
            )
            .map_err(refusal)?;
        let record = pin.record();
        let actual = fstat(held).map_err(|error| io_refusal(PURPOSES[slot], "held-stat", error))?;
        if (record.device, record.inode) != (actual.st_dev, actual.st_ino) {
            return Err(refusal(
                "anchor-identity: operation=container-helper purpose=directory",
            ));
        }
        records.push(record);
        descriptors.push(pin.into_fd());
    }
    for (slot, path) in [
        (2, entry),
        (3, podman),
        (4, Path::new("/usr/bin/sha256sum")),
    ] {
        let index = u32::try_from(slot).map_err(refusal)?;
        let pin = verifier
            .pin(path, PURPOSES[slot], index, executable_policy(false))
            .or_else(|error| {
                if error.kind == "anchor-owner" {
                    verifier.pin(path, PURPOSES[slot], index, executable_policy(true))
                } else {
                    Err(error)
                }
            })
            .map_err(refusal)?;
        records.push(pin.record());
        descriptors.push(pin.into_fd());
    }
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: OPERATION.into(),
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
    ACTIVE_OPERATION.with(|active| active.set(operation));
    EXECUTABLE.with(|active| {
        *active.borrow_mut() = Some(BTreeMap::from([
            (podman.to_path_buf(), Arc::new(executable)),
            (PathBuf::from("/usr/bin/sha256sum"), Arc::new(hash)),
        ]));
    });
    ExecutableGuard
}

fn active_refusal() -> LaneError {
    refusal(format!(
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
                .map_err(refusal)
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
            .map_err(refusal)
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
    let hash = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=hash-executable")
    })?;
    let podman = anchors.pop().ok_or_else(|| {
        refusal("anchor-missing: operation=container-helper purpose=podman-executable")
    })?;
    let _home = crate::home::activate_private_launch(
        Path::new(home),
        &anchors[0],
        Path::new(runs),
        &anchors[1],
        None,
        0,
    )?;
    EXECUTABLE.with(|active| {
        *active.borrow_mut() = Some(BTreeMap::from([(
            PathBuf::from("/usr/bin/sha256sum"),
            Arc::new(hash),
        )]));
    });
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

fn receive(source: &str, input: &impl AsFd) -> Result<(Manifest, Vec<Anchor>), LaneError> {
    let manifest = Manifest::parse(source).map_err(refusal)?;
    if manifest.records.len() != PURPOSES.len() {
        return Err(refusal(
            "anchor-declaration: operation=container-helper purpose=count",
        ));
    }
    let stream = UnixStream::from(
        input
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| io_refusal("rights", "input-duplicate", error))?,
    );
    let descriptors = anchor::transport::receive(&stream, PURPOSES.len(), Duration::from_secs(30))
        .map_err(|error| refusal(error.context(OPERATION, "rights")))?;
    let mut required = Vec::new();
    for (slot, purpose) in PURPOSES.iter().enumerate() {
        let record = manifest
            .records
            .iter()
            .find(|record| record.purpose == *purpose)
            .ok_or_else(|| {
                refusal("anchor-declaration: operation=container-helper purpose=roles")
            })?;
        if usize::try_from(record.slot).map_err(refusal)? != slot {
            return Err(refusal(
                "anchor-declaration: operation=container-helper purpose=slots",
            ));
        }
        required.push(Requirement {
            purpose: (*purpose).into(),
            policy: if slot < 2 {
                directory_policy(&descriptors[slot], purpose)?
            } else {
                executable_policy(record.owner_uid == 0)
            },
            alias_group: None,
        });
    }
    let anchors = Receiver::current()
        .map_err(refusal)?
        .validate(
            &manifest,
            descriptors,
            OPERATION,
            &manifest.loop_name,
            Transport::Rights,
            &required,
        )
        .map_err(refusal)?;
    let entry = &anchors[2];
    let current = std::fs::File::open("/proc/self/exe")
        .map_err(|error| io_refusal("entry-executable", "self-image-open", error))?;
    let expected =
        fstat(entry).map_err(|error| io_refusal("entry-executable", "held-stat", error))?;
    let actual = fstat(&current)
        .map_err(|error| io_refusal("entry-executable", "self-image-stat", error))?;
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino) {
        return Err(refusal(
            "anchor-identity: operation=container-helper purpose=entry-executable",
        ));
    }
    Ok((manifest, anchors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::process::Stdio;

    const CHILD: &str = "SUPERLOOP_CONTAINER_ANCHOR_TEST";

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
            let result = receive(&source, &std::io::stdin());
            if !matches!(case.as_str(), "valid" | "replaced") {
                let error = result.expect_err("custody refusal");
                let expected = match case.as_str() {
                    "identity" | "entry" => "anchor-identity",
                    "operation" => "anchor-declaration",
                    "mode" => "anchor-mode",
                    "substituted" => "anchor-kind",
                    "owner" => "anchor-owner",
                    "extra" | "missing" => "anchor-transport",
                    _ => panic!("unknown case"),
                };
                assert!(error.detail.contains(expected), "{error:?}");
                return;
            }
            let (_, mut anchors) = result.expect("production receiver");
            let program =
                PathBuf::from(std::env::var_os("SUPERLOOP_CONTAINER_PROGRAM").expect("program"));
            let hash = anchors.pop().expect("hash");
            let podman = anchors.pop().expect("podman");
            EXECUTABLE.with(|active| {
                *active.borrow_mut() = Some(BTreeMap::from([
                    (program.clone(), Arc::new(podman)),
                    (PathBuf::from("/usr/bin/sha256sum"), Arc::new(hash)),
                ]));
            });
            let _guard = ExecutableGuard;
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
        let home = fs::File::open(fixture.path()).expect("home").into();
        let held_runs = fs::File::open(&runs).expect("runs").into();
        let image = std::env::current_exe().expect("test image");
        for namespace in [false, true] {
            for case in [
                "valid",
                "replaced",
                "identity",
                "entry",
                "operation",
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
                let mut bundle = pin(
                    "alpha",
                    (fixture.path(), &home),
                    (&runs, &held_runs),
                    &image,
                    &program,
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
                            executable_policy(false),
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
                let child = command.spawn().expect("fixture child");
                anchor::transport::send(&sender, &bundle.descriptors).expect("bundle");
                let output = child.wait_with_output().expect("child end");
                assert!(
                    output.status.success(),
                    "namespace={namespace} case={case}; unavailable namespaces are unmeasured, not passed: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}
