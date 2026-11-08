//! Runtime preparation keeps executable and worker-verification custody across entry.
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::container_entry::{executable_policy as executable, registry_override};
use crate::error::LaneError;
use loop_home::anchor::{
    self, Anchor, Configuration, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver,
    Requirement, Transport,
};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};

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
    crate::container_entry::operation_error(
        operation,
        format!("{kind}: operation={operation} purpose={purpose}"),
    )
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
pub(crate) fn directory_policy_for(
    operation: &str,
    fd: &impl AsFd,
    purpose: &str,
) -> Result<Policy, LaneError> {
    crate::container_entry::directory_policy(operation, fd, purpose).map_err(boundary)
}
const fn boundary(mut error: LaneError) -> LaneError {
    error.kind = "runtime-anchor";
    error
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
    let mut pins = crate::container_entry::core_pins(host, operation, home, runs, entry, program)
        .map_err(boundary)?;
    let (home, _) = home;
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
    registry_override(operation)?;
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

#[derive(Clone, Debug)]
pub(crate) struct PlanConfiguration {
    home: std::path::PathBuf,
    operation: &'static str,
    directory: Arc<Anchor>,
    pub(crate) registry: loop_home::registry::Registry,
    pub(crate) allocations: loop_home::allocations::Allocations,
}
impl PlanConfiguration {
    pub(crate) fn read_settings(
        &self,
        scope: &str,
        path: &Path,
    ) -> Result<crate::Settings, LaneError> {
        let file = self
            .directory
            .open_beneath(
                &Path::new(scope).join("workers.toml"),
                Policy {
                    kind: Kind::File,
                    owner: Owner::Host,
                    mode: ModePolicy::Exact(0o600),
                },
                0o700,
            )
            .map_err(|error| crate::container_entry::operation_error(self.operation, error))?;
        crate::Settings::from_private_file(std::fs::File::from(file), path)
    }
}
thread_local! {
    static PLAN_CONFIGURATION: std::cell::RefCell<Option<PlanConfiguration>> = const { std::cell::RefCell::new(None) };
}
pub(crate) struct ConfigurationGuard {
    previous: Option<PlanConfiguration>,
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Drop for ConfigurationGuard {
    fn drop(&mut self) {
        PLAN_CONFIGURATION.with(|active| *active.borrow_mut() = self.previous.take());
    }
}
pub(crate) fn activate_configuration(
    home: &Path,
    configuration: &Configuration,
    directory: Arc<Anchor>,
    operation: &'static str,
) -> ConfigurationGuard {
    let snapshot = PlanConfiguration {
        home: home.to_path_buf(),
        operation,
        directory,
        registry: configuration.registry.clone(),
        allocations: configuration.allocations.clone(),
    };
    ConfigurationGuard {
        previous: PLAN_CONFIGURATION.with(|active| active.replace(Some(snapshot))),
        thread: std::marker::PhantomData,
    }
}
pub(crate) fn plan_configuration(home: &Path) -> Result<Option<PlanConfiguration>, LaneError> {
    PLAN_CONFIGURATION.with(|active| {
        let active = active.borrow();
        let Some(snapshot) = active.as_ref() else {
            return Ok(None);
        };
        registry_override(snapshot.operation)?;
        if snapshot.home != home {
            return Err(named_for(
                snapshot.operation,
                "anchor-identity",
                "configuration-home",
            ));
        }
        Ok(Some(snapshot.clone()))
    })
}

/// Validated configuration and worker storage for the runtime's one birth check.
pub struct Custody {
    pub(crate) configuration: Configuration,
    pub(crate) configuration_root: Arc<Anchor>,
    pub(crate) root: Anchor,
    pub(crate) private: Anchor,
    pub(crate) executor: Anchor,
}
impl Custody {
    pub(crate) fn reserved_uids(
        &self,
        home: &Path,
        loop_name: &str,
    ) -> Result<std::collections::BTreeSet<u32>, LaneError> {
        loop_home::mail::worker_provision::reserved_uids_beneath(
            home,
            loop_name,
            &self.configuration,
            &self.root,
        )
        .map_err(|error| LaneError::input("mail-birth", error.to_string()))
    }
    pub(crate) fn activate_configuration(
        &self,
        home: &Path,
        operation: &'static str,
    ) -> ConfigurationGuard {
        activate_configuration(
            home,
            &self.configuration,
            Arc::clone(&self.configuration_root),
            operation,
        )
    }
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

pub(crate) fn distinct_roots(manifest: &Manifest, operation: &str) -> Result<(), LaneError> {
    let home_identity = manifest
        .records
        .iter()
        .find(|record| record.purpose == "owner-home")
        .ok_or_else(|| named_for(operation, "anchor-declaration", "roles"))?;
    let runs_identity = manifest
        .records
        .iter()
        .find(|record| record.purpose == "runs-root")
        .ok_or_else(|| named_for(operation, "anchor-declaration", "roles"))?;
    if (home_identity.device, home_identity.inode) == (runs_identity.device, runs_identity.inode) {
        return Err(named_for(operation, "anchor-declaration", "runs-root"));
    }
    Ok(())
}

pub(crate) fn receive_bundle(
    source: &str,
    scope: &str,
    home: &str,
    operation: &str,
    extras: &[Requirement],
) -> Result<(Configuration, Vec<Anchor>), LaneError> {
    registry_override(operation)?;
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
    distinct_roots(&manifest, operation)?;
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
    let configuration_root = Arc::new(next()?);
    let custody = Custody {
        configuration,
        configuration_root,
        root: next()?,
        private: next()?,
        executor: next()?,
    };
    crate::container_entry::check_image(OPERATION, &entry).map_err(boundary)?;
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
    let _configuration = custody.activate_configuration(Path::new(home), OPERATION);
    crate::launch::private_prepare_runtime(Path::new(home), scope, run, Path::new(podman), &custody)
}

/// Describe custody that is pinned only by the changing launch.
pub(crate) fn preview() -> serde_json::Value {
    serde_json::json!({"state":"bound-on-launch","transport":"rights","operation":OPERATION,"purposes":PURPOSES})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// # Panics
    /// Panics if synthetic configuration fields violate the registry or ledger grammar.
    fn configuration(uid: u32, home: &Path) -> Configuration {
        let source = format!(
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{{name='alpha',uid={uid},launch='dev/alpha'}}]\n"
        );
        let path = home.join(format!("registry-{uid}.toml"));
        std::fs::write(&path, source).expect("fixture registry");
        let registry = loop_home::load_registry(&path).expect("registry");
        let ledger_source =
            "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n"
                .to_owned();
        let allocations =
            loop_home::allocations::Allocations::parse(&ledger_source).expect("ledger");
        Configuration {
            registry,
            allocations,
            ledger_source,
        }
    }

    /// # Panics
    /// Panics if the fixture directory cannot pass the production host and receiver checks.
    fn configuration_directory(home: &Path, operation: &str) -> Arc<Anchor> {
        let policy = directory(Owner::Host, 0o700);
        let pin = HostVerifier::current()
            .expect("host map")
            .for_operation(operation)
            .pin(home, "configuration", 0, policy)
            .expect("configuration pin");
        let manifest = Manifest {
            version: 1,
            transport: Transport::Rights,
            operation: operation.into(),
            loop_name: "alpha".into(),
            records: vec![pin.record()],
        };
        let mut anchors = Receiver::current()
            .expect("receiver map")
            .validate(
                &manifest,
                vec![pin.into_fd()],
                operation,
                "alpha",
                Transport::Rights,
                &[Requirement {
                    purpose: "configuration".into(),
                    policy,
                    alias_group: None,
                }],
            )
            .expect("configuration receipt");
        Arc::new(anchors.pop().expect("configuration anchor"))
    }

    /// # Panics
    /// Panics if plan readers reopen paths, widen a grant, leak a scope or accept another home.
    /// ´claim:superlooplane:runtime-plan-uses-anchored-configuration-snapshot´
    /// ´test:unit:runtime-plan-uses-anchored-configuration-snapshot´
    #[test]
    fn runtime_plan_uses_anchored_configuration_snapshot() {
        let directory = tempfile::tempdir().expect("home");
        let home = directory.path();
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))
            .expect("private configuration");
        assert_eq!(
            crate::read_plan_registry(home)
                .expect_err("no ambient registry")
                .kind,
            "registry-row"
        );
        let snapshot = configuration(64000, home);
        let guard = activate_configuration(
            home,
            &snapshot,
            configuration_directory(home, OPERATION),
            OPERATION,
        );
        assert_eq!(
            crate::read_plan_registry(home)
                .expect("snapshot")
                .row("alpha", home)
                .expect("row")
                .uid,
            64000
        );
        assert_eq!(
            crate::home::read_allocations(home)
                .expect("snapshot ledger")
                .require("alpha")
                .expect("block")
                .base,
            64010
        );
        let settings = crate::settings::Settings::from_private_bytes(
            b"driver_argv=['/usr/bin/true']\n[backend_argv]\ncodex=['/usr/bin/true']\n".to_vec(),
            Path::new("workers.toml"),
        )
        .expect("settings");
        settings
            .validate_grant(home, "alpha")
            .expect("snapshot grant");
        let error = crate::load_plan_with_settings(
            home,
            "alpha",
            "R",
            (0, 0),
            false,
            settings,
            crate::settings::BoxBackend::Codex,
        )
        .expect_err("next plan field");
        assert_eq!(error.kind, "missing-setting");
        assert_eq!(error.detail, "entry_bin is absent in workers.toml");
        assert!(
            plan_configuration(&home.join("other"))
                .expect_err("wrong home")
                .detail
                .contains("purpose=configuration-home")
        );
        {
            let second = configuration(63000, home);
            let _nested = activate_configuration(
                home,
                &second,
                configuration_directory(home, "make-home"),
                "make-home",
            );
            assert_eq!(
                crate::read_plan_registry(home)
                    .expect("nested snapshot")
                    .row("alpha", home)
                    .expect("row")
                    .uid,
                63000
            );
        }
        assert_eq!(
            crate::read_plan_registry(home)
                .expect("restored snapshot")
                .row("alpha", home)
                .expect("row")
                .uid,
            64000
        );
        drop(guard);
        assert_eq!(
            crate::read_plan_registry(home)
                .expect_err("scope cleared")
                .kind,
            "registry-row"
        );
    }
}
