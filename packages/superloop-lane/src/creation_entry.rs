//! Native creation carries configuration, lifetime storage and letter custody into entry.
use crate::{error::LaneError, launch, settings::BoxBackend};
use loop_home::anchor::{
    self, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Requirement, Transport,
};
use loop_home::{CommandDescriptors, CommandSpec, IoMode};
use nix::sys::stat::fstat;
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
const OPERATION: &str = "make-home";
const EXTRA: [&str; 4] = [
    "credential-client",
    "credential-clock",
    "letter-directory",
    "rotation-source",
];
fn extras(backend: BoxBackend) -> [&'static str; 4] {
    let mut purposes = EXTRA;
    if backend == BoxBackend::Claude {
        purposes[0] = "credential-claude";
    }
    purposes
}
pub(crate) fn selected_backend(body: &[String]) -> Result<BoxBackend, LaneError> {
    if body.get(21).map(String::as_str) != Some("--backend") {
        return Err(named("anchor-declaration", "backend"));
    }
    let value = body
        .get(22)
        .ok_or_else(|| named("anchor-declaration", "backend"))?;
    if !matches!(value.as_str(), "codex" | "claude")
        || body[23..].iter().any(|word| word == "--backend")
    {
        return Err(named("anchor-declaration", "backend"));
    }
    BoxBackend::parse(value)
}
fn refusal(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("creation-anchor", error.to_string())
}
fn named(kind: &str, purpose: &str) -> LaneError {
    refusal(format!("{kind}: operation={OPERATION} purpose={purpose}"))
}
fn io(purpose: &str, check: &str, error: impl std::fmt::Display) -> LaneError {
    refusal(format!(
        "anchor-io: operation={OPERATION} purpose={purpose} check={check}: {error}"
    ))
}
const fn policy(kind: Kind, owner: Owner, mode: ModePolicy) -> Policy {
    Policy { kind, owner, mode }
}
fn rotation(args: &[String]) -> bool {
    args.iter().any(|word| word == "--rotation-sha256")
}

/// Compose native creation with a single complete capability frame.
/// # Errors
/// Refuses inconsistent paths, unsafe host objects or unavailable configuration grants.
pub fn command(
    program: &Path,
    argv: &[String],
    home: (&Path, &OwnedFd),
    runs: (&Path, &OwnedFd),
    letter: (&Path, &OwnedFd),
    source: Option<&OwnedFd>,
) -> Result<CommandSpec, LaneError> {
    if argv.len() < 23
        || argv[0] != "unshare"
        || argv[2] != "_make-home"
        || argv[7] != "--owner-home"
        || Path::new(&argv[8]) != home.0
        || argv[11] != "--podman-bin"
        || Path::new(&argv[12]) != program
        || rotation(argv) != source.is_some()
    {
        return Err(named("anchor-declaration", "vector"));
    }
    let backend = selected_backend(&argv[2..])?;
    let purposes = extras(backend);
    let mut pins = crate::runtime_entry::core_pins(
        OPERATION,
        &argv[3],
        home,
        runs,
        Path::new(&argv[1]),
        program,
    )?;
    let host = HostVerifier::current()
        .map_err(refusal)?
        .for_operation(OPERATION);
    for (slot, path) in [
        (9, crate::container_entry::credential_client(backend)),
        (10, "/usr/bin/date"),
    ] {
        pins.push(
            host.pin(
                Path::new(path),
                purposes[slot - 9],
                u32::try_from(slot).map_err(refusal)?,
                policy(Kind::File, Owner::RootFile, ModePolicy::Executable),
            )
            .map_err(refusal)?,
        );
    }
    let pin = host
        .pin(
            letter.0,
            EXTRA[2],
            11,
            crate::runtime_entry::directory_policy_for(OPERATION, letter.1, EXTRA[2])?,
        )
        .map_err(refusal)?;
    let expected = fstat(letter.1).map_err(|e| io(EXTRA[2], "held-stat", e))?;
    if (pin.record().device, pin.record().inode) != (expected.st_dev, expected.st_ino) {
        return Err(named("anchor-identity", EXTRA[2]));
    }
    pins.push(pin);
    if let Some(source) = source {
        pins.push(
            host.retain_private_file(source, EXTRA[3], 12)
                .map_err(refusal)?,
        );
    }
    let declaration = serde_json::to_string(&Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: OPERATION.into(),
        loop_name: argv[3].clone(),
        records: pins.iter().map(anchor::HostPin::record).collect(),
    })
    .map_err(refusal)?;
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
    words.extend_from_slice(argv);
    words.extend([
        "--verified-runs-root".into(),
        crate::pinned::path_word(runs.0, "runs-root")?,
        "--verified-letter-dir".into(),
        crate::pinned::path_word(letter.0, "letter-directory")?,
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
fn requirements(rotating: bool, backend: BoxBackend) -> Vec<Requirement> {
    extras(backend)[..if rotating { 4 } else { 3 }]
        .iter()
        .enumerate()
        .map(|(index, purpose)| Requirement {
            purpose: (*purpose).into(),
            alias_group: None,
            policy: match index {
                0 | 1 => policy(Kind::File, Owner::RootFile, ModePolicy::Executable),
                2 => policy(Kind::Directory, Owner::Host, ModePolicy::Exact(0o700)),
                _ => policy(Kind::File, Owner::Host, ModePolicy::Exact(0o600)),
            },
        })
        .collect()
}
/// Validate native creation custody before invoking its planned birth phases.
/// # Errors
/// Refuses missing, substituted or mismatched capabilities before any plan is read.
pub fn serve(args: &[String]) -> Result<serde_json::Value, LaneError> {
    if args.len() < 27 {
        return Err(named("anchor-missing", "manifest"));
    }
    let (body, suffix) = args.split_at(args.len() - 6);
    let [runs_flag, runs, letter_flag, letter, manifest_flag, source] = suffix else {
        return Err(named("anchor-missing", "manifest"));
    };
    if body.len() < 21
        || body[0] != "_make-home"
        || body[5] != "--owner-home"
        || body[9] != "--podman-bin"
        || runs_flag != "--verified-runs-root"
        || letter_flag != "--verified-letter-dir"
        || manifest_flag != "--anchor-manifest"
        || ![&body[6], &body[10], runs, letter]
            .iter()
            .all(|word| Path::new(word).is_absolute())
    {
        return Err(named("anchor-declaration", "vector"));
    }
    let backend = selected_backend(body)?;
    if !nix::unistd::Uid::effective().is_root() {
        return Err(named("anchor-owner", "namespace"));
    }
    let (configuration, anchors) = crate::runtime_entry::receive_bundle(
        source,
        &body[1],
        &body[6],
        OPERATION,
        &requirements(rotation(body), backend),
    )?;
    let mut anchors = anchors.into_iter();
    let mut next = || {
        anchors
            .next()
            .ok_or_else(|| named("anchor-missing", "bundle"))
    };
    let home = next()?;
    let root = next()?;
    let entry = next()?;
    let podman = next()?;
    let hash = next()?;
    let configuration_root = Arc::new(next()?);
    let custody = crate::runtime_entry::Custody {
        configuration,
        configuration_root,
        root: next()?,
        private: next()?,
        executor: next()?,
    };
    let client = next()?;
    let date = next()?;
    let letter_anchor = next()?;
    crate::container_entry::check_image(OPERATION, &entry).map_err(|mut error| {
        error.kind = "creation-anchor";
        error
    })?;
    let _home = crate::home::activate_private_launch(
        Path::new(&body[6]),
        &home,
        Path::new(runs),
        &root,
        Some((Path::new(letter), &letter_anchor)),
        0,
    )?;
    if rotation(body) {
        crate::home::attach_private_rotation_source(&next()?, 0)?;
    }
    let programs = BTreeMap::from([
        (Path::new(&body[10]).to_path_buf(), Arc::new(podman)),
        ("/usr/bin/sha256sum".into(), Arc::new(hash)),
        (
            crate::container_entry::credential_client(backend).into(),
            Arc::new(client),
        ),
        ("/usr/bin/date".into(), Arc::new(date)),
    ]);
    let _programs = crate::container_entry::activate_program_map(OPERATION, programs);
    let _configuration = custody.activate_configuration(Path::new(&body[6]), OPERATION);
    invoke(body, &custody)
}
/// Describe capabilities without opening a changing launch's storage.
pub(crate) fn preview(backend: BoxBackend) -> serde_json::Value {
    let roles = extras(backend);
    let purposes = crate::runtime_entry::PURPOSES
        .iter()
        .chain(roles[..3].iter())
        .copied()
        .collect::<Vec<_>>();
    serde_json::json!({"state":"bound-on-launch","transport":"rights","operation":OPERATION,
        "purposes":purposes,"optional_purposes":&roles[3..]})
}

fn invoke(
    args: &[String],
    custody: &crate::runtime_entry::Custody,
) -> Result<serde_json::Value, LaneError> {
    let [
        _,
        loop_name,
        run,
        letter_option,
        letter,
        home_option,
        owner_home,
        uid_option,
        worker_uid,
        podman_option,
        podman,
        model_option,
        model,
        effort_option,
        effort,
        model_source_option,
        model_source,
        effort_source_option,
        effort_source,
        door_scope_option,
        door_scope,
        backend_option,
        backend,
        rest @ ..,
    ] = args
    else {
        return Err(LaneError::input(
            "make-home-private",
            "private home form is incomplete",
        ));
    };
    let (workspace_declaration, rest) = match rest {
        [option, declaration, digest_option, digest, tail @ ..]
            if option == "--compute-workspace" && digest_option == "--workspace-digest" =>
        {
            (Some((declaration.as_str(), digest.as_str())), tail)
        }
        _ => (None, rest),
    };
    let (rotation_digest, observe) = match rest {
        [] => (None, false),
        [option] if option == "--observe" => (None, true),
        [option, digest] if option == "--rotation-sha256" => (Some(digest.as_str()), false),
        [option, digest, observe] if option == "--rotation-sha256" && observe == "--observe" => {
            (Some(digest.as_str()), true)
        }
        _ => {
            return Err(LaneError::input(
                "make-home-private",
                "private home form has unexpected arguments",
            ));
        }
    };
    if letter_option != "--letter"
        || home_option != "--owner-home"
        || uid_option != "--worker-uid"
        || podman_option != "--podman-bin"
        || model_option != "--model"
        || effort_option != "--effort"
        || model_source_option != "--model-source"
        || effort_source_option != "--effort-source"
        || door_scope_option != "--door-scope"
        || backend_option != "--backend"
    {
        return Err(LaneError::input(
            "make-home-private",
            "private home form has unexpected arguments",
        ));
    }
    let report = launch::private_make(
        Path::new(owner_home),
        loop_name,
        run,
        Path::new(letter),
        observe,
        worker_uid
            .parse()
            .map_err(|_| LaneError::input("make-home-private", "worker UID is not decimal"))?,
        Path::new(podman),
        &serde_json::json!({"model":model,"effort":effort,"model_source":model_source,"effort_source":effort_source}),
        rotation_digest,
        match door_scope.as_str() {
            "work" => crate::door::Scope::Work,
            "review" => crate::door::Scope::Review,
            _ => {
                return Err(LaneError::input(
                    "make-home-private",
                    "door scope is invalid",
                ));
            }
        },
        custody,
        BoxBackend::parse(backend)?,
        workspace_declaration,
    )?;
    Ok(report)
}
