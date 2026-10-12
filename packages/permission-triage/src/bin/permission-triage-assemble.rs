#![deny(clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::{Flock, FlockArg, RenameFlags, renameat2};

use loop_home::allocations::{Allocations, allocations_path};
use permission_triage::Mode;
use permission_triage::evidence::{AuditEvidence, EvidenceContext};
use permission_triage::role::{
    Registry, SubordinateMapping, effective_uid, load_registry_with_estate_uid,
};
use permission_triage::rubric::{
    load_rubrics_from_paths, refused_worker_rubric_roots, sha256_digest,
};
use serde_json::{Map, Value, json};

const USAGE: &str = "usage: permission-triage-assemble --verdict FILE --repo DIR --instance FILE --out DIR [--audit-evidence FILE] [--check]";
const WORKER_CHECK_USAGE: &str =
    "usage: permission-triage-assemble --worker-rubric-check --instance FILE --loop NAME";
const SETTINGS_FRAGMENT: &str = include_str!("../../deploy/settings-fragment.json");
const MAX_HOOK_CEILING_MS: u64 = 60_000;
const MAX_MODEL_DEADLINE_MS: u64 = 55_000;
static NEXT_REGISTRY_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(
        "permission-triage-assemble",
        env!("CARGO_PKG_VERSION"),
        None,
    );
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--worker-rubric-check")
    {
        return match run_worker_rubric_check(&arguments) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(CommandError::Usage) => {
                write_stderr(WORKER_CHECK_USAGE);
                ExitCode::from(2)
            }
            Err(CommandError::Blocked(reason) | CommandError::Infrastructure(reason)) => {
                write_stderr(&format!("worker-rubric: {reason}"));
                ExitCode::from(2)
            }
        };
    }
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CommandError::Usage) => {
            write_stderr(USAGE);
            ExitCode::from(2)
        }
        Err(CommandError::Blocked(reason)) => {
            write_stderr(&format!("blocked: {reason}"));
            ExitCode::from(3)
        }
        Err(CommandError::Infrastructure(reason)) => {
            write_stderr(&format!("infrastructure: {reason}"));
            ExitCode::from(1)
        }
    }
}

fn run_worker_rubric_check(arguments: &[OsString]) -> Result<bool, CommandError> {
    let [mode, instance_flag, instance_path, loop_flag, loop_name] = arguments else {
        return Err(CommandError::Usage);
    };
    if mode != "--worker-rubric-check" || instance_flag != "--instance" || loop_flag != "--loop" {
        return Err(CommandError::Usage);
    }
    let bytes = fs::read(instance_path)
        .map_err(|error| infrastructure(format!("instance file read failed: {error}")))?;
    let values = parse_instance_values(&bytes)?;
    let registry_path = values
        .loop_registry
        .ok_or_else(|| infrastructure("loop registry is required for worker rubric check"))?;
    let registry = load_registry_with_estate_uid(
        Some(registry_path.into_os_string()),
        values.estate_uid.map(|uid| uid.to_string().into()),
    )
    .map_err(|error| infrastructure(format!("loop registry inspection failed: {error}")))?
    .ok_or_else(|| infrastructure("loop registry is required for worker rubric check"))?;
    registry
        .validate_deployment_structure(None)
        .map_err(|error| {
            infrastructure(format!("loop registry root deployment failed: {error}"))
        })?;
    registry
        .validate_rubric_layout(values.owner_rubric.as_deref())
        .map_err(|error| {
            infrastructure(format!("loop registry rubric deployment failed: {error}"))
        })?;
    let entry = registry
        .entries()
        .iter()
        .find(|entry| OsStr::new(entry.name()) == loop_name)
        .ok_or_else(|| infrastructure("requested loop is not registered"))?;
    let orchestrator_path = entry.orchestrator_rubric().ok_or_else(|| {
        infrastructure(format!(
            "{} has no registered orchestrator rubric",
            entry.name()
        ))
    })?;
    let home = entry
        .home()
        .ok_or_else(|| infrastructure(format!("{} has no LOOP_HOME", entry.name())))?;
    let worker_path = home.join("shared/permissions/domain.md");
    let orchestrator = load_rubrics_from_paths(None, Some(orchestrator_path))
        .map_err(|error| infrastructure(format!("orchestrator rubric read failed: {error}")))?
        .domain()
        .cloned()
        .ok_or_else(|| infrastructure("orchestrator rubric is missing"))?;
    let worker = load_rubrics_from_paths(None, Some(&worker_path))
        .map_err(|error| infrastructure(format!("worker rubric read failed: {error}")))?
        .domain()
        .cloned()
        .ok_or_else(|| infrastructure("worker rubric is missing"))?;
    let refused = refused_worker_rubric_roots(orchestrator.text(), worker.text());
    let contained = refused.is_empty();
    let document = worker_verdict_bytes(
        entry.name(),
        orchestrator.digest(),
        worker.digest(),
        &refused,
        &timestamp()?,
    )?;
    write_worker_verdict(&home.join("runs"), &document)?;
    Ok(contained)
}

fn worker_verdict_bytes(
    loop_name: &str,
    orchestrator_digest: &str,
    worker_digest: &str,
    refused: &[String],
    checked_at: &str,
) -> Result<Vec<u8>, CommandError> {
    let mut document = String::new();
    let encode = |value: &str| {
        serde_json::to_string(value)
            .map_err(|error| infrastructure(format!("worker verdict JSON failed: {error}")))
    };
    let refused_json = serde_json::to_string(refused)
        .map_err(|error| infrastructure(format!("worker verdict JSON failed: {error}")))?;
    writeln!(document, "{{")
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(document, "  \"schema\": 1,")
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(document, "  \"loop\": {},", encode(loop_name)?)
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(
        document,
        "  \"orchestrator_rubric_digest\": {},",
        encode(orchestrator_digest)?
    )
    .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(
        document,
        "  \"worker_rubric_digest\": {},",
        encode(worker_digest)?
    )
    .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    let verdict = if refused.is_empty() {
        "contained"
    } else {
        "refused"
    };
    writeln!(document, "  \"verdict\": {},", encode(verdict)?)
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(document, "  \"refused_roots\": {refused_json},")
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(document, "  \"checked_at\": {}", encode(checked_at)?)
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    writeln!(document, "}}")
        .map_err(|_error| infrastructure("worker verdict formatting failed"))?;
    Ok(document.into_bytes())
}

fn write_worker_verdict(runs: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    if !fs::symlink_metadata(runs)
        .map_err(|error| infrastructure(format!("worker run tree inspection failed: {error}")))?
        .file_type()
        .is_dir()
    {
        return Err(infrastructure("worker run tree is not a real directory"));
    }
    let target = runs.join("worker-rubric-verdict.json");
    let temporary = runs.join(format!(".worker-rubric-verdict.{}.tmp", std::process::id()));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(infrastructure(format!(
                "worker verdict cleanup failed: {error}"
            )));
        }
    }
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        sync_directory(runs)
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result.map_err(|error| infrastructure(format!("worker verdict write failed: {error}")))
}

fn run(arguments: &[OsString]) -> Result<(), CommandError> {
    let parsed = parse_arguments(arguments)?;
    validate_repo(&parsed.repo)?;
    let instance_bytes = fs::read(&parsed.instance)
        .map_err(|error| infrastructure(format!("instance file read failed: {error}")))?;
    let readiness_error = |error| readiness_error(error, parsed.audit_evidence.is_some());
    let instance = validate_instance(&instance_bytes, &parsed.repo).map_err(readiness_error)?;
    let verdict_bytes = read_verdict(&parsed.verdict)?;
    let verdict = parse_verdict(&verdict_bytes).map_err(readiness_error)?;
    let classifier = inspect_classifier_binary(&instance.classifier_binary)?;
    let domain_rubric = parsed.repo.join("local/permissions/domain.md");
    validate_private_path(&domain_rubric, &parsed.repo, PrivatePathKind::DomainRubric)
        .map_err(readiness_error)?;
    let rubrics = load_rubrics_from_paths(instance.owner_rubric.as_deref(), Some(&domain_rubric))
        .map_err(|error| infrastructure(format!("rubric inspection failed: {error}")))
        .map_err(readiness_error)?;
    if instance.owner_rubric.is_some() && rubrics.owner().is_none() {
        return Err(infrastructure("configured owner rubric is missing"));
    }
    let registry_path = instance
        .loop_registry
        .as_deref()
        .ok_or_else(|| infrastructure("loop registry is required for assembly"))?;
    validate_output_separation(&parsed.out, &parsed, &instance, None)?;
    let assembly_lock = lock_registry_parent(registry_path)?;
    let snapshot = plan_allocation_snapshot(&instance)?;
    let staged = snapshot.as_ref().map(stage_snapshot).transpose()?;
    let mut proposed_instance = instance.clone();
    if let Some(staged) = &staged {
        proposed_instance.loop_registry = Some(staged.path.clone());
    }
    let inventory =
        inspect_registry_inventory(&proposed_instance, &parsed.repo).map_err(readiness_error)?;
    validate_output_separation(&parsed.out, &parsed, &instance, Some(&inventory.registry))?;
    let version = permission_triage_version()?;
    let verdict_digest = sha256_digest(&verdict_bytes);
    let rendered_instance = audit_instance(&instance_bytes)?;
    let instance_digest = sha256_digest(&rendered_instance);
    let assembled_at = timestamp()?;
    let audit_evidence = read_audit_evidence(
        parsed.audit_evidence.as_deref(),
        &assembled_at,
        &verdict,
        &verdict_digest,
        &inventory,
    )?;
    let settings = rendered_settings()?;
    let record_fields = DeploymentRecordFields {
        topology: &verdict.topology,
        verdict_digest: &verdict_digest,
        harness_version: &verdict.harness_version,
        general_rubric_digest: &version.general_rubric_digest,
        instance_digest: &instance_digest,
        classifier: &classifier,
        owner_rubric_digest: rubrics
            .owner()
            .map(permission_triage::rubric::OwnerRubric::digest),
        domain_rubric_digest: rubrics
            .domain()
            .map(permission_triage::rubric::OwnerRubric::digest),
        loop_registry: instance
            .loop_registry
            .as_deref()
            .map(|path| (path, inventory.digest.as_str())),
        domain_rubric_digests: &inventory.domains,
        assembled_at: &assembled_at,
        mode: instance.mode,
    };
    let record = deployment_record(&record_fields)?;
    let record = bind_assembly_record(
        &record,
        &verdict,
        &inventory,
        &instance_bytes,
        audit_evidence.as_ref(),
    )?;
    let marker = json_bytes(
        &json!({
            "allocationLedgerSha256": snapshot.as_ref().map(|plan| plan.ledger_digest.as_str()),
            "allocationCopiedAt": snapshot.as_ref().map(|plan| plan.copied_at.as_str()),
            "registryInventorySha256": inventory.digest,
        }),
        "assembly marker",
    )?;
    if parsed.check {
        // Validate the planned generation before discarding its scratch directory.
        return Ok(());
    }
    let mut outputs = stage_outputs(&parsed.out, &settings, &record, &rendered_instance, &marker)?;
    // The registry-parent lock precedes the configuration-root and ledger locks; prepare takes
    // the configuration-root lock first and never takes the registry-parent lock.
    let _configuration_lock = lock_configuration_source(&assembly_lock)?;
    let _ledger_lock = lock_allocation_source()?;
    recheck_allocation_source(snapshot.as_ref())?;
    publish_generation(staged, &mut outputs)
}

fn publish_generation(
    staged: Option<StagedSnapshot>,
    outputs: &mut StagedOutputs,
) -> Result<(), CommandError> {
    let older = staged
        .map(|mut staged| publish_staged_snapshot(&mut staged))
        .transpose()?
        .unwrap_or_default();
    publish_staged_outputs(outputs)?;
    for path in older {
        let _retired = fs::remove_dir_all(path);
    }
    Ok(())
}

fn read_audit_evidence(
    path: Option<&Path>,
    assembled_at: &str,
    verdict: &Verdict,
    verdict_digest: &str,
    inventory: &RegistryInventory,
) -> Result<Option<(AuditEvidence, String)>, CommandError> {
    path.map(|path| {
        let bytes = fs::read(path).map_err(|error| {
            CommandError::Blocked(format!("audit evidence read failed: {error}"))
        })?;
        let evidence = AuditEvidence::parse(
            &bytes,
            &EvidenceContext {
                assembled_at,
                harness_version: &verdict.harness_version,
                binary_digest: &verdict.harness_digest,
                topology_digest: verdict_digest,
                registry_digest: &inventory.digest,
                domain_digests: &inventory.domains,
                registry: &inventory.registry,
            },
        )
        .map_err(|reason| CommandError::Blocked(format!("enforce-readiness blocked: {reason}")))?;
        Ok((evidence, sha256_digest(&bytes)))
    })
    .transpose()
}

fn lock_registry_parent(path: &Path) -> Result<Flock<File>, CommandError> {
    let parent = path
        .parent()
        .ok_or_else(|| infrastructure("loop registry has no parent"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(parent)
        .map_err(|error| infrastructure(format!("assembly lock parent open failed: {error}")))?;
    Flock::lock(directory, FlockArg::LockExclusiveNonblock)
        .map_err(|(_directory, error)| infrastructure(format!("assembly-busy: {error}")))
}

fn lock_configuration_source(
    registry_parent_lock: &Flock<File>,
) -> Result<Option<Flock<File>>, CommandError> {
    let home = env::var_os("HOME")
        .ok_or_else(|| infrastructure("HOME is required for allocation publication"))?;
    lock_configuration_path(
        &Path::new(&home).join(".config/loops"),
        Some(registry_parent_lock),
    )
}

fn owner_only_configuration_root(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_dir()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.mode() & 0o7777 == 0o700
}

fn lock_configuration_path(
    path: &Path,
    registry_parent_lock: Option<&Flock<File>>,
) -> Result<Option<Flock<File>>, CommandError> {
    let expected = fs::symlink_metadata(path)
        .map_err(|error| infrastructure(format!("configuration root metadata failed: {error}")))?;
    if !owner_only_configuration_root(&expected) {
        return Err(infrastructure(
            "configuration root is not an owner-only directory",
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| infrastructure(format!("configuration root open failed: {error}")))?;
    let opened = directory
        .metadata()
        .map_err(|error| infrastructure(format!("configuration root metadata failed: {error}")))?;
    if !owner_only_configuration_root(&opened) {
        return Err(infrastructure(
            "configuration root is not an owner-only directory",
        ));
    }
    if opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        return Err(infrastructure("configuration root changed before assembly"));
    }
    if let Some(registry_parent_lock) = registry_parent_lock {
        let parent = registry_parent_lock.metadata().map_err(|error| {
            infrastructure(format!("assembly lock parent metadata failed: {error}"))
        })?;
        if opened.dev() == parent.dev() && opened.ino() == parent.ino() {
            return Ok(None);
        }
    }
    Flock::lock(directory, FlockArg::LockSharedNonblock)
        .map(Some)
        .map_err(|(_directory, error)| {
            infrastructure(format!("assembly-busy: configuration root: {error}"))
        })
}

struct RegistryInventory {
    registry: permission_triage::Registry,
    digest: String,
    domains: BTreeMap<String, String>,
    worker_verdicts: BTreeMap<String, Value>,
}

struct SnapshotPlan {
    directory: PathBuf,
    rows: BTreeMap<String, Vec<u8>>,
    ledger_digest: String,
    copied_at: String,
}

struct StagedSnapshot {
    path: PathBuf,
    directory: PathBuf,
    published: bool,
}

impl Drop for StagedSnapshot {
    fn drop(&mut self) {
        if !self.published {
            let _removed = fs::remove_dir_all(&self.path);
        }
    }
}

fn plan_allocation_snapshot(
    instance: &ValidatedInstance,
) -> Result<Option<SnapshotPlan>, CommandError> {
    let directory = instance
        .loop_registry
        .as_deref()
        .ok_or_else(|| infrastructure("loop registry is required for assembly"))?;
    let registry = load_registry_with_estate_uid(
        Some(directory.as_os_str().to_os_string()),
        instance.estate_uid.map(|uid| uid.to_string().into()),
    )
    .map_err(|error| infrastructure(format!("loop registry inspection failed: {error}")))?
    .ok_or_else(|| infrastructure("loop registry is required for assembly"))?;
    let home = env::var_os("HOME")
        .ok_or_else(|| infrastructure("HOME is required for allocation publication"))?;
    let ledger_path = allocations_path(Path::new(&home));
    match fs::symlink_metadata(&ledger_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if registry
                .entries()
                .iter()
                .any(|entry| entry.worker_uids().is_some())
            {
                return Err(infrastructure("allocation snapshot has no ledger"));
            }
            return Ok(None);
        }
        Err(error) => {
            return Err(infrastructure(format!(
                "allocation ledger metadata failed: {error}"
            )));
        }
        Ok(_metadata) => {}
    }
    let before = fs::metadata(&ledger_path)
        .map_err(|error| infrastructure(format!("allocation ledger metadata failed: {error}")))?;
    let (allocations, source) = Allocations::read_with_source(&ledger_path)
        .map_err(|error| infrastructure(format!("allocation ledger inspection failed: {error}")))?;
    let after = fs::metadata(&ledger_path)
        .map_err(|error| infrastructure(format!("allocation ledger metadata failed: {error}")))?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.modified().ok(),
    ) != (after.dev(), after.ino(), after.len(), after.modified().ok())
    {
        return Err(infrastructure("allocation ledger changed during assembly"));
    }
    let modified = timestamp_at(after.modified().map_err(|error| {
        infrastructure(format!(
            "allocation ledger modification time failed: {error}"
        ))
    })?)?;
    let digest = sha256_digest(source.as_bytes());
    let copied_at = timestamp()?;
    let rows = planned_allocation_rows(
        directory,
        &registry,
        &allocations,
        &digest,
        &modified,
        &copied_at,
    )?;
    Ok(Some(SnapshotPlan {
        directory: directory.to_path_buf(),
        rows,
        ledger_digest: digest,
        copied_at,
    }))
}

fn planned_allocation_rows(
    directory: &Path,
    registry: &permission_triage::Registry,
    allocations: &Allocations,
    digest: &str,
    modified: &str,
    copied_at: &str,
) -> Result<BTreeMap<String, Vec<u8>>, CommandError> {
    let mut rows = BTreeMap::new();
    for entry in registry.entries() {
        let target = directory.join(format!("{}.env", entry.name()));
        let original = fs::read_to_string(&target).map_err(|error| {
            infrastructure(format!(
                "allocation row read failed for {}: {error}",
                entry.name()
            ))
        })?;
        let expected = allocations.get(entry.name());
        let differs = entry
            .worker_uids()
            .map(|block| (block.base(), block.count()))
            != expected.map(|block| (block.base, block.count));
        let ledger_newer = entry.allocation_digest() != Some(digest)
            && entry
                .allocation_copied_at()
                .is_some_and(|copied| copied.len() == modified.len() && modified > copied);
        if differs && entry.worker_uids().is_some() && !ledger_newer {
            return Err(infrastructure(format!(
                "allocation row disagrees with ledger for {}",
                entry.name()
            )));
        }
        let mut updated = String::new();
        for line in original.lines().filter(|line| {
            !line.starts_with("LOOP_WORKER_UIDS=")
                && !line.starts_with("LOOP_ALLOCATIONS_SHA256=")
                && !line.starts_with("LOOP_ALLOCATIONS_COPIED_AT=")
        }) {
            writeln!(updated, "{line}")
                .map_err(|_error| infrastructure("allocation row formatting failed"))?;
        }
        if let Some(block) = expected {
            writeln!(updated, "LOOP_WORKER_UIDS={}:{}", block.base, block.count)
                .map_err(|_error| infrastructure("allocation row formatting failed"))?;
        }
        writeln!(updated, "LOOP_ALLOCATIONS_SHA256={digest}")
            .map_err(|_error| infrastructure("allocation row formatting failed"))?;
        writeln!(updated, "LOOP_ALLOCATIONS_COPIED_AT={copied_at}")
            .map_err(|_error| infrastructure("allocation row formatting failed"))?;
        rows.insert(
            target
                .file_name()
                .expect("entry name")
                .to_string_lossy()
                .into_owned(),
            updated.into_bytes(),
        );
    }
    Ok(rows)
}

fn recheck_allocation_source(planned: Option<&SnapshotPlan>) -> Result<(), CommandError> {
    let home = env::var_os("HOME")
        .ok_or_else(|| infrastructure("HOME is required for allocation publication"))?;
    let path = allocations_path(Path::new(&home));
    recheck_allocation_path(&path, planned.map(|plan| plan.ledger_digest.as_str()))
}

fn lock_allocation_source() -> Result<Option<Flock<File>>, CommandError> {
    let home = env::var_os("HOME")
        .ok_or_else(|| infrastructure("HOME is required for allocation publication"))?;
    lock_allocation_path(&allocations_path(Path::new(&home)))
}

fn lock_allocation_path(path: &Path) -> Result<Option<Flock<File>>, CommandError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(infrastructure(format!(
                "allocation ledger lock open failed: {error}"
            )));
        }
    };
    let opened = file.metadata().map_err(|error| {
        infrastructure(format!("allocation ledger lock metadata failed: {error}"))
    })?;
    let lock = Flock::lock(file, FlockArg::LockSharedNonblock).map_err(|(_file, error)| {
        infrastructure(format!("assembly-busy: allocation ledger: {error}"))
    })?;
    let current = fs::symlink_metadata(path)
        .map_err(|error| infrastructure(format!("allocation ledger lock path failed: {error}")))?;
    if !current.file_type().is_file()
        || current.dev() != opened.dev()
        || current.ino() != opened.ino()
    {
        return Err(infrastructure("allocation ledger changed during assembly"));
    }
    Ok(Some(lock))
}

fn recheck_allocation_path(path: &Path, expected: Option<&str>) -> Result<(), CommandError> {
    let current = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(infrastructure(format!(
                "allocation ledger metadata failed: {error}"
            )));
        }
        Ok(_metadata) => {
            let (_allocations, source) = Allocations::read_with_source(path).map_err(|error| {
                infrastructure(format!("allocation ledger inspection failed: {error}"))
            })?;
            Some(sha256_digest(source.as_bytes()))
        }
    };
    if current.as_deref() != expected {
        return Err(infrastructure("allocation ledger changed during assembly"));
    }
    Ok(())
}

fn stage_snapshot(plan: &SnapshotPlan) -> Result<StagedSnapshot, CommandError> {
    let parent = plan
        .directory
        .parent()
        .ok_or_else(|| infrastructure("registry has no parent"))?;
    let mode = fs::metadata(&plan.directory)
        .map_err(|error| infrastructure(format!("registry metadata failed: {error}")))?
        .permissions()
        .mode()
        & 0o7777;
    let registry_name = plan
        .directory
        .file_name()
        .ok_or_else(|| infrastructure("registry has no name"))?
        .to_string_lossy();
    let stage = loop {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = parent.join(format!(
            ".{registry_name}.permission-triage-retired-{}-{suffix}",
            std::process::id()
        ));
        match DirBuilder::new().mode(mode).create(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(infrastructure(format!("registry staging failed: {error}"))),
        }
    };
    let staged = StagedSnapshot {
        path: stage,
        directory: plan.directory.clone(),
        published: false,
    };
    fs::set_permissions(&staged.path, fs::Permissions::from_mode(mode))
        .map_err(|error| infrastructure(format!("registry staging mode failed: {error}")))?;
    for entry in fs::read_dir(&plan.directory)
        .map_err(|error| infrastructure(format!("registry listing failed: {error}")))?
    {
        let entry =
            entry.map_err(|error| infrastructure(format!("registry entry failed: {error}")))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| infrastructure(format!("registry entry metadata failed: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(infrastructure("registry contains a nonregular entry"));
        }
        let name = entry.file_name();
        let bytes = name
            .to_str()
            .and_then(|name| plan.rows.get(name))
            .map_or_else(
                || {
                    fs::read(entry.path()).map_err(|error| {
                        infrastructure(format!("registry entry read failed: {error}"))
                    })
                },
                |bytes| Ok(bytes.clone()),
            )?;
        write_private_row(
            &staged.path,
            &staged.path.join(&name),
            &bytes,
            metadata.permissions().mode() & 0o7777,
        )?;
    }
    sync_directory(&staged.path)
        .map_err(|error| infrastructure(format!("registry staging sync failed: {error}")))?;
    Ok(staged)
}

fn publish_staged_snapshot(staged: &mut StagedSnapshot) -> Result<Vec<PathBuf>, CommandError> {
    let parent = staged
        .directory
        .parent()
        .ok_or_else(|| infrastructure("registry has no parent"))?;
    let directory = File::open(parent)
        .map_err(|error| infrastructure(format!("registry parent open failed: {error}")))?;
    let prefix = format!(
        ".{}.permission-triage-retired-",
        staged
            .directory
            .file_name()
            .ok_or_else(|| infrastructure("registry has no name"))?
            .to_string_lossy()
    );
    let mut older = Vec::new();
    for entry in fs::read_dir(parent)
        .map_err(|error| infrastructure(format!("retired registry listing failed: {error}")))?
    {
        let entry = entry
            .map_err(|error| infrastructure(format!("retired registry entry failed: {error}")))?;
        if entry.file_name().to_string_lossy().starts_with(&prefix)
            && entry.path() != staged.path
            && entry
                .file_type()
                .map_err(|error| infrastructure(format!("retired registry type failed: {error}")))?
                .is_dir()
        {
            older.push(entry.path());
        }
    }
    directory
        .sync_all()
        .map_err(|error| infrastructure(format!("registry staging parent sync failed: {error}")))?;
    renameat2(
        &directory,
        staged
            .path
            .file_name()
            .ok_or_else(|| infrastructure("staging has no name"))?,
        &directory,
        staged
            .directory
            .file_name()
            .ok_or_else(|| infrastructure("registry has no name"))?,
        RenameFlags::RENAME_EXCHANGE,
    )
    .map_err(|error| infrastructure(format!("registry publication failed: {error}")))?;
    staged.published = true;
    let _synced = directory.sync_all();
    Ok(older)
}

fn write_private_row(
    directory: &Path,
    target: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), CommandError> {
    let name = target
        .file_name()
        .ok_or_else(|| infrastructure("allocation row has no name"))?;
    let (temporary, mut file) = loop {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = directory.join(format!(
            ".{}.{}-{suffix}.tmp",
            name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
        {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(infrastructure(format!(
                    "allocation row temporary failed: {error}"
                )));
            }
        }
    };
    let result = (|| -> io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, target)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result.map_err(|error| infrastructure(format!("allocation row publication failed: {error}")))
}

fn inspect_registry_inventory(
    instance: &ValidatedInstance,
    repo: &Path,
) -> Result<RegistryInventory, CommandError> {
    let path = instance
        .loop_registry
        .as_ref()
        .ok_or_else(|| infrastructure("loop registry is required for assembly"))?;
    let registry = load_registry_with_estate_uid(
        Some(path.clone().into_os_string()),
        instance.estate_uid.map(|uid| uid.to_string().into()),
    )
    .map_err(|error| infrastructure(format!("loop registry inspection failed: {error}")))?
    .ok_or_else(|| infrastructure("loop registry is required for assembly"))?;
    registry.validate_deployment().map_err(|error| {
        infrastructure(format!("loop registry root deployment failed: {error}"))
    })?;
    let mut authorization_sources = vec![path.as_path()];
    if let Some(owner) = instance.owner_rubric.as_deref() {
        authorization_sources.push(owner);
    }
    registry
        .validate_root_layout(&authorization_sources, Some(path))
        .map_err(|error| {
            infrastructure(format!("loop registry root deployment failed: {error}"))
        })?;
    registry
        .validate_rubric_layout(instance.owner_rubric.as_deref())
        .map_err(|error| {
            infrastructure(format!("loop registry rubric deployment failed: {error}"))
        })?;
    if registry
        .entries()
        .iter()
        .any(|entry| entry.worker_uids().is_some())
    {
        let mapping = SubordinateMapping::read_system(effective_uid().map_err(|error| {
            infrastructure(format!("deployment uid inspection failed: {error}"))
        })?)
        .map_err(|error| {
            infrastructure(format!("subordinate mapping inspection failed: {error}"))
        })?;
        registry
            .validate_subordinate_mapping(&mapping)
            .map_err(|error| {
                infrastructure(format!("loop registry subordinate mapping failed: {error}"))
            })?;
    }
    if registry
        .entries()
        .iter()
        .filter(|entry| {
            entry.checkout() == repo && entry.state_root() == Some(instance.state_root.as_path())
        })
        .count()
        != 1
    {
        return Err(infrastructure(
            "estate state root does not match its registered checkout",
        ));
    }
    let mut domains = BTreeMap::new();
    let mut worker_verdicts = BTreeMap::new();
    for entry in registry.entries() {
        let domain_path = entry.orchestrator_rubric().map_or_else(
            || entry.checkout().join("local/permissions/domain.md"),
            Path::to_path_buf,
        );
        let rubric = load_rubrics_from_paths(None, Some(&domain_path)).map_err(|error| {
            infrastructure(format!(
                "domain rubric inspection failed for {}: {error}",
                entry.name()
            ))
        })?;
        let domain = rubric.domain().ok_or_else(|| {
            infrastructure(format!("domain rubric is missing for {}", entry.name()))
        })?;
        domains.insert(entry.name().to_owned(), domain.digest().to_owned());
        if entry.worker_uids().is_some() {
            let verdict = inspect_worker_verdict(entry, domain.digest())?;
            worker_verdicts.insert(entry.name().to_owned(), verdict);
        }
        if instance.owner_rubric.as_deref().is_some_and(|owner| {
            entry
                .state_root()
                .is_some_and(|root| owner.starts_with(root))
        }) {
            return Err(infrastructure(
                "state root contains the configured owner rubric",
            ));
        }
    }
    let tuples = serde_json::to_vec(&registry.sorted_state_entries())
        .map_err(|error| infrastructure(format!("registry digest input failed: {error}")))?;
    Ok(RegistryInventory {
        registry,
        digest: sha256_digest(&tuples),
        domains,
        worker_verdicts,
    })
}

fn inspect_worker_verdict(
    entry: &permission_triage::RegistryEntry,
    orchestrator_digest: &str,
) -> Result<Value, CommandError> {
    if entry.orchestrator_rubric().is_none() {
        return Err(infrastructure(format!(
            "worker rubric verdict for {} requires a registered orchestrator rubric",
            entry.name()
        )));
    }
    let home = entry.home().ok_or_else(|| {
        infrastructure(format!(
            "worker rubric verdict for {} has no LOOP_HOME",
            entry.name()
        ))
    })?;
    let path = home.join("runs/worker-rubric-verdict.json");
    let bytes = fs::read(&path).map_err(|error| {
        infrastructure(format!(
            "worker rubric verdict for {} is unreadable: {error}",
            entry.name()
        ))
    })?;
    let verdict: Value = serde_json::from_slice(&bytes).map_err(|error| {
        infrastructure(format!(
            "worker rubric verdict for {} is invalid JSON: {error}",
            entry.name()
        ))
    })?;
    if verdict.get("schema").and_then(Value::as_u64) != Some(1)
        || verdict.get("loop").and_then(Value::as_str) != Some(entry.name())
        || verdict.get("verdict").and_then(Value::as_str) != Some("contained")
    {
        return Err(infrastructure(format!(
            "worker rubric verdict for {} is not contained",
            entry.name()
        )));
    }
    if verdict
        .get("orchestrator_rubric_digest")
        .and_then(Value::as_str)
        != Some(orchestrator_digest)
    {
        return Err(infrastructure(format!(
            "worker rubric verdict for {} has a different orchestrator rubric digest",
            entry.name()
        )));
    }
    let worker_digest = verdict
        .get("worker_rubric_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            infrastructure(format!(
                "worker rubric verdict for {} has no worker digest",
                entry.name()
            ))
        })?;
    let checked_at = verdict
        .get("checked_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            infrastructure(format!(
                "worker rubric verdict for {} has no check time",
                entry.name()
            ))
        })?;
    Ok(json!({
        "loop": entry.name(),
        "orchestratorRubricDigest": orchestrator_digest,
        "workerRubricDigest": worker_digest,
        "checkedAt": checked_at,
    }))
}

struct ParsedArguments {
    verdict: PathBuf,
    repo: PathBuf,
    instance: PathBuf,
    out: PathBuf,
    audit_evidence: Option<PathBuf>,
    check: bool,
}

fn parse_arguments(arguments: &[OsString]) -> Result<ParsedArguments, CommandError> {
    let [
        verdict_flag,
        verdict,
        repo_flag,
        repo,
        instance_flag,
        instance,
        out_flag,
        out,
        rest @ ..,
    ] = arguments
    else {
        return Err(CommandError::Usage);
    };
    if verdict_flag != "--verdict"
        || repo_flag != "--repo"
        || instance_flag != "--instance"
        || out_flag != "--out"
    {
        return Err(CommandError::Usage);
    }
    let mut parsed = ParsedArguments {
        verdict: PathBuf::from(verdict),
        repo: PathBuf::from(repo),
        instance: PathBuf::from(instance),
        out: PathBuf::from(out),
        audit_evidence: None,
        check: false,
    };
    let mut flags = rest.iter();
    while let Some(flag) = flags.next() {
        if flag == "--check" && !parsed.check {
            parsed.check = true;
        } else if flag == "--audit-evidence" && parsed.audit_evidence.is_none() {
            parsed.audit_evidence = Some(PathBuf::from(flags.next().ok_or(CommandError::Usage)?));
        } else {
            return Err(CommandError::Usage);
        }
    }
    Ok(parsed)
}

fn validate_repo(repo: &Path) -> Result<(), CommandError> {
    if !absolute_normal_path(repo) {
        return Err(infrastructure(
            "repository path must be absolute without dot components",
        ));
    }
    let metadata = fs::metadata(repo)
        .map_err(|error| infrastructure(format!("repository metadata failed: {error}")))?;
    if !metadata.is_dir() {
        return Err(infrastructure("repository path is not a directory"));
    }
    Ok(())
}

fn read_verdict(path: &Path) -> Result<Vec<u8>, CommandError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(CommandError::Blocked(
            "deployment blocked: topology verdict is missing".to_owned(),
        )),
        Err(error) => Err(infrastructure(format!(
            "topology verdict read failed: {error}"
        ))),
    }
}

struct Verdict {
    bypass_digest: String,
    harness_digest: String,
    topology: String,
    harness_version: String,
}

fn parse_verdict(bytes: &[u8]) -> Result<Verdict, CommandError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| infrastructure(format!("topology verdict JSON failed: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| infrastructure("topology verdict is not an object"))?;
    if object.get("schema").and_then(Value::as_u64) != Some(2) {
        return Err(infrastructure("topology verdict schema is not 2"));
    }
    for field in [
        "audit",
        "bypass",
        "settings_deny_wins",
        "infrastructure",
        "table_confirmation",
        "friction",
    ] {
        if !object.contains_key(field) {
            return Err(infrastructure(format!(
                "topology verdict required {field} evidence is missing"
            )));
        }
    }
    let provenance = object.get("harness_provenance");
    let fake_digest = sha256_digest(include_bytes!("../../tests/topology/fake-harness.sh"));
    let fake_path = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .is_some_and(|path| Path::new(path).file_name() == Some(OsStr::new("fake-harness.sh")))
    };
    if provenance.is_some_and(|value| {
        value.get("kind").and_then(Value::as_str) == Some("fake")
            || value.get("fake_name_match").and_then(Value::as_bool) == Some(true)
            || value.get("fake_bytes_match").and_then(Value::as_bool) == Some(true)
            || value.get("sha256").and_then(Value::as_str) == Some(fake_digest.as_str())
            || fake_path(value.get("path"))
    }) || fake_path(object.get("harness_binary"))
    {
        return Err(CommandError::Blocked(
            "deployment blocked: harness: fake".to_owned(),
        ));
    }
    let deployment_blocked = object
        .get("deployment_blocked")
        .and_then(Value::as_bool)
        .ok_or_else(|| infrastructure("topology verdict deployment_blocked is not a boolean"))?;
    if deployment_blocked {
        return Err(CommandError::Blocked(
            "deployment blocked: topology verdict forbids deployment".to_owned(),
        ));
    }
    let topology = object
        .get("selected_topology")
        .and_then(Value::as_str)
        .ok_or_else(|| infrastructure("topology verdict selected_topology is not a string"))?;
    if topology != "bypass" {
        return Err(CommandError::Blocked(
            "deployment blocked: topology verdict selected no deployable topology".to_owned(),
        ));
    }
    let (harness_version, harness_digest) = harness_identity(object)?;
    if object.get("roster_selection").and_then(Value::as_str) != Some("full") {
        return Err(infrastructure(
            "topology verdict test roster is not deployable; full roster required",
        ));
    }
    validate_topology_rows(&value)?;
    let bypass_bytes = serde_json::to_vec(&object.get("bypass")).map_err(|error| {
        infrastructure(format!("bypass evidence serialization failed: {error}"))
    })?;
    Ok(Verdict {
        bypass_digest: sha256_digest(&bypass_bytes),
        harness_digest,
        topology: topology.to_owned(),
        harness_version,
    })
}

fn harness_identity(object: &Map<String, Value>) -> Result<(String, String), CommandError> {
    let provenance = object.get("harness_provenance");
    let harness_version = object
        .get("harness_version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| infrastructure("topology verdict harness_version is missing"))?;
    if harness_version != permission_triage::topology::SUPPORTED_HARNESS_VERSION {
        return Err(infrastructure("topology verdict harness version is stale"));
    }
    let provenance = provenance
        .and_then(Value::as_object)
        .ok_or_else(|| infrastructure("topology verdict harness provenance is missing"))?;
    if provenance.get("kind").and_then(Value::as_str) != Some("real")
        || provenance.get("fake_name_match").and_then(Value::as_bool) != Some(false)
        || provenance.get("fake_bytes_match").and_then(Value::as_bool) != Some(false)
        || provenance.get("version").and_then(Value::as_str) != Some(harness_version)
        || provenance.get("path") != object.get("harness_binary")
        || !provenance
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| Path::new(path).is_absolute())
        || !provenance
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(infrastructure(
            "topology verdict harness provenance does not identify the pinned real harness",
        ));
    }
    let harness_digest = provenance
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| infrastructure("topology verdict harness digest is missing"))?;
    Ok((harness_version.to_owned(), harness_digest.to_owned()))
}

#[derive(Default)]
struct InstanceValues {
    mode: Option<Mode>,
    state_root: Option<PathBuf>,
    owner_rubric: Option<PathBuf>,
    hook_ceiling_ms: Option<u64>,
    model: Option<String>,
    model_deadline_ms: Option<u64>,
    classifier_binary: Option<PathBuf>,
    loop_registry: Option<PathBuf>,
    estate_uid: Option<u32>,
}

fn validate_instance(bytes: &[u8], repo: &Path) -> Result<ValidatedInstance, CommandError> {
    let values = parse_instance_values(bytes)?;
    let mode = values
        .mode
        .ok_or_else(|| infrastructure("instance file has no permission triage mode"))?;
    let state_root = values
        .state_root
        .as_deref()
        .ok_or_else(|| infrastructure("instance file has no state root"))?;
    validate_private_path(state_root, repo, PrivatePathKind::StateRoot)?;
    if let Some(owner_rubric) = values.owner_rubric.as_deref() {
        validate_private_path(owner_rubric, repo, PrivatePathKind::OwnerRubric)?;
    }
    let classifier_binary = values
        .classifier_binary
        .ok_or_else(|| infrastructure("instance file has no classifier binary"))?;
    if !absolute_normal_path(&classifier_binary) {
        return Err(infrastructure(
            "instance classifier binary must be absolute without dot components",
        ));
    }
    if values
        .loop_registry
        .as_deref()
        .is_some_and(|path| !absolute_normal_path(path))
    {
        return Err(infrastructure(
            "instance loop registry must be absolute without dot components",
        ));
    }
    Ok(ValidatedInstance {
        mode,
        state_root: state_root.to_path_buf(),
        classifier_binary,
        owner_rubric: values.owner_rubric,
        loop_registry: values.loop_registry,
        estate_uid: values.estate_uid,
    })
}

fn parse_instance_values(bytes: &[u8]) -> Result<InstanceValues, CommandError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_error| infrastructure("instance file is not valid UTF-8"))?;
    let mut values = InstanceValues::default();
    let mut lines = text.split('\n').peekable();
    while let Some(line) = lines.next() {
        if line.is_empty() && lines.peek().is_none() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| infrastructure("instance file line is malformed"))?;
        if value.is_empty() || !value.bytes().all(instance_value_byte) {
            return Err(infrastructure("instance file value is malformed"));
        }
        match key {
            "PERMISSION_TRIAGE_MODE" => {
                let mode = Mode::parse(OsStr::new(value)).ok_or_else(|| {
                    infrastructure("instance file PERMISSION_TRIAGE_MODE is malformed")
                })?;
                set_once(&mut values.mode, mode, key)?;
            }
            "PERMISSION_TRIAGE_STATE_ROOT" => {
                set_once(&mut values.state_root, PathBuf::from(value), key)?;
            }
            "PERMISSION_TRIAGE_OWNER_RUBRIC" => {
                set_once(&mut values.owner_rubric, PathBuf::from(value), key)?;
            }
            "PERMISSION_TRIAGE_HOOK_CEILING_MS" => {
                let number = positive_number(value, key)?;
                if number > MAX_HOOK_CEILING_MS {
                    return Err(infrastructure(
                        "PERMISSION_TRIAGE_HOOK_CEILING_MS exceeds 60000",
                    ));
                }
                set_once(&mut values.hook_ceiling_ms, number, key)?;
            }
            "PERMISSION_TRIAGE_MODEL" => {
                set_once(&mut values.model, value.to_owned(), key)?;
            }
            "PERMISSION_TRIAGE_MODEL_DEADLINE_MS" => {
                let number = positive_number(value, key)?;
                if number > MAX_MODEL_DEADLINE_MS {
                    return Err(infrastructure(
                        "PERMISSION_TRIAGE_MODEL_DEADLINE_MS exceeds 55000",
                    ));
                }
                set_once(&mut values.model_deadline_ms, number, key)?;
            }
            "PERMISSION_TRIAGE_CLI" => {
                set_once(&mut values.classifier_binary, PathBuf::from(value), key)?;
            }
            "PERMISSION_TRIAGE_LOOP_REGISTRY" => {
                set_once(&mut values.loop_registry, PathBuf::from(value), key)?;
            }
            "PERMISSION_TRIAGE_ESTATE_UID" => {
                let uid = instance_uid(value)?;
                set_once(&mut values.estate_uid, uid, key)?;
            }
            _ => return Err(infrastructure("instance file contains an unknown key")),
        }
    }
    Ok(values)
}

#[derive(Clone)]
struct ValidatedInstance {
    mode: Mode,
    state_root: PathBuf,
    classifier_binary: PathBuf,
    owner_rubric: Option<PathBuf>,
    loop_registry: Option<PathBuf>,
    estate_uid: Option<u32>,
}

const fn instance_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'.' | b'/' | b',' | b':' | b'@' | b'%' | b'+' | b'-'
        )
}

fn instance_uid(value: &str) -> Result<u32, CommandError> {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .ok_or_else(|| infrastructure("instance file PERMISSION_TRIAGE_ESTATE_UID is malformed"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), CommandError> {
    if slot.is_some() {
        return Err(infrastructure(format!("instance file repeats {key}")));
    }
    *slot = Some(value);
    Ok(())
}

fn positive_number(value: &str, key: &str) -> Result<u64, CommandError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| infrastructure(format!("instance file {key} is not a positive integer")))
}

#[derive(Clone, Copy)]
enum PrivatePathKind {
    StateRoot,
    OwnerRubric,
    DomainRubric,
}

impl PrivatePathKind {
    const fn label(self) -> &'static str {
        match self {
            Self::StateRoot => "state root",
            Self::OwnerRubric => "owner rubric",
            Self::DomainRubric => "domain rubric",
        }
    }
}

fn validate_private_path(
    path: &Path,
    repo: &Path,
    kind: PrivatePathKind,
) -> Result<(), CommandError> {
    let label = kind.label();
    if !absolute_normal_path(path) {
        return Err(infrastructure(format!(
            "instance {label} must be absolute without dot components"
        )));
    }
    if matches!(kind, PrivatePathKind::StateRoot) {
        return Ok(());
    }
    let local = repo.join("local");
    let relative = path
        .strip_prefix(&local)
        .map_err(|_error| infrastructure(format!("instance {label} is outside REPO/local")))?;
    if relative.components().next().is_none() {
        return Err(infrastructure(format!(
            "instance {label} must be beneath REPO/local"
        )));
    }
    Ok(())
}

fn absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

struct ClassifierBinary {
    path: PathBuf,
    digest: String,
}

fn inspect_classifier_binary(path: &Path) -> Result<ClassifierBinary, CommandError> {
    let metadata = fs::metadata(path)
        .map_err(|error| infrastructure(format!("classifier binary metadata failed: {error}")))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(infrastructure(
            "classifier binary is not a regular executable file",
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| infrastructure(format!("classifier binary read failed: {error}")))?;
    Ok(ClassifierBinary {
        path: path.to_owned(),
        digest: sha256_digest(&bytes),
    })
}

struct BinaryVersion {
    general_rubric_digest: String,
}

fn permission_hook_path() -> Option<PathBuf> {
    env::var_os("PERMISSION_TRIAGE_HOOK_BIN")
        .or_else(|| option_env!("PERMISSION_TRIAGE_HOOK_BIN").map(Into::into))
        .map(PathBuf::from)
}

fn permission_triage_version() -> Result<BinaryVersion, CommandError> {
    let binary = permission_hook_path()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            infrastructure("PERMISSION_TRIAGE_HOOK_BIN must name an absolute helper path")
        })?;
    let output = Command::new(&binary)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| infrastructure(format!("permission-triage version failed: {error}")))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(infrastructure(
            "permission-triage version did not exit cleanly",
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_error| infrastructure("permission-triage version output is not UTF-8"))?;
    let mut fields = text.split_whitespace();
    if fields.next() != Some("permission-triage") || fields.next().is_none() {
        return Err(infrastructure(
            "permission-triage version output is malformed",
        ));
    }
    let digest = fields
        .next()
        .and_then(|field| field.strip_prefix("general-rubric-sha256="))
        .filter(|value| digest_shape(value))
        .ok_or_else(|| infrastructure("permission-triage version digest is malformed"))?;
    if fields.next().is_some() {
        return Err(infrastructure(
            "permission-triage version output is malformed",
        ));
    }
    Ok(BinaryVersion {
        general_rubric_digest: digest.to_owned(),
    })
}

fn digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn rendered_settings() -> Result<Vec<u8>, CommandError> {
    let adapter = permission_adapter_path()
        .ok_or_else(|| infrastructure("PERMISSION_TRIAGE_ADAPTER_BIN is unset"))?;
    settings_for_adapter(&adapter)
}

fn permission_adapter_path() -> Option<PathBuf> {
    env::var_os("PERMISSION_TRIAGE_ADAPTER_BIN")
        .or_else(|| option_env!("PERMISSION_TRIAGE_ADAPTER_BIN").map(Into::into))
        .map(PathBuf::from)
}

fn settings_for_adapter(adapter: &Path) -> Result<Vec<u8>, CommandError> {
    let adapter = adapter
        .to_str()
        .filter(|_| adapter.is_absolute())
        .ok_or_else(|| {
            infrastructure("PERMISSION_TRIAGE_ADAPTER_BIN must be an absolute UTF-8 path")
        })?;
    if adapter.contains(['\n', '\r']) {
        return Err(infrastructure(
            "PERMISSION_TRIAGE_ADAPTER_BIN contains a line break",
        ));
    }
    let mut fragment: Value = serde_json::from_str(SETTINGS_FRAGMENT)
        .map_err(|error| infrastructure(format!("embedded settings fragment failed: {error}")))?;
    if !fragment.is_object() {
        return Err(infrastructure(
            "embedded settings fragment is not an object",
        ));
    }
    let command = fragment
        .pointer_mut("/hooks/PreToolUse/0/hooks/0/command")
        .ok_or_else(|| infrastructure("embedded settings fragment lacks the adapter command"))?;
    *command = Value::String(format!("'{}' pre-tool-use", adapter.replace('\'', "'\\''")));
    json_bytes(&fragment, "settings fragment")
}

struct DeploymentRecordFields<'a> {
    topology: &'a str,
    verdict_digest: &'a str,
    harness_version: &'a str,
    general_rubric_digest: &'a str,
    instance_digest: &'a str,
    classifier: &'a ClassifierBinary,
    owner_rubric_digest: Option<&'a str>,
    domain_rubric_digest: Option<&'a str>,
    domain_rubric_digests: &'a BTreeMap<String, String>,
    loop_registry: Option<(&'a Path, &'a str)>,
    assembled_at: &'a str,
    mode: Mode,
}

fn deployment_record(fields: &DeploymentRecordFields<'_>) -> Result<Vec<u8>, CommandError> {
    let mut record = Map::new();
    record.insert("topology".to_owned(), Value::from(fields.topology));
    record.insert(
        "verdictDigest".to_owned(),
        Value::from(fields.verdict_digest),
    );
    record.insert(
        "harnessVersion".to_owned(),
        Value::from(fields.harness_version),
    );
    record.insert(
        "generalRubricDigest".to_owned(),
        Value::from(fields.general_rubric_digest),
    );
    record.insert(
        "instanceDigest".to_owned(),
        Value::from(fields.instance_digest),
    );
    record.insert(
        "classifierBinary".to_owned(),
        json!({
            "path": fields.classifier.path.to_string_lossy(),
            "sha256": fields.classifier.digest.as_str(),
        }),
    );
    record.insert(
        "ownerRubricDigest".to_owned(),
        fields.owner_rubric_digest.map_or(Value::Null, Value::from),
    );
    record.insert(
        "domainRubricDigest".to_owned(),
        fields.domain_rubric_digest.map_or(Value::Null, Value::from),
    );
    record.insert(
        "loopRegistry".to_owned(),
        fields.loop_registry.map_or(Value::Null, |(path, digest)| {
            json!({
                "path": path.to_string_lossy(),
                "sha256": digest,
            })
        }),
    );
    record.insert("roleResolution".to_owned(), Value::from(2));
    record.insert(
        "domainRubricDigests".to_owned(),
        serde_json::to_value(fields.domain_rubric_digests).map_err(|error| {
            infrastructure(format!("domain inventory serialization failed: {error}"))
        })?,
    );
    record.insert("hookMode".to_owned(), Value::from(Mode::Audit.as_str()));
    record.insert(
        "sourceHookMode".to_owned(),
        Value::from(fields.mode.as_str()),
    );
    record.insert("assembledAt".to_owned(), Value::from(fields.assembled_at));
    json_bytes(&Value::Object(record), "deployment record")
}

fn audit_instance(bytes: &[u8]) -> Result<Vec<u8>, CommandError> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_error| infrastructure("instance file is not valid UTF-8"))?;
    let mut rendered = String::new();
    for line in source.lines() {
        let line = if line.starts_with("PERMISSION_TRIAGE_MODE=") {
            "PERMISSION_TRIAGE_MODE=audit"
        } else {
            line
        };
        writeln!(rendered, "{line}")
            .map_err(|_error| infrastructure("instance rendering failed"))?;
    }
    Ok(rendered.into_bytes())
}

fn bind_assembly_record(
    record: &[u8],
    verdict: &Verdict,
    inventory: &RegistryInventory,
    source_instance: &[u8],
    evidence: Option<&(AuditEvidence, String)>,
) -> Result<Vec<u8>, CommandError> {
    let mut record: Map<String, Value> = serde_json::from_slice(record)
        .map_err(|error| infrastructure(format!("assembly record parsing failed: {error}")))?;
    record.insert(
        "sourceInstanceDigest".to_owned(),
        Value::from(sha256_digest(source_instance)),
    );
    record.insert(
        "harnessBinaryDigest".to_owned(),
        Value::from(verdict.harness_digest.as_str()),
    );
    record.insert(
        "bypassEvidenceDigest".to_owned(),
        Value::from(verdict.bypass_digest.as_str()),
    );
    record.insert(
        "registryInventory".to_owned(),
        json!(inventory.registry.sorted_state_entries()),
    );
    record.insert(
        "workerRubricVerdicts".to_owned(),
        json!(inventory.worker_verdicts),
    );
    record.insert(
        "auditEvidence".to_owned(),
        evidence.map_or(Value::Null, |(record, _digest)| record.value().clone()),
    );
    record.insert(
        "auditEvidenceDigest".to_owned(),
        evidence.map_or(Value::Null, |(_record, digest)| {
            Value::from(digest.as_str())
        }),
    );
    json_bytes(&Value::Object(record), "deployment record")
}

fn validate_output_separation(
    out: &Path,
    parsed: &ParsedArguments,
    instance: &ValidatedInstance,
    registry: Option<&Registry>,
) -> Result<(), CommandError> {
    if !absolute_normal_path(out) {
        return Err(infrastructure(
            "output path must be absolute without dot components",
        ));
    }
    let output = resolved_path(out)?;
    let live = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".claude/permission-triage.env"));
    let mut protected = vec![
        parsed.instance.clone(),
        parsed.verdict.clone(),
        parsed.repo.clone(),
        instance.classifier_binary.clone(),
        instance.state_root.clone(),
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/subuid"),
        PathBuf::from("/etc/subgid"),
    ];
    if let Some(path) = parsed.audit_evidence.as_deref() {
        protected.push(path.to_path_buf());
    }
    if let Some(path) = instance.owner_rubric.as_deref() {
        protected.push(path.to_path_buf());
    }
    if let Some(path) = instance.loop_registry.as_deref() {
        protected.push(path.to_path_buf());
        if let Some(parent) = path.parent() {
            protected.push(parent.to_path_buf());
        }
    }
    if let Some(path) = live.as_deref() {
        protected.push(path.to_path_buf());
    }
    let home = env::var_os("HOME")
        .ok_or_else(|| infrastructure("HOME is required for output separation"))?;
    let ledger = allocations_path(Path::new(&home));
    if let Some(parent) = ledger.parent() {
        protected.push(parent.to_path_buf());
    }
    protected.push(ledger);
    let executable = env::current_exe()
        .map_err(|error| infrastructure(format!("assembler executable lookup failed: {error}")))?;
    protected.push(executable);
    if let Some(binary) = permission_hook_path() {
        if !binary.is_absolute() {
            return Err(infrastructure(
                "PERMISSION_TRIAGE_HOOK_BIN must name an absolute helper path",
            ));
        }
        protected.push(binary);
    }
    let adapter = permission_adapter_path()
        .ok_or_else(|| infrastructure("PERMISSION_TRIAGE_ADAPTER_BIN is unset"))?;
    if !adapter.is_absolute() {
        return Err(infrastructure(
            "PERMISSION_TRIAGE_ADAPTER_BIN must name an absolute adapter path",
        ));
    }
    protected.push(adapter);
    if let Some(registry) = registry {
        for entry in registry.entries() {
            protected.push(entry.checkout().to_path_buf());
            protected.push(entry.checkout().join("local/permissions/domain.md"));
            if let Some(path) = entry.state_root() {
                protected.push(path.to_path_buf());
            }
            if let Some(path) = entry.orchestrator_rubric() {
                protected.push(path.to_path_buf());
            }
            if let Some(path) = entry.home() {
                protected.push(path.to_path_buf());
                protected.push(path.join("runs/worker-rubric-verdict.json"));
            }
        }
    }
    for path in protected {
        let input = resolved_path(&path)?;
        if output.starts_with(&input) || input.starts_with(&output) {
            return Err(CommandError::Blocked(
                "deployment blocked: output overlaps a protected input".to_owned(),
            ));
        }
    }
    validate_dedicated_output(out)
}

fn validate_dedicated_output(out: &Path) -> Result<(), CommandError> {
    let entries = match fs::symlink_metadata(out) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::read_dir(out)
            .map_err(|error| infrastructure(format!("output directory read failed: {error}")))?,
        Ok(_other) => {
            return Err(CommandError::Blocked(
                "deployment blocked: output is not a dedicated directory".to_owned(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(infrastructure(format!(
                "output directory metadata failed: {error}"
            )));
        }
    };
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| infrastructure(format!("output directory read failed: {error}")))?;
        let name = entry.file_name();
        let known = matches!(
            name.to_str(),
            Some(
                "settings-fragment.json"
                    | "permission-triage.env"
                    | "deployment-record.json"
                    | "assembly-marker.json"
            )
        );
        if !known
            || !entry
                .file_type()
                .map_err(|error| infrastructure(format!("output entry metadata failed: {error}")))?
                .is_file()
        {
            return Err(CommandError::Blocked(
                "deployment blocked: output is not a dedicated directory".to_owned(),
            ));
        }
        seen.insert(name);
    }
    if !seen.is_empty() && seen.len() != 4 {
        return Err(CommandError::Blocked(
            "deployment blocked: output is not a dedicated directory".to_owned(),
        ));
    }
    Ok(())
}

fn resolved_path(path: &Path) -> Result<PathBuf, CommandError> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| infrastructure("path has no existing ancestor"))?;
            let name = path
                .file_name()
                .ok_or_else(|| infrastructure("path has no filename"))?;
            Ok(resolved_path(parent)?.join(name))
        }
        Err(error) => Err(infrastructure(format!(
            "output path inspection failed: {error}"
        ))),
    }
}

fn json_bytes(value: &Value, label: &str) -> Result<Vec<u8>, CommandError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| infrastructure(format!("{label} JSON failed: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn timestamp() -> Result<String, CommandError> {
    timestamp_at(SystemTime::now())
}

fn timestamp_at(moment: SystemTime) -> Result<String, CommandError> {
    let duration = moment
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| infrastructure("system clock precedes the Unix epoch"))?;
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_date(days)?;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let mut value = String::with_capacity(30);
    write!(
        value,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:09}Z",
        duration.subsec_nanos()
    )
    .map_err(|_error| infrastructure("timestamp formatting failed"))?;
    Ok(value)
}

fn civil_date(days_since_epoch: u64) -> Result<(i64, u64, u64), CommandError> {
    let epoch_days = i64::try_from(days_since_epoch)
        .map_err(|_error| infrastructure("system clock is outside the supported range"))?;
    let days = epoch_days
        .checked_add(719_468)
        .ok_or_else(|| infrastructure("system clock is outside the supported range"))?;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let month = u64::try_from(month)
        .map_err(|_error| infrastructure("timestamp month is outside the supported range"))?;
    let day = u64::try_from(day)
        .map_err(|_error| infrastructure("timestamp day is outside the supported range"))?;
    Ok((year, month, day))
}

struct StagedOutputs {
    path: PathBuf,
    target: PathBuf,
    published: bool,
}

impl Drop for StagedOutputs {
    fn drop(&mut self) {
        if !self.published {
            let _removed = fs::remove_dir_all(&self.path);
        }
    }
}

fn stage_outputs(
    out: &Path,
    settings: &[u8],
    record: &[u8],
    instance: &[u8],
    marker: &[u8],
) -> Result<StagedOutputs, CommandError> {
    stage_outputs_with_hook(out, settings, record, instance, marker, &mut |_path| Ok(()))
}

fn stage_outputs_with_hook(
    out: &Path,
    settings: &[u8],
    record: &[u8],
    instance: &[u8],
    marker: &[u8],
    after_first: &mut impl FnMut(&Path) -> Result<(), CommandError>,
) -> Result<StagedOutputs, CommandError> {
    validate_dedicated_output(out)?;
    let parent = out
        .parent()
        .ok_or_else(|| infrastructure("output path has no parent"))?;
    let mode = match fs::symlink_metadata(out) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            for name in [
                "settings-fragment.json",
                "permission-triage.env",
                "deployment-record.json",
                "assembly-marker.json",
            ] {
                match fs::symlink_metadata(out.join(name)) {
                    Ok(file) if file.file_type().is_file() => {}
                    Ok(_other) => return Err(infrastructure("output path is not a regular file")),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(infrastructure(format!(
                            "output path inspection failed: {error}"
                        )));
                    }
                }
            }
            metadata.permissions().mode() & 0o7777
        }
        Ok(_other) => return Err(infrastructure("output path is not a real directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0o700,
        Err(error) => {
            return Err(infrastructure(format!(
                "output directory metadata failed: {error}"
            )));
        }
    };
    let name = out
        .file_name()
        .ok_or_else(|| infrastructure("output path has no name"))?
        .to_string_lossy();
    let path = loop {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.permission-triage-output-{}-{suffix}.tmp",
            std::process::id()
        ));
        match DirBuilder::new().mode(mode).create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(infrastructure(format!("output staging failed: {error}"))),
        }
    };
    let staged = StagedOutputs {
        path,
        target: out.to_path_buf(),
        published: false,
    };
    fs::set_permissions(&staged.path, fs::Permissions::from_mode(mode))
        .map_err(|error| infrastructure(format!("output staging mode failed: {error}")))?;
    write_atomic(&staged.path, "settings-fragment.json", settings)?;
    after_first(&staged.path)?;
    write_atomic(&staged.path, "permission-triage.env", instance)?;
    write_atomic(&staged.path, "deployment-record.json", record)?;
    write_atomic(&staged.path, "assembly-marker.json", marker)?;
    sync_directory(&staged.path)
        .map_err(|error| infrastructure(format!("output staging sync failed: {error}")))?;
    Ok(staged)
}

fn publish_staged_outputs(staged: &mut StagedOutputs) -> Result<(), CommandError> {
    validate_dedicated_output(&staged.target)?;
    let parent = staged
        .target
        .parent()
        .ok_or_else(|| infrastructure("output path has no parent"))?;
    let directory = File::open(parent)
        .map_err(|error| infrastructure(format!("output parent open failed: {error}")))?;
    directory
        .sync_all()
        .map_err(|error| infrastructure(format!("output parent sync failed: {error}")))?;
    match fs::symlink_metadata(&staged.target) {
        Ok(metadata) if metadata.file_type().is_dir() => renameat2(
            &directory,
            staged
                .path
                .file_name()
                .ok_or_else(|| infrastructure("output staging has no name"))?,
            &directory,
            staged
                .target
                .file_name()
                .ok_or_else(|| infrastructure("output path has no name"))?,
            RenameFlags::RENAME_EXCHANGE,
        )
        .map_err(|error| infrastructure(format!("output publication failed: {error}"))),
        Ok(_other) => Err(infrastructure("output path is not a real directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::rename(&staged.path, &staged.target)
                .map_err(|error| infrastructure(format!("output publication failed: {error}")))
        }
        Err(error) => Err(infrastructure(format!("output metadata failed: {error}"))),
    }?;
    staged.published = true;
    Ok(())
}

fn write_atomic(out: &Path, name: &str, bytes: &[u8]) -> Result<(), CommandError> {
    let target = out.join(name);
    let (mut file, temporary) = loop {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = out.join(format!(
            ".{name}.permission-triage-assemble-{}-{suffix}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => break (file, temporary),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(infrastructure(format!(
                    "output temporary creation failed: {error}"
                )));
            }
        }
    };
    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        sync_directory(out)
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result.map_err(|error| infrastructure(format!("output write failed: {error}")))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[derive(Debug)]
enum CommandError {
    Usage,
    Blocked(String),
    Infrastructure(String),
}

fn readiness_error(error: CommandError, checking_evidence: bool) -> CommandError {
    match error {
        CommandError::Infrastructure(reason) if checking_evidence => {
            CommandError::Blocked(format!("enforce-readiness blocked: {reason}"))
        }
        other => other,
    }
}

fn infrastructure(reason: impl Into<String>) -> CommandError {
    CommandError::Infrastructure(reason.into())
}

fn write_stderr(reason: &str) {
    let mut stderr = io::stderr().lock();
    let _publication_failure_cannot_be_reported =
        write_stderr_to(&mut stderr, reason).and_then(|()| stderr.flush());
}

fn write_stderr_to(writer: &mut impl io::Write, reason: &str) -> io::Result<()> {
    writeln!(writer, "{}", reason.escape_debug())
}

fn validate_topology_rows(verdict: &Value) -> Result<(), CommandError> {
    let expected_roster = permission_triage::topology::planned_topology_roster();
    if verdict.get("roster") != Some(&json!(expected_roster))
        || verdict.get("planned_trials") != Some(&json!(expected_roster.len() * 3))
    {
        return Err(infrastructure(
            "topology verdict generated roster is missing or stale",
        ));
    }
    let trials = verdict
        .get("trials")
        .and_then(Value::as_array)
        .ok_or_else(|| infrastructure("topology verdict trials are missing"))?;
    for expected in permission_triage::topology::acceptance_requirements() {
        let phase = expected
            .get("phase")
            .and_then(Value::as_str)
            .ok_or_else(|| infrastructure("invalid required phase"))?;
        let rows = verdict
            .get(phase)
            .and_then(Value::as_array)
            .ok_or_else(|| {
                infrastructure(format!("topology verdict {phase} evidence is malformed"))
            })?;
        let matching = rows
            .iter()
            .filter(|row| row.get("row") == expected.get("row"))
            .collect::<Vec<_>>();
        let [row] = matching.as_slice() else {
            return Err(infrastructure(format!(
                "topology verdict {phase} row is missing or duplicated"
            )));
        };
        if row.get("classification").and_then(Value::as_str) != Some("pass")
            || row.get("hook_mode") != expected.get("hook_mode")
        {
            return Err(infrastructure(format!(
                "topology verdict {phase} row did not pass"
            )));
        }
        validate_repetitions(
            row.get("repetitions"),
            trials,
            phase,
            expected.get("hook_mode").and_then(Value::as_str) != Some("baseline")
                && phase != "settings_deny_wins",
        )?;
    }
    let tables = verdict
        .get("table_confirmation")
        .and_then(Value::as_array)
        .ok_or_else(|| infrastructure("topology verdict table_confirmation is malformed"))?;
    for expected in expected_roster.iter().filter(|row| {
        row.get("phase").and_then(Value::as_str) == Some("table-confirmation")
            && row.get("polarity").and_then(Value::as_str) == Some("positive")
    }) {
        let matching = tables
            .iter()
            .filter(|row| row.get("member") == expected.get("row"))
            .collect::<Vec<_>>();
        let [row] = matching.as_slice() else {
            return Err(infrastructure(
                "topology verdict table_confirmation member is missing or duplicated",
            ));
        };
        if !matches!(
            row.get("classification").and_then(Value::as_str),
            Some("pass" | "candidate")
        ) {
            return Err(infrastructure(
                "topology verdict table_confirmation member failed",
            ));
        }
        validate_repetitions(
            row.get("positive_repetitions"),
            trials,
            "table_confirmation",
            true,
        )?;
        validate_repetitions(
            row.get("negative_repetitions"),
            trials,
            "table_confirmation",
            true,
        )?;
    }
    validate_topology_friction(verdict)
}

fn validate_topology_friction(verdict: &Value) -> Result<(), CommandError> {
    let friction = verdict
        .get("friction")
        .and_then(Value::as_object)
        .ok_or_else(|| infrastructure("topology verdict friction is malformed"))?;
    for field in ["invocation_wall_ms", "hook_wall_ms", "verdict_wall_ms"] {
        let summary = friction.get(field).ok_or_else(|| {
            infrastructure(format!("topology verdict friction {field} is missing"))
        })?;
        if summary.get("sample_count").and_then(Value::as_u64) == Some(0) {
            return Err(infrastructure(format!(
                "topology verdict friction {field} has no samples"
            )));
        }
        for statistic in ["sample_count", "censored_count", "p50", "p95", "p99", "max"] {
            if summary.get(statistic).and_then(Value::as_u64).is_none() {
                return Err(infrastructure(format!(
                    "topology verdict friction {field}.{statistic} is missing"
                )));
            }
        }
        if field == "invocation_wall_ms"
            && summary.get("censored_count").and_then(Value::as_u64) != Some(0)
        {
            return Err(infrastructure(
                "topology verdict friction contains censored observations",
            ));
        }
    }
    Ok(())
}

fn validate_repetitions(
    ids: Option<&Value>,
    trials: &[Value],
    phase: &str,
    deciding_hook: bool,
) -> Result<(), CommandError> {
    let ids = ids
        .and_then(Value::as_array)
        .filter(|ids| ids.len() == 3)
        .ok_or_else(|| {
            infrastructure(format!(
                "topology verdict {phase} requires three repetitions"
            ))
        })?;
    let unique = ids
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != 3 {
        return Err(infrastructure(format!(
            "topology verdict {phase} repetitions are duplicated"
        )));
    }
    for id in ids {
        let matching = trials
            .iter()
            .filter(|trial| trial.get("id") == Some(id))
            .collect::<Vec<_>>();
        let [trial] = matching.as_slice() else {
            return Err(infrastructure(format!(
                "topology verdict {phase} trial is missing or duplicated"
            )));
        };
        if (deciding_hook && trial.get("hook_stdout").and_then(Value::as_array).is_none())
            || trial
                .get("invocation_wall_ms")
                .and_then(Value::as_u64)
                .is_none()
        {
            return Err(infrastructure(format!(
                "topology verdict {phase} captures are missing"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:assembler-stderr-escapes-control-bytes´
    #[test]
    fn assembler_stderr_escapes_control_bytes() {
        let mut output = Vec::new();
        write_stderr_to(&mut output, "infrastructure: bad\npath\rname").expect("diagnostic write");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8 diagnostic"),
            "infrastructure: bad\\npath\\rname\n"
        );
    }

    /// ´test:unit:assembler-retries-stale-row-temporary´
    #[test]
    fn assembler_retries_stale_row_temporary() {
        let directory = std::env::temp_dir().join(format!("assembler-temp-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("fixture directory");
        let suffix = NEXT_REGISTRY_TEMP.load(std::sync::atomic::Ordering::Relaxed);
        let stale = directory.join(format!(".alpha.env.{}-{suffix}.tmp", std::process::id()));
        fs::write(&stale, b"stale").expect("stale temporary");
        let target = directory.join("alpha.env");
        write_private_row(&directory, &target, b"LOOP_NAME=alpha\n", 0o600)
            .expect("collision retry");
        assert_eq!(fs::read(&stale).expect("stale bytes"), b"stale");
        assert_eq!(
            fs::read(&target).expect("published bytes"),
            b"LOOP_NAME=alpha\n"
        );
        fs::remove_dir_all(&directory).expect("remove fixture");
    }

    const AUDIT_INSTANCE_FIXTURE: &[u8] = b"PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/repo/local/state\nPERMISSION_TRIAGE_CLI=/private/classifier\n";
    const ENFORCE_INSTANCE_FIXTURE: &[u8] = b"PERMISSION_TRIAGE_MODE=enforce\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/repo/local/state\nPERMISSION_TRIAGE_CLI=/private/classifier\n";

    fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        value.get(name).expect("deployment record field is present")
    }

    fn fixture_mode(instance: &[u8]) -> Mode {
        validate_instance(instance, Path::new("/fixture/repo"))
            .expect("instance fixture is valid")
            .mode
    }

    /// ´test:unit:assembler-inventory-retains-sorted-roots-and-domain-digests´
    #[test]
    fn assembler_inventory_retains_sorted_roots_and_domain_digests() {
        use std::os::unix::fs::PermissionsExt as _;
        struct InventoryFixture(PathBuf);
        impl Drop for InventoryFixture {
            fn drop(&mut self) {
                let _cleanup = fs::remove_dir_all(&self.0);
            }
        }
        let fixture = InventoryFixture(env::temp_dir().join(format!(
            "permission-triage-inventory-{}",
            std::process::id()
        )));
        fs::create_dir(&fixture.0).expect("unique inventory fixture");
        let registry_path = fixture.0.join("loops.d");
        fs::create_dir(&registry_path).expect("registry");
        fs::set_permissions(&registry_path, fs::Permissions::from_mode(0o700))
            .expect("private registry");
        let mut tuples = Vec::new();
        let mut domains = BTreeMap::new();
        for (name, sid, domain) in [
            ("estate", Some("main"), "estate domain"),
            ("peer", Some("peer-main"), "peer domain"),
        ] {
            let checkout = fixture.0.join(name);
            let root = checkout.join("local/state");
            fs::create_dir_all(&root).expect("state");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private state");
            fs::create_dir_all(checkout.join("local/permissions")).expect("permissions");
            fs::write(checkout.join("local/permissions/domain.md"), domain).expect("domain");
            let entry = registry_path.join(format!("{name}.env"));
            let sid_line = sid.map_or_else(String::new, |sid| format!("LOOP_SID={sid}\n"));
            fs::write(
                &entry,
                format!(
                    "LOOP_NAME={name}\n{sid_line}LOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                    checkout.display(),
                    root.display()
                ),
            )
            .expect("entry");
            fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).expect("private entry");
            tuples.push(json!([name, sid, checkout, root]));
            domains.insert(name.to_owned(), sha256_digest(domain.as_bytes()));
        }
        let repo = fixture.0.join("estate");
        let instance = ValidatedInstance {
            mode: Mode::Audit,
            state_root: repo.join("local/state"),
            classifier_binary: fixture.0.join("classifier"),
            owner_rubric: None,
            loop_registry: Some(registry_path),
            estate_uid: None,
        };
        let inventory = inspect_registry_inventory(&instance, &repo).expect("inventory");
        assert_eq!(
            inventory.digest,
            sha256_digest(&serde_json::to_vec(&tuples).expect("sorted tuples"))
        );
        assert_eq!(inventory.domains, domains);
    }

    /// ´test:unit:assembler-state-root-validation-uses-a-typed-condition´
    #[test]
    fn assembler_state_root_validation_uses_a_typed_condition() {
        let error = validate_private_path(
            Path::new("relative/state"),
            Path::new("/fixture/repo"),
            PrivatePathKind::StateRoot,
        )
        .expect_err("relative state root is rejected");
        let CommandError::Infrastructure(reason) = error else {
            panic!("state-root validation returned the wrong error class");
        };
        assert_eq!(
            reason,
            "instance state root must be absolute without dot components"
        );
    }

    /// ´test:unit:assembler-renders-pinned-settings-and-complete-mode-record´
    #[test]
    fn assembler_renders_pinned_settings_and_complete_mode_record() {
        let instance_mode = fixture_mode(AUDIT_INSTANCE_FIXTURE);
        let settings = settings_for_adapter(Path::new("/private/superloop-claude-hook"))
            .expect("settings fragment renders");
        let expected_settings = concat!(
            "{\n",
            "  \"hooks\": {\n",
            "    \"PreToolUse\": [\n",
            "      {\n",
            "        \"hooks\": [\n",
            "          {\n",
            "            \"command\": \"'/private/superloop-claude-hook' pre-tool-use\",\n",
            "            \"timeout\": 60,\n",
            "            \"type\": \"command\"\n",
            "          }\n",
            "        ],\n",
            "        \"matcher\": \"*\"\n",
            "      }\n",
            "    ]\n",
            "  }\n",
            "}\n"
        );
        assert_eq!(settings, expected_settings.as_bytes());

        let classifier = ClassifierBinary {
            path: PathBuf::from("/private/classifier"),
            digest: "classifier-digest".to_owned(),
        };
        let record = deployment_record(&DeploymentRecordFields {
            topology: "manual",
            verdict_digest: "verdict-digest",
            harness_version: "2.1.258",
            general_rubric_digest: "general-digest",
            instance_digest: "instance-digest",
            classifier: &classifier,
            owner_rubric_digest: Some("owner-digest"),
            domain_rubric_digest: Some("domain-digest"),
            domain_rubric_digests: &BTreeMap::from([
                ("orchestration".to_owned(), "domain-digest".to_owned()),
                ("peer".to_owned(), "peer-digest".to_owned()),
            ]),
            loop_registry: Some((Path::new("/private/registry"), "registry-digest")),
            assembled_at: "2026-09-13T00:00:00.000000000Z",
            mode: instance_mode,
        })
        .expect("deployment record renders");
        let record: Value = serde_json::from_slice(&record).expect("deployment record is JSON");

        assert_eq!(field(&record, "topology"), "manual");
        assert_eq!(field(&record, "verdictDigest"), "verdict-digest");
        assert_eq!(field(&record, "harnessVersion"), "2.1.258");
        assert_eq!(field(&record, "generalRubricDigest"), "general-digest");
        assert_eq!(field(&record, "instanceDigest"), "instance-digest");
        let classifier = field(&record, "classifierBinary");
        assert_eq!(field(classifier, "path"), "/private/classifier");
        assert_eq!(field(classifier, "sha256"), "classifier-digest");
        assert_eq!(field(&record, "ownerRubricDigest"), "owner-digest");
        assert_eq!(field(&record, "domainRubricDigest"), "domain-digest");
        assert_eq!(field(&record, "roleResolution"), 2);
        assert_eq!(
            field(&record, "domainRubricDigests"),
            &json!({"orchestration": "domain-digest", "peer": "peer-digest"})
        );
        assert_eq!(field(&record, "hookMode"), "audit");
        let registry = field(&record, "loopRegistry");
        assert_eq!(field(registry, "path"), "/private/registry");
        assert_eq!(field(registry, "sha256"), "registry-digest");
        assert_eq!(
            field(&record, "assembledAt"),
            "2026-09-13T00:00:00.000000000Z"
        );
    }

    /// ´test:unit:assembler-records-an-unset-loop-registry-as-null´
    #[test]
    fn assembler_records_an_unset_loop_registry_as_null() {
        let instance_mode = fixture_mode(ENFORCE_INSTANCE_FIXTURE);
        let classifier = ClassifierBinary {
            path: PathBuf::from("/private/classifier"),
            digest: "classifier-digest".to_owned(),
        };
        let record = deployment_record(&DeploymentRecordFields {
            topology: "manual",
            verdict_digest: "verdict-digest",
            harness_version: "2.1.258",
            general_rubric_digest: "general-digest",
            instance_digest: "instance-digest",
            classifier: &classifier,
            owner_rubric_digest: None,
            domain_rubric_digest: None,
            domain_rubric_digests: &BTreeMap::new(),
            loop_registry: None,
            assembled_at: "2026-09-13T00:00:00.000000000Z",
            mode: instance_mode,
        })
        .expect("deployment record renders");
        let record: Value = serde_json::from_slice(&record).expect("deployment record is JSON");

        assert!(field(&record, "ownerRubricDigest").is_null());
        assert!(field(&record, "domainRubricDigest").is_null());
        assert!(field(&record, "loopRegistry").is_null());
        assert_eq!(field(&record, "hookMode"), "audit");
        assert_eq!(field(&record, "sourceHookMode"), "enforce");
    }

    /// ´test:unit:assembler-stages-output-failure-after-first-file-as-one-set´
    #[test]
    fn assembler_stages_output_failure_after_first_file_as_one_set() {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = env::temp_dir().join(format!("assembly-output-{}-{suffix}", std::process::id()));
        fs::create_dir(&root).expect("output fixture root");
        let out = root.join("out");
        fs::create_dir(&out).expect("existing output set");
        fs::write(out.join("deployment-record.json"), "old record")
            .expect("existing review record");
        let result = stage_outputs_with_hook(
            &out,
            b"settings",
            b"new record",
            b"instance",
            b"marker",
            &mut |stage| {
                fs::create_dir(stage.join("permission-triage.env"))
                    .expect("second staged output is obstructed");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(out.join("deployment-record.json")).expect("old record remains"),
            "old record"
        );
        assert!(!out.join("settings-fragment.json").exists());
        assert_eq!(fs::read_dir(&root).expect("fixture listing").count(), 1);
        fs::remove_dir_all(root).expect("output fixture cleanup");
    }

    /// ´test:unit:assembler-lock-and-ledger-recheck-refuse-stale-plan´
    #[test]
    fn assembler_lock_and_ledger_recheck_refuse_stale_plan() {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = Path::new("/tmp").join(format!("assembly-lock-{}-{suffix}", std::process::id()));
        let config = root.join(".config");
        let loops = config.join("loops");
        fs::create_dir_all(&loops).expect("private ledger directories");
        for path in [&root, &config, &loops] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private ledger directory");
        }
        let registry = loops.join("registry.toml");
        fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n")
            .expect("registry fixture");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600))
            .expect("private registry");
        let ledger = loops.join("allocations.toml");
        let old = "[alpha]\nuids = { base = 3000, count = 64 }\n";
        fs::write(&ledger, old).expect("first allocation");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("private ledger");
        let lock_path = root.join("loops.d");
        let lock = lock_registry_parent(&lock_path).expect("first assembly lock");
        assert!(matches!(
            lock_registry_parent(&lock_path),
            Err(CommandError::Infrastructure(reason)) if reason.contains("assembly-busy")
        ));
        fs::write(&ledger, "[alpha]\nuids = { base = 3064, count = 64 }\n")
            .expect("ledger changes while assembly holds lock");
        assert!(matches!(
            recheck_allocation_path(&ledger, Some(&sha256_digest(old.as_bytes()))),
            Err(CommandError::Infrastructure(reason)) if reason.contains("changed during assembly")
        ));
        drop(lock);
        fs::remove_dir_all(root).expect("ledger fixture cleanup");
    }

    /// ´test:unit:assembler-shared-ledger-lock-blocks-writer-through-exchange´
    #[test]
    fn assembler_shared_ledger_lock_blocks_writer_through_exchange() {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            Path::new("/tmp").join(format!("assembly-reader-{}-{suffix}", std::process::id()));
        let config = root.join(".config");
        let loops = config.join("loops");
        fs::create_dir_all(&loops).expect("private ledger directories");
        for path in [&root, &config, &loops] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private ledger directory");
        }
        let registry = loops.join("registry.toml");
        fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\" }]\n")
            .expect("registry fixture");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600))
            .expect("private registry");
        let ledger = loops.join("allocations.toml");
        let source = "[alpha]\nuids = { base = 3000, count = 64 }\n";
        fs::write(&ledger, source).expect("allocation ledger");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("private ledger");
        let live = root.join("loops.d");
        fs::create_dir(&live).expect("live registry");
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).expect("private registry");
        let row = live.join("alpha.env");
        fs::write(&row, "LOOP_NAME=alpha\nLOOP_CWD=/workspace/alpha\n").expect("old registry row");
        fs::set_permissions(&row, fs::Permissions::from_mode(0o600)).expect("private row");
        let digest = sha256_digest(source.as_bytes());
        let updated = format!(
            "LOOP_NAME=alpha\nLOOP_CWD=/workspace/alpha\nLOOP_WORKER_UIDS=3000:64\nLOOP_ALLOCATIONS_SHA256={digest}\n"
        );
        let plan = SnapshotPlan {
            directory: live.clone(),
            rows: BTreeMap::from([("alpha.env".to_owned(), updated.into_bytes())]),
            ledger_digest: digest.clone(),
            copied_at: "2026-09-30T00:00:00Z".to_owned(),
        };
        let _registry_lock = lock_registry_parent(&live).expect("registry lock first");
        let mut staged = stage_snapshot(&plan).expect("complete staged registry");
        let ledger_lock = lock_allocation_path(&ledger)
            .expect("shared ledger lock")
            .expect("ledger exists");
        recheck_allocation_path(&ledger, Some(&digest)).expect("ledger still matches");
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&ledger)
            .expect("writer opens ledger");
        assert!(Flock::lock(writer, FlockArg::LockExclusiveNonblock).is_err());
        publish_staged_snapshot(&mut staged).expect("publish while writer is refused");
        assert!(
            fs::read_to_string(live.join("alpha.env"))
                .expect("published row")
                .contains("LOOP_WORKER_UIDS=3000:64")
        );
        assert_eq!(
            fs::read_to_string(&ledger).expect("unchanged ledger"),
            source
        );
        drop(ledger_lock);
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&ledger)
            .expect("writer opens ledger after exchange");
        let _writer_lock = Flock::lock(writer, FlockArg::LockExclusiveNonblock)
            .expect("writer can proceed after assembly");
        fs::remove_dir_all(root).expect("ledger fixture cleanup");
    }

    /// ´test:unit:assembler-configuration-lock-refuses-first-allocator-through-publication´
    #[test]
    fn assembler_configuration_lock_refuses_first_allocator_through_publication() {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "assembly-first-allocation-{}-{suffix}",
            std::process::id()
        ));
        let config = root.join(".config/loops");
        fs::create_dir_all(&config).expect("configuration root");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700))
            .expect("private configuration root");
        let ledger = config.join("allocations.toml");
        let guard = lock_configuration_path(&config, None)
            .expect("assembler shared lock")
            .expect("distinct configuration lock");
        recheck_allocation_path(&ledger, None).expect("ledger is still absent");
        let writer = File::open(&config).expect("prepare opens configuration root");
        assert!(Flock::lock(writer, FlockArg::LockExclusiveNonblock).is_err());
        let out = root.join("out");
        let mut outputs = stage_outputs(&out, b"settings", b"record", b"instance", b"null-ledger")
            .expect("complete output stage");
        publish_staged_outputs(&mut outputs).expect("publish absent-ledger result");
        assert_eq!(
            fs::read(out.join("assembly-marker.json")).expect("marker"),
            b"null-ledger"
        );
        assert!(!ledger.exists());
        drop(guard);
        let writer = File::open(&config).expect("prepare reopens configuration root");
        let _writer_guard = Flock::lock(writer, FlockArg::LockExclusiveNonblock)
            .expect("first allocator can proceed after publication");
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    /// ´test:unit:assembler-retires-old-generation-only-after-output-publication´
    #[test]
    fn assembler_retires_old_generation_only_after_output_publication() {
        let suffix = NEXT_REGISTRY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "assembly-retirement-{}-{suffix}",
            std::process::id()
        ));
        let parent = root.join("registry-parent");
        let live = parent.join("loops.d");
        fs::create_dir_all(&live).expect("live registry");
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).expect("private registry");
        let row = live.join("alpha.env");
        fs::write(&row, "LOOP_NAME=alpha\nLOOP_CWD=/workspace/alpha\n").expect("old row");
        fs::set_permissions(&row, fs::Permissions::from_mode(0o600)).expect("private row");
        let retired = parent.join(".loops.d.permission-triage-retired-older");
        fs::create_dir(&retired).expect("older generation");
        fs::write(retired.join("marker"), "retain").expect("older generation marker");
        let plan = SnapshotPlan {
            directory: live,
            rows: BTreeMap::from([(
                "alpha.env".to_owned(),
                b"LOOP_NAME=alpha\nLOOP_CWD=/workspace/new-alpha\n".to_vec(),
            )]),
            ledger_digest: "a".repeat(64),
            copied_at: "2026-09-30T00:00:00.000000000Z".to_owned(),
        };
        let staged = stage_snapshot(&plan).expect("registry stage");
        let out = root.join("out");
        let mut outputs = stage_outputs(&out, b"settings", b"record", b"instance", b"marker")
            .expect("output stage");
        fs::write(&out, "publication obstacle").expect("output publication obstacle");
        assert!(publish_generation(Some(staged), &mut outputs).is_err());
        assert_eq!(
            fs::read_to_string(retired.join("marker")).expect("older generation"),
            "retain"
        );
        assert!(
            fs::read_to_string(&row)
                .expect("published row")
                .contains("/workspace/new-alpha")
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
