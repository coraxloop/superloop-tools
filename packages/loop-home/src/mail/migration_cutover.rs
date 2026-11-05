//! Whole-estate migration under the reviewed install-and-cutover hold.
use super::{
    io,
    journal::{MailError, Result, digest},
    migration,
    migration_control::{self, Deployment},
    migration_history,
    migration_hold::{Baseline, DeliveryHold},
    migration_inventory::{self, Inventory},
    migration_relocation, migration_tree, provision, worker_provision,
};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    home: PathBuf,
    deployment: Deployment,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    path: PathBuf,
    backup: String,
    present: bool,
    digest: Option<String>,
    identity: Option<(u64, u64)>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ancestor {
    path: PathBuf,
    identity: (u64, u64),
    uid: u32,
    gid: u32,
    mode: u32,
    attributes: super::migration_metadata::Attributes,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Relocation {
    loop_name: String,
    lane: String,
    uid: u32,
    loop_uid: u32,
    state: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    plan: Plan,
    plan_digest: String,
    inventory: Inventory,
    snapshots: Vec<Snapshot>,
    relocations: Vec<Relocation>,
    legacy_outbox_policy: String,
    phase: String,
    mapped: usize,
    baseline: Option<Baseline>,
    history_paths: Vec<PathBuf>,
    service: Option<u32>,
    rollback_step: u8,
    ancestors: Vec<Ancestor>,
    generation: u32,
    reimport_step: u8,
    mapping_history: Vec<Vec<super::birth::Identity>>,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn directory(root: &File, name: &str) -> Result<File> {
    let uid = nix::unistd::Uid::effective().as_raw();
    let gid = nix::unistd::Gid::effective().as_raw();
    provision::directory(root, name, uid, gid, 0o700).map(|(file, _)| file)
}
fn root(path: &Path) -> Result<Flock<File>> {
    let root = io::absolute(path, true)?;
    let info = root.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw() || info.mode() & 0o7777 != 0o700 {
        return Err(invalid("unsafe-storage: migration state custody"));
    }
    Flock::lock(root, FlockArg::LockExclusiveNonblock)
        .map_err(|_| invalid("changed-source: migration is already running"))
}
fn bytes(path: &Path) -> Result<Vec<u8>> {
    migration_control::bounded(&io::absolute(path, false)?, migration_control::MAX_BYTES)
}
fn save(root: &File, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|_| invalid("invalid-directory: migration manifest encoding"))?;
    if bytes.len() as u64 > migration_control::MAX_BYTES {
        return Err(invalid(
            "invalid-directory: migration manifest exceeds implementation bound",
        ));
    }
    let mut file = File::from(openat2(
        root,
        ".cutover-next",
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    let info = file.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw()
        || info.mode() & 0o7777 != 0o600
        || !info.is_file()
        || info.nlink() != 1
    {
        return Err(invalid("unsafe-storage: migration manifest scratch"));
    }
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    renameat2(
        root,
        ".cutover-next",
        root,
        "cutover.json",
        RenameFlags::empty(),
    )?;
    root.sync_all()?;
    Ok(())
}
fn load(root: &File) -> Result<Manifest> {
    let file = io::child(root, Path::new("cutover.json"), false)?;
    let info = file.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw() || info.mode() & 0o7777 != 0o600 {
        return Err(invalid("unsafe-storage: migration manifest custody"));
    }
    let manifest: Manifest = serde_json::from_slice(&migration_control::bounded(
        &file,
        migration_control::MAX_BYTES,
    )?)
    .map_err(|_| invalid("invalid-directory: cutover manifest schema"))?;
    if manifest.version != 1 {
        return Err(invalid("invalid-directory: cutover manifest version"));
    }
    Ok(manifest)
}
fn control(plan: &Plan, state: &Path, mode: &str) -> Result<()> {
    let arguments = [
        mode.into(),
        plan.home.as_os_str().to_owned(),
        state.as_os_str().to_owned(),
    ];
    let output = migration_control::invoke(
        &plan.deployment.controller,
        &arguments,
        &plan.home,
        state,
        mode,
    )?;
    let response: Value = serde_json::from_slice(&output)
        .map_err(|_| invalid("invalid-directory: deployment controller output"))?;
    if response["operation"] != mode
        || response["home"] != plan.home.to_string_lossy().as_ref()
        || response["state"] != state.to_string_lossy().as_ref()
        || response["complete"] != true
    {
        return Err(invalid(
            "changed-source: deployment controller did not establish requested boundary",
        ));
    }
    Ok(())
}
fn registry(home: &Path) -> Result<(Vec<u8>, crate::Registry)> {
    let bytes = bytes(&home.join(".config/loops/registry.toml"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| invalid("invalid-directory: registry encoding"))?;
    let registry = crate::registry::parse_registry(text)
        .map_err(|_| invalid("invalid-directory: migration registry"))?;
    Ok((bytes, registry))
}
fn quiet(home: &Path) -> Result<()> {
    let (_, registry) = registry(home)?;
    let allocations =
        crate::allocations::Allocations::read(&home.join(".config/loops/allocations.toml"))
            .map_err(|_| invalid("invalid-directory: migration allocations"))?;
    for row in registry.rows(home) {
        worker_provision::worker_quiet(Path::new("/proc"), row.uid)?;
        if let Some(block) = allocations.get(&row.name) {
            for uid in block.uids() {
                worker_provision::worker_quiet(Path::new("/proc"), uid)?;
            }
        }
    }
    Ok(())
}
fn census(
    plan: &Plan,
    state: &Path,
    registry: &crate::Registry,
) -> Result<Vec<(String, Option<Value>)>> {
    let mut result = Vec::new();
    for row in registry.rows(&plan.home) {
        let grant = plan.home.join(".config/loops").join(&row.name);
        match io::absolute(&grant, true) {
            Err(MailError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
                    && registry.runs_root(&row.name).is_none() =>
            {
                result.push((row.name, None));
            }
            Err(error) => return Err(error),
            Ok(_) => {
                let output = migration_control::invoke(
                    &plan.deployment.native_lane,
                    &[
                        "census".into(),
                        row.name.clone().into(),
                        "--mail-migration".into(),
                    ],
                    &plan.home,
                    state,
                    &format!("census-{}", digest(row.name.as_bytes())),
                )?;
                result.push((
                    row.name,
                    Some(serde_json::from_slice(&output).map_err(|_| {
                        invalid("invalid-directory: native migration census output")
                    })?),
                ));
            }
        }
    }
    Ok(result)
}
fn optional(path: &Path) -> Result<Option<File>> {
    match io::absolute(path, true) {
        Ok(file) => Ok(Some(file)),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn legacy_rows(home: &Path, registry: &crate::Registry) -> Result<Vec<Relocation>> {
    let allocations =
        crate::allocations::Allocations::read(&home.join(".config/loops/allocations.toml"))
            .map_err(|_| invalid("invalid-directory: migration allocations"))?;
    let mut result = Vec::new();
    for row in registry.rows(home) {
        let Some(workers) = optional(&row.home.join("workers"))? else {
            continue;
        };
        let info = workers.metadata()?;
        if info.uid() == 0 {
            match bytes(&row.home.join("runs/table.tsv")) {
                Ok(table)
                    if table
                        .split(|byte| *byte == b'\n')
                        .filter(|line| !line.is_empty())
                        .count()
                        > 1 =>
                {
                    return Err(invalid(
                        "changed-source: close existing worker-run lanes through worker-run close before migration",
                    ));
                }
                Ok(_) => (),
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            continue;
        }
        if info.uid() != row.uid || info.mode() & 0o7777 != 0o710 {
            return Err(invalid("unsafe-storage: unrecognized worker namespace"));
        }
        let table = bytes(&row.home.join("runs/table.tsv"))?;
        let text = std::str::from_utf8(&table)
            .map_err(|_| invalid("invalid-directory: worker-run table encoding"))?;
        let mut lines = text.lines();
        let columns = match lines.next() {
            Some("uid\tlane\tdriver\tcommit\tstarted") => 5,
            Some("uid\tlane\tdriver\tcommit\tstarted\tclaimed") => 6,
            _ => {
                return Err(invalid(
                    "invalid-directory: worker-run legacy table requires reconciliation",
                ));
            }
        };
        if !text.ends_with('\n') {
            return Err(invalid(
                "invalid-directory: worker-run legacy table requires reconciliation",
            ));
        }
        let names = io::names(&workers)?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| invalid("invalid-directory: legacy lane encoding"))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let mut assigned = std::collections::BTreeSet::new();
        for line in lines {
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != columns
                || (columns == 6
                    && (fields[5].is_empty()
                        || !fields[5].bytes().all(|byte| byte.is_ascii_digit())))
            {
                return Err(invalid("invalid-directory: legacy worker-run row"));
            }
            let uid = fields[0]
                .parse()
                .map_err(|_| invalid("invalid-directory: legacy worker uid"))?;
            if !allocations
                .get(&row.name)
                .is_some_and(|block| block.contains(uid))
            {
                return Err(invalid(
                    "unsafe-storage: legacy worker identity is outside its loop allocation",
                ));
            }
            if !names.contains(fields[1]) || !assigned.insert(fields[1].to_owned()) {
                return Err(invalid(
                    "invalid-directory: missing or duplicate legacy execution tree",
                ));
            }
            result.push(Relocation {
                loop_name: row.name.clone(),
                lane: fields[1].into(),
                uid,
                loop_uid: row.uid,
                state: format!("relocation-{:08}", result.len()),
            });
        }
        if assigned != names {
            return Err(invalid(
                "invalid-directory: legacy execution tree lacks a table binding",
            ));
        }
    }
    Ok(result)
}
fn snapshot_inventory(snapshot_paths: Vec<PathBuf>) -> Result<Vec<Snapshot>> {
    snapshot_paths
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            let observed = optional(&path)?;
            let (present, digest, identity) = if let Some(file) = observed {
                let info = file.metadata()?;
                (
                    true,
                    Some(migration_tree::fingerprint(&file)?),
                    Some((info.dev(), info.ino())),
                )
            } else {
                (false, None, None)
            };
            Ok(Snapshot {
                present,
                digest,
                identity,
                path,
                backup: format!("backup-{index:08}"),
            })
        })
        .collect::<Result<Vec<_>>>()
}
fn ancestor_inventory(home: &Path, registry: &crate::Registry) -> Result<Vec<Ancestor>> {
    let mut ancestor_paths = vec![
        home.to_path_buf(),
        home.join(".config"),
        home.join(".var"),
        home.join(".var/loops"),
    ];
    for row in registry.rows(home) {
        ancestor_paths.push(row.home.join("private"));
        ancestor_paths.push(row.home.join("private/.config"));
        ancestor_paths.push(row.home);
    }
    ancestor_paths
        .into_iter()
        .map(|path| {
            let file = io::absolute(&path, true)?;
            let info = file.metadata()?;
            Ok(Ancestor {
                path,
                identity: (info.dev(), info.ino()),
                uid: info.uid(),
                gid: info.gid(),
                mode: info.mode() & 0o7777,
                attributes: super::migration_metadata::read(&file)?,
            })
        })
        .collect::<Result<Vec<_>>>()
}
fn historical_workers(
    home: &Path,
    registry: &crate::Registry,
    relocations: &[Relocation],
    inventory: &mut Inventory,
) -> Result<()> {
    for movement in relocations {
        let row = registry
            .row(&movement.loop_name, home)
            .map_err(|_| invalid("invalid-directory: relocation loop"))?;
        let tree = io::absolute(&row.home.join("workers").join(&movement.lane), true)?;
        let info = tree.metadata()?;
        let table_path = row.home.join("runs/table.tsv");
        inventory.workers.push(migration_inventory::Worker {
            loop_name: movement.loop_name.clone(),
            identity: super::birth::Identity::for_reservation(
                movement.uid,
                format!(
                    "migration-worker-run:{}:{}:{}:{}",
                    movement.loop_name,
                    movement.lane,
                    info.dev(),
                    info.ino()
                ),
            ),
            sources: Vec::new(),
            record: table_path.clone(),
            record_digest: digest(&bytes(&table_path)?),
        });
    }
    Ok(())
}
fn reviewed_plan(plan_path: &Path, state_path: &Path) -> Result<(Plan, String)> {
    let plan_file = io::absolute(plan_path, false)?;
    let info = plan_file.metadata()?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err(invalid("unsafe-storage: reviewed migration plan custody"));
    }
    let plan_bytes = migration_control::bounded(&plan_file, migration_control::MAX_BYTES)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)
        .map_err(|_| invalid("invalid-directory: migration deployment plan"))?;
    if plan.version != 1 || !plan.home.is_absolute() {
        return Err(invalid("invalid-directory: migration plan version or home"));
    }
    if plan
        .home
        .components()
        .chain(state_path.components())
        .any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid(
            "unsafe-storage: migration estate and state paths must be normalized",
        ));
    }
    if state_path.starts_with(&plan.home) || plan.home.starts_with(state_path) {
        return Err(invalid(
            "unsafe-storage: migration state and estate must be disjoint trees",
        ));
    }
    Ok((plan, digest(&plan_bytes)))
}
fn prepare(plan_path: &Path, state_path: &Path, state: &File) -> Result<Manifest> {
    let (plan, plan_digest) = reviewed_plan(plan_path, state_path)?;
    plan.deployment.verify(false)?;
    control(&plan, state_path, "hold")?;
    quiet(&plan.home)?;
    let (registry_bytes, registry) = registry(&plan.home)?;
    if optional(&plan.home.join(".var/loops/.mail-service"))?.is_some() {
        let service = super::command::settings(&plan.home)?.uid;
        provision::spawn_identity(
            service,
            service,
            None,
            &[
                "_mail-journal".into(),
                plan.home.as_os_str().to_owned(),
                service.to_string().into(),
            ],
        )?;
        DeliveryHold::acquire(
            io::absolute(&plan.home.join(".var/loops/.mail-service"), true)?,
            service,
        )?
        .require_no_delivery()?;
    }
    let mut inventory = migration_inventory::close(
        &plan.home,
        &registry_bytes,
        &census(&plan, state_path, &registry)?,
    )?;
    let relocations = legacy_rows(&plan.home, &registry)?;
    historical_workers(&plan.home, &registry, &relocations, &mut inventory)?;
    let mut snapshot_paths = vec![
        plan.home.join(".config/loops"),
        plan.home.join(".var/loops/.mail-service"),
    ];
    let mut history_paths = vec![
        plan.home.join(".config/loops"),
        plan.home.join(".var/loops/.mail-service"),
    ];
    for row in registry.rows(&plan.home) {
        // Only the mail configuration is migration state. The rest of a loop's
        // private tier holds its credentials and never leaves the loop's custody.
        snapshot_paths.push(row.home.join("private/.config/mail"));
        if optional(&row.home.join("workers"))?
            .is_some_and(|file| file.metadata().is_ok_and(|info| info.uid() == 0))
        {
            snapshot_paths.push(row.home.join("workers"));
        }
        for leaf in ["mail", ".mail-births", ".mail-staging"] {
            snapshot_paths.push(row.home.join(leaf));
            history_paths.push(row.home.join(leaf));
        }
        history_paths.push(row.home.join("workers"));
        history_paths.push(row.home.join("private/.config/mail"));
    }
    let snapshots = snapshot_inventory(snapshot_paths)?;
    let ancestors = ancestor_inventory(&plan.home, &registry)?;
    let manifest = Manifest {
        version: 1,
        legacy_outbox_policy: "inert: no legacy reader; writes cannot submit or authorize a round"
            .into(),
        plan,
        plan_digest,
        inventory,
        snapshots,
        relocations,
        phase: "inventory".into(),
        mapped: 0,
        baseline: None,
        history_paths,
        service: None,
        rollback_step: 0,
        ancestors,
        generation: 0,
        reimport_step: 0,
        mapping_history: Vec::new(),
    };
    save(state, &manifest)?;
    Ok(manifest)
}
fn snapshots(state: &File, manifest: &mut Manifest) -> Result<()> {
    for snapshot in &manifest.snapshots {
        match optional(&snapshot.path)? {
            Some(source) if snapshot.present => {
                let info = source.metadata()?;
                if Some((info.dev(), info.ino())) != snapshot.identity
                    || Some(migration_tree::fingerprint(&source)?) != snapshot.digest
                {
                    return Err(invalid("changed-source: frozen backup source changed"));
                }
                let proof = migration_tree::backup(&source, &directory(state, &snapshot.backup)?)?;
                if Some(proof.digest) != snapshot.digest {
                    return Err(invalid("changed-source: backup differs from frozen source"));
                }
            }
            None if !snapshot.present => (),
            _ => {
                return Err(invalid(
                    "changed-source: frozen backup source presence changed",
                ));
            }
        }
    }
    manifest.phase = "backed-up".into();
    save(state, manifest)
}
fn restore_ancestors(manifest: &Manifest) -> Result<()> {
    for ancestor in &manifest.ancestors {
        let file = io::absolute(&ancestor.path, true)?;
        let info = file.metadata()?;
        if (info.dev(), info.ino()) != ancestor.identity {
            return Err(invalid("changed-source: rollback ancestor replaced"));
        }
        nix::unistd::fchown(
            &file,
            Some(nix::unistd::Uid::from_raw(ancestor.uid)),
            Some(nix::unistd::Gid::from_raw(ancestor.gid)),
        )?;
        nix::sys::stat::fchmod(&file, Mode::from_bits_truncate(ancestor.mode))?;
        super::migration_metadata::restore(&file, &ancestor.attributes)?;
        file.sync_all()?;
        let info = file.metadata()?;
        if info.uid() != ancestor.uid
            || info.gid() != ancestor.gid
            || info.mode() & 0o7777 != ancestor.mode
            || super::migration_metadata::read(&file)? != ancestor.attributes
        {
            return Err(invalid("unsafe-storage: rollback ancestor custody differs"));
        }
    }
    Ok(())
}
fn verify_snapshots(state: &File, manifest: &Manifest) -> Result<()> {
    for snapshot in &manifest.snapshots {
        match optional(&snapshot.path)? {
            Some(source) if snapshot.present => {
                let expected = snapshot
                    .digest
                    .as_ref()
                    .ok_or_else(|| invalid("invalid-directory: missing backup digest"))?;
                let backup = io::child(state, Path::new(&snapshot.backup), true)?;
                if migration_tree::verify_backup(&backup)?.digest != *expected
                    || migration_tree::fingerprint(&source)? != *expected
                {
                    return Err(invalid(
                        "changed-source: legacy state restoration is not exact",
                    ));
                }
            }
            None if !snapshot.present => (),
            _ => {
                return Err(invalid(
                    "changed-source: restored legacy state presence differs",
                ));
            }
        }
    }
    Ok(())
}
fn service(manifest: &Manifest) -> Result<u32> {
    if let Some(service) = manifest.service {
        return Ok(service);
    }
    crate::allocations::Allocations::read(
        &manifest.plan.home.join(".config/loops/allocations.toml"),
    )
    .map_err(|_| invalid("invalid-directory: migration allocations"))?
    .mail_uid()
    .ok_or_else(|| invalid("unsafe-storage: migration mail identity is not reserved"))
}
fn journal_hold(manifest: &Manifest) -> Result<DeliveryHold> {
    DeliveryHold::acquire(
        io::absolute(&manifest.plan.home.join(".var/loops/.mail-service"), true)?,
        service(manifest)?,
    )
}
fn verify_inventory(state_path: &Path, manifest: &Manifest) -> Result<()> {
    let (registry_bytes, registry) = registry(&manifest.plan.home)?;
    let fresh = migration_inventory::close(
        &manifest.plan.home,
        &registry_bytes,
        &census(&manifest.plan, state_path, &registry)?,
    )?;
    let boxed = manifest
        .inventory
        .workers
        .iter()
        .filter(|worker| !worker.sources.is_empty())
        .collect::<Vec<_>>();
    let projection = |workers: Vec<&migration_inventory::Worker>| {
        workers.into_iter().map(|worker|json!({"loop":worker.loop_name,"uid":worker.identity.uid,"sources":worker.sources,"record":worker.record,"record_digest":worker.record_digest})).collect::<Vec<_>>()
    };
    let expected = json!({"registry":manifest.inventory.registry_digest,"sources":manifest.inventory.sources,"workers":projection(boxed),"exclusions":manifest.inventory.exclusions,"inert":manifest.inventory.inert_leaves});
    let actual = json!({"registry":fresh.registry_digest,"sources":fresh.sources,"workers":projection(fresh.workers.iter().collect()),"exclusions":fresh.exclusions,"inert":fresh.inert_leaves});
    if actual != expected || !legacy_rows(&manifest.plan.home, &registry)?.is_empty() {
        return Err(invalid(
            "changed-source: estate inventory changed during migration",
        ));
    }
    Ok(())
}
fn verify_endpoints(manifest: &Manifest) -> Result<()> {
    let service = service(manifest)?;
    // Endpoint::open deliberately validates the effective service identity. Keep
    // this half in the real service entry rather than inspecting it as root.
    provision::spawn_identity(
        service,
        service,
        None,
        &[
            "_mail-migration-inventory".into(),
            manifest.plan.home.as_os_str().to_owned(),
            service.to_string().into(),
        ],
    )?;
    for worker in &manifest.inventory.workers {
        worker_provision::verify_retired(&manifest.plan.home, &worker.loop_name, &worker.identity)?;
        let mailbox = manifest
            .plan
            .home
            .join(".var/loops")
            .join(&worker.loop_name)
            .join("workers")
            .join(&worker.identity.name)
            .join("mail");
        let root = io::absolute(&mailbox, true)?;
        let info = root.metadata()?;
        if info.uid() != service || info.gid() != service || info.mode() & 0o7777 != 0o700 {
            return Err(invalid(
                "unsafe-storage: historical mailbox is not sealed in recovery inventory",
            ));
        }
    }
    Ok(())
}
fn generation_name(kind: &str, generation: u32) -> String {
    if generation == 0 {
        kind.to_owned()
    } else {
        format!("{kind}-{generation}")
    }
}
fn apply(state_path: &Path, state: &File, manifest: &mut Manifest) -> Result<()> {
    if ["rolling-back", "rolled-back", "reimporting"].contains(&manifest.phase.as_str()) {
        return Err(invalid(
            "changed-source: retained lifetime history requires explicit reconciliation before another cutover",
        ));
    }
    manifest.plan.deployment.verify(false)?;
    control(&manifest.plan, state_path, "verify-held")?;
    quiet(&manifest.plan.home)?;
    if digest(&bytes(
        &manifest.plan.home.join(".config/loops/registry.toml"),
    )?) != manifest.inventory.registry_digest
    {
        return Err(invalid("changed-source: registry changed during migration"));
    }
    if manifest.phase == "inventory" {
        snapshots(state, manifest)?;
    }
    if manifest.phase == "backed-up" {
        for movement in &manifest.relocations {
            migration_relocation::relocate(
                &directory(state, &movement.state)?,
                &manifest
                    .plan
                    .home
                    .join(".var/loops")
                    .join(&movement.loop_name),
                movement.loop_uid,
                &movement.lane,
                movement.uid,
            )?;
        }
        manifest.phase = "relocated".into();
        save(state, manifest)?;
    }
    if manifest.phase == "relocated" {
        for name in &manifest.inventory.loops {
            provision::provision(&manifest.plan.home, name)?;
        }
        manifest.service = Some(service(manifest)?);
        manifest.phase = "provisioned".into();
        save(state, manifest)?;
    }
    if manifest.phase == "provisioned" {
        for index in manifest.mapped..manifest.inventory.workers.len() {
            let worker = &manifest.inventory.workers[index];
            // The phase is checkpointed only after the common retirement writes its terminal receipt.
            if worker_provision::retired_identity(
                &manifest.plan.home,
                &worker.loop_name,
                &worker.identity,
            )? {
                // Retained bindings are checked through the normal loop-owned store below.
                worker_provision::verify_retired(
                    &manifest.plan.home,
                    &worker.loop_name,
                    &worker.identity,
                )?;
            } else {
                for phase in ["reserve", "finish", "retire"] {
                    worker_provision::coordinate(
                        &manifest.plan.home,
                        &worker.loop_name,
                        &worker.identity,
                        phase,
                    )?;
                }
            }
            manifest.mapped = index + 1;
            save(state, manifest)?;
        }
        manifest.phase = "mapped".into();
        save(state, manifest)?;
    }
    let held = journal_hold(manifest)?;
    held.require_no_delivery()?;
    if manifest.baseline.is_none() {
        manifest.baseline = Some(held.baseline()?);
        save(state, manifest)?;
    }
    held.require_unchanged(
        manifest
            .baseline
            .as_ref()
            .ok_or_else(|| invalid("invalid-directory: journal baseline absent"))?,
    )?;
    let conversion = directory(state, &generation_name("letters", manifest.generation))?;
    migration::prepare(
        &conversion,
        manifest.inventory.mapped_sources(&manifest.plan.home),
    )?;
    migration::apply(&conversion)?;
    migration::verify(&conversion)?;
    manifest.inventory.verify_exclusions()?;
    verify_endpoints(manifest)?;
    verify_inventory(state_path, manifest)?;
    control(&manifest.plan, state_path, "verify-held")?;
    manifest.plan.deployment.verify(false)?;
    manifest.phase = "verified".into();
    save(state, manifest)
}
fn markers(manifest: &Manifest) -> Result<()> {
    for name in &manifest.inventory.loops {
        let root = io::absolute(&manifest.plan.home.join(".var/loops").join(name), true)?;
        let marker = directory(&root, ".mail-migration-hold")?;
        marker.sync_all()?;
        root.sync_all()?;
    }
    Ok(())
}
fn verify_markers(manifest: &Manifest) -> Result<()> {
    for name in &manifest.inventory.loops {
        let marker = io::absolute(
            &manifest
                .plan
                .home
                .join(".var/loops")
                .join(name)
                .join(".mail-migration-hold"),
            true,
        )?;
        let info = marker.metadata()?;
        if info.uid() != 0 || info.mode() & 0o7777 != 0o700 || !io::names(&marker)?.is_empty() {
            return Err(invalid(
                "unsafe-storage: retained lifetime history lacks its protected hold marker",
            ));
        }
    }
    Ok(())
}
fn verify_parked(state: &File, manifest: &Manifest) -> Result<()> {
    verify_markers(manifest)?;
    migration_history::verify_parked(&io::child(
        state,
        Path::new(&generation_name("lifetime-history", manifest.generation)),
        true,
    )?)
}
fn reverse_relocations(state_path: &Path, state: &File, manifest: &Manifest) -> Result<()> {
    for movement in manifest.relocations.iter().rev() {
        if optional(&state_path.join(&movement.state))?.is_some() {
            migration_relocation::rollback(&io::child(state, Path::new(&movement.state), true)?)?;
        }
    }
    let mut verified = std::collections::BTreeSet::new();
    for movement in &manifest.relocations {
        if verified.insert(&movement.loop_name)
            && optional(&state_path.join(&movement.state))?.is_some()
        {
            migration_relocation::verify_restored_table(&io::child(
                state,
                Path::new(&movement.state),
                true,
            )?)?;
        }
    }
    Ok(())
}
fn rollback(state_path: &Path, state: &File, manifest: &mut Manifest) -> Result<()> {
    if manifest.phase == "rolled-back" {
        control(&manifest.plan, state_path, "verify-restored")?;
        verify_parked(state, manifest)?;
        return manifest.plan.deployment.verify(true);
    }
    if manifest.phase != "rolling-back" {
        control(&manifest.plan, state_path, "verify-held")?;
        quiet(&manifest.plan.home)?;
        if let Some(baseline) = &manifest.baseline {
            journal_hold(manifest)?.require_unchanged(baseline)?;
        }
        if optional(&manifest.plan.home.join(".var/loops/.mail-service"))?.is_some() {
            manifest.service = Some(service(manifest)?);
        }
        manifest.phase = "rolling-back".into();
        save(state, manifest)?;
    }
    let held = if manifest.rollback_step < 2
        && manifest.service.is_some()
        && optional(&manifest.plan.home.join(".var/loops/.mail-service"))?.is_some()
    {
        Some(journal_hold(manifest)?)
    } else {
        None
    };
    if let Some(held) = &held {
        held.require_no_delivery()?;
        if let Some(baseline) = &manifest.baseline {
            held.require_unchanged(baseline)?;
        }
    }
    if manifest.rollback_step == 0 {
        if let Some(letters) =
            optional(&state_path.join(generation_name("letters", manifest.generation)))?
        {
            migration::rollback(&letters)?;
        }
        manifest.inventory.verify_exclusions()?;
        markers(manifest)?;
        // A legacy worker namespace is not lifetime history: only namespace-root mail roots enter the vault.
        let mut history_paths = Vec::new();
        for path in &manifest.history_paths {
            if path.file_name().is_some_and(|leaf| leaf == "workers")
                && optional(path)?
                    .is_some_and(|file| file.metadata().is_ok_and(|info| info.uid() != 0))
            {
                continue;
            }
            history_paths.push(path.clone());
        }
        migration_history::prepare(
            &directory(
                state,
                &generation_name("lifetime-history", manifest.generation),
            )?,
            &history_paths,
        )?;
        manifest.rollback_step = 1;
        save(state, manifest)?;
    }
    if manifest.rollback_step == 1 {
        migration_history::park(&directory(
            state,
            &generation_name("lifetime-history", manifest.generation),
        )?)?;
        manifest.rollback_step = 2;
        save(state, manifest)?;
    }
    if manifest.rollback_step == 2 {
        reverse_relocations(state_path, state, manifest)?;
        manifest.rollback_step = 3;
        save(state, manifest)?;
    }
    if manifest.rollback_step == 3 {
        // Restore bytes and previous programs while all producers remain held.
        control(&manifest.plan, state_path, "restore-state")?;
        restore_ancestors(manifest)?;
        verify_snapshots(state, manifest)?;
        manifest.plan.deployment.verify(true)?;
        verify_parked(state, manifest)?;
        manifest.rollback_step = 4;
        save(state, manifest)?;
    }
    if manifest.rollback_step == 4 {
        control(&manifest.plan, state_path, "restore-processes")?;
        control(&manifest.plan, state_path, "verify-restored")?;
        verify_parked(state, manifest)?;
        manifest.rollback_step = 5;
        save(state, manifest)?;
    }
    manifest.phase = "rolled-back".into();
    save(state, manifest)
}
fn remove_markers(manifest: &Manifest) -> Result<()> {
    // Names and their protected receipts are back before any hold marker leaves.
    for name in &manifest.inventory.loops {
        let root = io::absolute(&manifest.plan.home.join(".var/loops").join(name), true)?;
        match io::child(&root, Path::new(".mail-migration-hold"), true) {
            Ok(marker) => {
                let info = marker.metadata()?;
                if info.uid() != 0
                    || info.mode() & 0o7777 != 0o700
                    || !io::names(&marker)?.is_empty()
                {
                    return Err(invalid(
                        "unsafe-storage: migration history hold marker differs",
                    ));
                }
                nix::unistd::unlinkat(
                    &root,
                    ".mail-migration-hold",
                    nix::unistd::UnlinkatFlags::RemoveDir,
                )?;
                root.sync_all()?;
            }
            Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn reconcile(state_path: &Path, state: &File, manifest: &mut Manifest) -> Result<()> {
    let next_generation = manifest
        .generation
        .checked_add(1)
        .ok_or_else(|| invalid("invalid-directory: migration generation exhausted"))?;
    if !["rolled-back", "reimporting"].contains(&manifest.phase.as_str()) {
        return Err(invalid(
            "changed-source: only a completed rollback can reimport retained history",
        ));
    }
    if manifest.phase == "rolled-back" {
        control(&manifest.plan, state_path, "hold")?;
        quiet(&manifest.plan.home)?;
        verify_snapshots(state, manifest)?;
        manifest.inventory.verify_exclusions()?;
        verify_parked(state, manifest)?;
        manifest.phase = "reimporting".into();
        manifest.reimport_step = 0;
        save(state, manifest)?;
    }
    control(&manifest.plan, state_path, "verify-held")?;
    if manifest.reimport_step == 0 {
        control(&manifest.plan, state_path, "install-current")?;
        manifest.plan.deployment.verify(false)?;
        for (index, movement) in manifest.relocations.iter().enumerate() {
            let next = format!("relocation-generation-{next_generation}-{index:08}");
            migration_relocation::relocate(
                &directory(state, &next)?,
                &manifest
                    .plan
                    .home
                    .join(".var/loops")
                    .join(&movement.loop_name),
                movement.loop_uid,
                &movement.lane,
                movement.uid,
            )?;
        }
        manifest.reimport_step = 1;
        save(state, manifest)?;
    }
    let history = io::child(
        state,
        Path::new(&generation_name("lifetime-history", manifest.generation)),
        true,
    )?;
    if manifest.reimport_step == 1 {
        let legacy = directory(
            state,
            &generation_name("legacy-reimport", manifest.generation),
        )?;
        migration_history::prepare(&legacy, &migration_history::paths(&history)?)?;
        migration_history::park(&legacy)?;
        manifest.reimport_step = 2;
        save(state, manifest)?;
    }
    if manifest.reimport_step == 2 {
        migration_history::restore(&history)?;
        manifest.reimport_step = 3;
        save(state, manifest)?;
    }
    if manifest.reimport_step == 3 {
        remove_markers(manifest)?;
        for (index, movement) in manifest.relocations.iter_mut().enumerate() {
            movement.state = format!("relocation-generation-{next_generation}-{index:08}");
        }
        manifest.mapping_history.push(
            manifest
                .inventory
                .workers
                .iter()
                .map(|worker| worker.identity.clone())
                .collect(),
        );
        for worker in &mut manifest.inventory.workers {
            worker.identity = super::birth::Identity::for_reservation(
                worker.identity.uid,
                format!(
                    "migration-reimport:{next_generation}:{}",
                    digest(worker.identity.reservation.as_bytes())
                ),
            );
        }
        manifest.mapped = 0;
        manifest.generation = next_generation;
        manifest.baseline = None;
        manifest.rollback_step = 0;
        manifest.reimport_step = 0;
        manifest.phase = "relocated".into();
        save(state, manifest)?;
    }
    Ok(())
}
/// Execute one durable migration operation; activation remains the loop's separate cutover action.
///
/// # Errors
/// Namespace root, a protected state directory and reviewed deployment plan are mandatory.
pub fn run(arguments: &[std::ffi::OsString], report: &mut dyn std::io::Write) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(invalid("unsafe-storage: namespace-root migration required"));
    }
    let [mode, state_path, plan_path] = arguments else {
        return Err(invalid(
            "usage: superloop-mail migrate {prepare|apply|verify|rollback|reconcile} STATE PLAN",
        ));
    };
    let state_path = PathBuf::from(state_path);
    let state = root(&state_path)?;
    let mut manifest = match load(&state) {
        Ok(manifest) => {
            if digest(&bytes(Path::new(plan_path))?) != manifest.plan_digest {
                return Err(invalid("changed-source: reviewed migration plan differs"));
            }
            manifest
        }
        Err(MailError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound && mode == "prepare" =>
        {
            prepare(Path::new(plan_path), &state_path, &state)?
        }
        Err(error) => return Err(error),
    };
    if mode == "prepare" {
        if manifest.phase == "inventory" {
            snapshots(&state, &mut manifest)?;
        }
    } else if mode == "apply" {
        apply(&state_path, &state, &mut manifest)?;
    } else if mode == "verify" {
        if manifest.phase != "verified" {
            return Err(invalid("changed-source: migration is not verified"));
        }
        control(&manifest.plan, &state_path, "verify-held")?;
        manifest.plan.deployment.verify(false)?;
        let held = journal_hold(&manifest)?;
        held.require_no_delivery()?;
        held.require_unchanged(
            manifest
                .baseline
                .as_ref()
                .ok_or_else(|| invalid("invalid-directory: migration baseline absent"))?,
        )?;
        migration::verify(&io::child(
            &state,
            Path::new(&generation_name("letters", manifest.generation)),
            true,
        )?)?;
        manifest.inventory.verify_exclusions()?;
        verify_endpoints(&manifest)?;
        verify_inventory(&state_path, &manifest)?;
    } else if mode == "rollback" {
        rollback(&state_path, &state, &mut manifest)?;
    } else if mode == "reconcile" {
        reconcile(&state_path, &state, &mut manifest)?;
    } else {
        return Err(invalid(
            "usage: superloop-mail migrate {prepare|apply|verify|rollback|reconcile} STATE PLAN",
        ));
    }
    writeln!(
        report,
        "{}",
        json!({"version":1,"phase":manifest.phase,"activation":false,"verified":manifest.phase=="verified","inert_legacy_outbox_leaves":manifest.inventory.inert_leaves,"legacy_outbox_policy":manifest.legacy_outbox_policy,"lifetime_history_retained":manifest.phase=="rolled-back"})
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    fn manifest(home: &Path, snapshot: Snapshot) -> Manifest {
        let artifact = super::super::migration_control::Artifact {
            path: home.join("unused"),
            sha256: String::new(),
        };
        Manifest {
            version: 1,
            legacy_outbox_policy: "inert".into(),
            plan: Plan {
                version: 1,
                home: home.into(),
                deployment: Deployment {
                    controller: artifact.clone(),
                    native_lane: artifact,
                    artifacts: vec![],
                    retirements: vec![],
                },
            },
            plan_digest: String::new(),
            inventory: Inventory {
                registry_digest: String::new(),
                loops: vec![],
                sources: vec![],
                workers: vec![],
                exclusions: vec![],
                inert_leaves: vec![],
            },
            snapshots: vec![snapshot],
            relocations: vec![],
            phase: "inventory".into(),
            mapped: 0,
            baseline: None,
            history_paths: vec![],
            service: None,
            rollback_step: 0,
            ancestors: vec![],
            generation: 0,
            reimport_step: 0,
            mapping_history: Vec::new(),
        }
    }
    /// ´claim:loophome:migration-backup-freezes-optional-absence-before-any-mutation´
    /// ´test:unit:migration-backup-freezes-optional-absence-before-any-mutation´
    #[test]
    fn migration_backup_freezes_optional_absence_before_any_mutation() {
        let root = std::env::temp_dir().join(format!("migration-cutover-{}", std::process::id()));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("custody");
        let state = File::open(&root).expect("state");
        let source = root.join("absent");
        let mut record = manifest(
            &root,
            Snapshot {
                path: source.clone(),
                backup: "backup".into(),
                present: false,
                digest: None,
                identity: None,
            },
        );
        fs::create_dir(&source).expect("unexpected source");
        assert!(snapshots(&state, &mut record).is_err());
        assert_eq!(record.phase, "inventory");
        fs::remove_dir(source).expect("remove fixture");
        snapshots(&state, &mut record).expect("explicit absence");
        assert_eq!(record.phase, "backed-up");
        fs::remove_dir_all(root).expect("cleanup");
    }
    /// ´claim:loophome:migration-production-entry-refuses-unprivileged-estate-mutation´
    /// ´test:unit:migration-production-entry-refuses-unprivileged-estate-mutation´
    #[test]
    fn migration_production_entry_refuses_unprivileged_estate_mutation() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let mut report = Vec::new();
        let status = super::super::command::entry(
            &[
                "migrate".into(),
                "prepare".into(),
                "/absent/state".into(),
                "/absent/plan".into(),
            ],
            &mut report,
        );
        assert_eq!(status, 2);
        assert!(
            String::from_utf8(report)
                .expect("report")
                .contains("namespace-root migration required")
        );
    }
}
