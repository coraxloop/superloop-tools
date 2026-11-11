//! Unit-test fixture proofs. No item in this module exists in a release build.
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use super::{ReviewedProgramBinding, RuntimeAdmission};
use crate::error::LaneError;
use crate::settings::BoxBackend;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::fstat;

pub const SENTINEL: &str = "SUPERLOOP_CLAUDE_FIXTURE_ADMISSION_V1_ONLY_UNIT_TESTS";

pub struct FixtureRoot {
    temporary: Option<tempfile::TempDir>,
    witness: Arc<RootIdentity>,
    account_home: PathBuf,
    configured_runs: PathBuf,
}
struct RootIdentity {
    path: PathBuf,
    directory: File,
    identity: (u64, u64),
}
impl FixtureRoot {
    pub(crate) fn create(configured_runs: &Path) -> Result<Arc<Self>, LaneError> {
        let account_home = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .map_err(|_| refusal("account database"))?
            .ok_or_else(|| refusal("account database"))?
            .dir;
        let temporary = tempfile::Builder::new()
            .prefix("lane-claude-admission-")
            .tempdir()
            .map_err(|_| refusal("temporary root"))?;
        let path = temporary.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| refusal("root mode"))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| refusal("root descriptor"))?;
        let stat = fstat(&directory).map_err(|_| refusal("root metadata"))?;
        Ok(Arc::new(Self {
            temporary: Some(temporary),
            witness: Arc::new(RootIdentity {
                path,
                directory,
                identity: (stat.st_dev, stat.st_ino),
            }),
            account_home,
            configured_runs: configured_runs.to_path_buf(),
        }))
    }
    pub(crate) fn path(&self) -> &Path {
        &self.witness.path
    }
}
impl RootIdentity {
    fn path(&self) -> &Path {
        &self.path
    }
    fn revalidate(&self) -> Result<(), LaneError> {
        let stat = fstat(&self.directory).map_err(|_| refusal("root metadata"))?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|_| refusal("root pathname"))?;
        if !named.is_dir()
            || (named.dev(), named.ino()) != self.identity
            || (stat.st_dev, stat.st_ino) != self.identity
            || stat.st_uid != nix::unistd::Uid::effective().as_raw()
            || stat.st_mode & 0o7777 != 0o700
        {
            return Err(refusal("root creation custody"));
        }
        Ok(())
    }
}
impl Drop for FixtureRoot {
    fn drop(&mut self) {
        // Never let TempDir delete a replacement supplied by another fixture process.
        if self.witness.revalidate().is_err()
            && let Some(directory) = self.temporary.take()
        {
            let _retained = directory.keep();
        }
    }
}

pub struct Declaration {
    pub owner_home: PathBuf,
    pub runs: PathBuf,
    pub plan_home: PathBuf,
    pub loop_name: String,
    pub run: String,
    pub worker_uid: u32,
    pub backend: BoxBackend,
    pub stand_in: PathBuf,
    pub digest: String,
}

pub struct FixtureBinding {
    digest: String,
}
impl FixtureBinding {
    pub(super) const fn digest(&self) -> &str {
        self.digest.as_str()
    }
}
struct Authority {
    root: Arc<RootIdentity>,
    owner_home: PathBuf,
    runs: PathBuf,
    loop_name: String,
    anchors: [(u64, u64); 4],
    binding: ReviewedProgramBinding,
}
struct RunKey {
    authority: Authority,
    run: String,
    worker_uid: u32,
    plan_home: PathBuf,
}
enum Scope {
    Run(RunKey),
    Periodic(PeriodicAuthority),
}
struct PeriodicAuthority {
    authority: Authority,
    driver: PathBuf,
}
pub struct FixtureAdmission {
    scope: Scope,
    thread: Cell<Option<FixtureThreadPart>>,
}
pub struct FixtureThreadPart {
    periodic: PeriodicAuthority,
}

fn refusal(field: &str) -> LaneError {
    LaneError::input("fixture-scope", format!("{SENTINEL}: refuses {field}"))
}
fn directory_identity(root: &RootIdentity, path: &Path) -> Result<(u64, u64), LaneError> {
    root.revalidate()?;
    let relative = path
        .strip_prefix(root.path())
        .map_err(|_| refusal("outside root"))?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(refusal("non-normal path"));
    }
    let fd = openat2(
        &root.directory,
        relative,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|_| refusal("directory containment"))?;
    let stat = fstat(&fd).map_err(|_| refusal("directory metadata"))?;
    Ok((stat.st_dev, stat.st_ino))
}
fn held_identities(owner: &Path) -> Result<[(u64, u64); 4], LaneError> {
    let [home, runs] = crate::home::fixture_scope_identities()?;
    let configuration = crate::runtime_entry::plan_configuration(owner)?
        .ok_or_else(|| refusal("configuration custody"))?
        .fixture_scope_identity()?;
    let programs = crate::container_entry::credential_programs(BoxBackend::Claude)?
        .ok_or_else(|| refusal("program custody"))?;
    let program = programs
        .get(Path::new("/usr/bin/claude"))
        .ok_or_else(|| refusal("Claude program custody"))?;
    program
        .revalidate()
        .map_err(|_| refusal("program policy"))?;
    let (record, _) = program.relay().map_err(|_| refusal("program record"))?;
    if record.owner_uid != 0 {
        return Err(refusal("root-owned stand-in"));
    }
    let stat = fstat(program.as_fd()).map_err(|_| refusal("program metadata"))?;
    Ok([home, runs, configuration, (stat.st_dev, stat.st_ino)])
}
fn validate(root: &FixtureRoot, declaration: &Declaration) -> Result<[(u64, u64); 4], LaneError> {
    if declaration.backend != BoxBackend::Claude {
        return Err(refusal("Codex backend"));
    }
    if declaration.digest.len() != 64
        || !declaration
            .digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(refusal("digest syntax"));
    }
    if declaration.digest == crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256 {
        return Err(refusal("reviewed vendor digest"));
    }
    if declaration.stand_in != Path::new("/usr/bin/true") {
        return Err(refusal("stand-in name"));
    }
    for path in [&declaration.owner_home, &declaration.runs] {
        if path == &root.account_home {
            return Err(refusal("account home"));
        }
        if path == &root.configured_runs {
            return Err(refusal("configured live runs"));
        }
    }
    loop_home::validate_name(&declaration.loop_name).map_err(|_| refusal("loop name"))?;
    if !crate::valid_run_name(&declaration.run) {
        return Err(refusal("run name"));
    }
    let home = directory_identity(&root.witness, &declaration.owner_home)?;
    let runs = directory_identity(&root.witness, &declaration.runs)?;
    if home == runs {
        return Err(refusal("distinct roots"));
    }
    let configuration =
        directory_identity(&root.witness, &declaration.owner_home.join(".config/loops"))?;
    let expected_home = declaration.owner_home.join(".cache/tmp").join(format!(
        "lane-{}-{}",
        declaration.loop_name, declaration.run
    ));
    if declaration.plan_home != expected_home {
        return Err(refusal("plan home mapping"));
    }
    directory_identity(&root.witness, &declaration.plan_home)?;
    let anchors = held_identities(&declaration.owner_home)?;
    if anchors[..3] != [home, runs, configuration] {
        return Err(refusal("held roots"));
    }
    let stand_in = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&declaration.stand_in)
        .map_err(|_| refusal("stand-in identity"))?;
    let stat = fstat(&stand_in).map_err(|_| refusal("stand-in metadata"))?;
    if anchors[3] != (stat.st_dev, stat.st_ino) {
        return Err(refusal("held stand-in"));
    }
    crate::container_entry::verify_program_digest(
        Path::new("/usr/bin/claude"),
        &declaration.digest,
    )?;
    Ok(anchors)
}
fn authority(
    root: Arc<RootIdentity>,
    declaration: &Declaration,
    anchors: [(u64, u64); 4],
) -> Authority {
    Authority {
        root,
        owner_home: declaration.owner_home.clone(),
        runs: declaration.runs.clone(),
        loop_name: declaration.loop_name.clone(),
        anchors,
        binding: ReviewedProgramBinding::Fixture(FixtureBinding {
            digest: declaration.digest.clone(),
        }),
    }
}

pub fn construct(
    root: &FixtureRoot,
    declaration: Declaration,
) -> Result<RuntimeAdmission, LaneError> {
    let anchors = validate(root, &declaration)?;
    // The two authorities are minted here, once; neither can be copied from a borrowed proof.
    let periodic = PeriodicAuthority {
        authority: authority(Arc::clone(&root.witness), &declaration, anchors),
        driver: declaration.runs.join(&declaration.run),
    };
    Ok(RuntimeAdmission::Fixture(Box::new(FixtureAdmission {
        scope: Scope::Run(RunKey {
            authority: authority(Arc::clone(&root.witness), &declaration, anchors),
            run: declaration.run,
            worker_uid: declaration.worker_uid,
            plan_home: declaration.plan_home,
        }),
        thread: Cell::new(Some(FixtureThreadPart { periodic })),
    })))
}
impl Authority {
    fn check(&self, owner: &Path, scope: &str, runs: &Path) -> Result<(), LaneError> {
        if owner != self.owner_home {
            return Err(refusal("owner home"));
        }
        if scope != self.loop_name {
            return Err(refusal("loop"));
        }
        if runs != self.runs {
            return Err(refusal("runs root"));
        }
        let [home, storage, configuration, _] = self.anchors;
        if directory_identity(&self.root, owner)? != home
            || directory_identity(&self.root, runs)? != storage
            || directory_identity(&self.root, &owner.join(".config/loops"))? != configuration
            || held_identities(owner)? != self.anchors
        {
            return Err(refusal("anchor identity"));
        }
        Ok(())
    }
}
impl FixtureAdmission {
    const fn authority(&self) -> &Authority {
        match &self.scope {
            Scope::Run(run) => &run.authority,
            Scope::Periodic(periodic) => &periodic.authority,
        }
    }
    fn run(&self) -> Result<&RunKey, LaneError> {
        match &self.scope {
            Scope::Run(run) => Ok(run),
            Scope::Periodic(_) => Err(refusal("periodic proof at run")),
        }
    }
    pub(super) fn backend(&self, backend: BoxBackend) -> Result<(), LaneError> {
        if backend != BoxBackend::Claude {
            return Err(refusal("backend"));
        }
        self.authority().root.revalidate()
    }
    pub(super) const fn binding(&self) -> &ReviewedProgramBinding {
        &self.authority().binding
    }
    pub(super) fn names(&self, home: &Path, scope: &str, name: &str) -> Result<(), LaneError> {
        let run = self.run()?;
        if name != run.run {
            return Err(refusal("run"));
        }
        run.authority.check(home, scope, &run.authority.runs)
    }
    pub(super) fn round(
        &self,
        home: &Path,
        scope: &str,
        worker: &Path,
        uid: u32,
    ) -> Result<(), LaneError> {
        let run = self.run()?;
        if worker != run.plan_home {
            return Err(refusal("plan home"));
        }
        if uid != run.worker_uid {
            return Err(refusal("worker uid"));
        }
        directory_identity(&run.authority.root, worker)?;
        run.authority.check(home, scope, &run.authority.runs)
    }
    pub(super) fn periodic(&self, home: &Path, scope: &str, runs: &Path) -> Result<(), LaneError> {
        self.roots(home, scope, runs)?;
        if matches!(self.scope, Scope::Run(_)) {
            return Err(refusal("run proof at periodic"));
        }
        Ok(())
    }
    pub(super) fn roots(&self, home: &Path, scope: &str, runs: &Path) -> Result<(), LaneError> {
        self.authority().check(home, scope, runs)
    }
    pub(super) fn plan(&self, document: &serde_json::Value) -> Result<(), LaneError> {
        self.backend(BoxBackend::from_plan(document)?)?;
        let run = self.run()?;
        if document["loop"].as_str() != Some(run.authority.loop_name.as_str()) {
            return Err(refusal("loop"));
        }
        if document["run"].as_str() != Some(run.run.as_str()) {
            return Err(refusal("run"));
        }
        if document["driver_dir"].as_str() != run.authority.runs.join(&run.run).to_str() {
            return Err(refusal("driver directory"));
        }
        let worker = document["home"]
            .as_str()
            .ok_or_else(|| refusal("plan home"))?;
        let uid = document["worker_uid"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| refusal("worker uid"))?;
        self.round(
            &run.authority.owner_home,
            &run.authority.loop_name,
            Path::new(worker),
            uid,
        )
    }
    pub(super) fn record(&self, record: &serde_json::Value) -> Result<(), LaneError> {
        self.plan(&record["plan"])?;
        if record["worker_uid"].as_u64() != Some(u64::from(self.run()?.worker_uid)) {
            return Err(refusal("worker uid"));
        }
        Ok(())
    }
    pub(super) fn recipient(&self, worker: &Path) -> Result<(), LaneError> {
        let authority = self.authority();
        authority.check(&authority.owner_home, &authority.loop_name, &authority.runs)?;
        let prefix = format!("lane-{}-", authority.loop_name);
        let run = worker
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(&prefix))
            .ok_or_else(|| refusal("recipient"))?;
        if !crate::valid_run_name(run)
            || worker.parent() != Some(authority.owner_home.join(".cache/tmp").as_path())
        {
            return Err(refusal("recipient"));
        }
        directory_identity(&authority.root, worker)?;
        Ok(())
    }
    pub(super) fn evidence(&self, driver: &Path) -> Result<(), LaneError> {
        let authority = self.authority();
        authority.check(&authority.owner_home, &authority.loop_name, &authority.runs)?;
        let expected = match &self.scope {
            Scope::Run(run) => authority.runs.join(&run.run),
            Scope::Periodic(periodic) => periodic.driver.clone(),
        };
        if driver != expected {
            return Err(refusal("evidence directory"));
        }
        let run = driver
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refusal("evidence directory"))?;
        if !crate::valid_run_name(run) || driver.parent() != Some(authority.runs.as_path()) {
            return Err(refusal("evidence directory"));
        }
        directory_identity(&authority.root, driver)?;
        let protected = crate::plan::protected_identity_dir(driver)?;
        directory_identity(&authority.root, &protected)?;
        Ok(())
    }
    pub(crate) fn take_thread(
        &self,
        _: &crate::container_helper::CapturePermit,
    ) -> Result<FixtureThreadPart, LaneError> {
        let authority = self.authority();
        authority.check(&authority.owner_home, &authority.loop_name, &authority.runs)?;
        self.thread
            .take()
            .ok_or_else(|| refusal("thread already transferred"))
    }
}
impl FixtureThreadPart {
    pub(crate) fn activate(
        self,
        _: &crate::container_helper::ActivationPermit,
    ) -> Result<RuntimeAdmission, LaneError> {
        let authority = &self.periodic.authority;
        authority.check(&authority.owner_home, &authority.loop_name, &authority.runs)?;
        Ok(RuntimeAdmission::Fixture(Box::new(FixtureAdmission {
            scope: Scope::Periodic(self.periodic),
            thread: Cell::new(None),
        })))
    }
}
