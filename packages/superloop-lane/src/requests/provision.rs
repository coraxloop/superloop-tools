//! Deploy the private request registry from validated estate rows.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat, mkdirat};
use serde_json::{Value, json};

use crate::error::LaneError;

fn failure(detail: impl std::fmt::Display) -> LaneError {
    LaneError::input("requests-registry-refusal", detail.to_string())
}

fn at(path: &Path, error: impl std::fmt::Display) -> LaneError {
    failure(format!("{}: {error}", path.display()))
}

fn normal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .all(|part| part != b"." && part != b"..")
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn destination<'a>(home: &Path, path: &'a Path) -> Result<&'a Path, LaneError> {
    let relative = path.strip_prefix(home).map_err(|error| at(path, error))?;
    if !normal(path) || relative.as_os_str().is_empty() {
        return Err(at(
            path,
            "destination must be a normal child path of the calling home",
        ));
    }
    Ok(relative)
}

struct PinnedHome<'a> {
    path: &'a Path,
    directory: OwnedFd,
    owner: u32,
}

struct Walk {
    directory: Option<OwnedFd>,
    created: bool,
    missing: bool,
    identity: Value,
}

impl<'a> PinnedHome<'a> {
    fn open(path: &'a Path) -> Result<Self, LaneError> {
        let owner = nix::unistd::Uid::effective().as_raw();
        let directory = crate::home::pin_parent(path, owner).map_err(|error| at(path, error))?;
        Ok(Self {
            path,
            directory,
            owner,
        })
    }

    fn walk(&self, path: &Path, dry: bool) -> Result<Walk, LaneError> {
        let relative = destination(self.path, path)?;
        let mut parent = nix::unistd::dup(&self.directory).map_err(|error| at(path, error))?;
        let mut current = self.path.to_path_buf();
        let mut created = false;
        for part in relative.components() {
            let name = Path::new(part.as_os_str());
            current.push(name);
            let open = || {
                openat2(
                    &parent,
                    name,
                    OpenHow::new()
                        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
                )
            };
            let next = match open() {
                Ok(fd) => fd,
                Err(Errno::ENOENT) if dry => {
                    return Ok(Walk {
                        directory: None,
                        created: false,
                        missing: true,
                        identity: Value::Null,
                    });
                }
                Err(Errno::ENOENT) => {
                    match mkdirat(&parent, name, Mode::from_bits_truncate(0o700)) {
                        Ok(()) => created |= current == path,
                        Err(Errno::EEXIST) => {}
                        Err(error) => return Err(at(&current, error)),
                    }
                    open().map_err(|error| at(&current, error))?
                }
                Err(error) => return Err(at(&current, error)),
            };
            let stat = fstat(&next).map_err(|error| at(&current, error))?;
            if stat.st_uid != self.owner {
                return Err(at(
                    &current,
                    format!(
                        "foreign owner: expected {}, found {}",
                        self.owner, stat.st_uid
                    ),
                ));
            }
            if stat.st_mode & 0o022 != 0 {
                return Err(at(&current, "group or other writable directory"));
            }
            parent = next;
        }
        let stat = fstat(&parent).map_err(|error| at(path, error))?;
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(at(path, "not a private directory (requires mode 0700)"));
        }
        Ok(Walk {
            directory: Some(parent),
            created,
            missing: false,
            identity: json!({"st_dev":stat.st_dev,"st_ino":stat.st_ino}),
        })
    }
}

fn literal(value: &str) -> Result<&str, LaneError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(failure(
            "registry value is empty or contains a control character",
        ));
    }
    Ok(value)
}

fn entry_name(name: &str) -> bool {
    name.strip_suffix(".env").is_some_and(|stem| {
        !stem.is_empty()
            && stem.len() <= 128
            && stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    })
}

#[derive(Default)]
struct Entries {
    names: BTreeSet<Vec<u8>>,
    texts: BTreeMap<String, Vec<u8>>,
}

impl Entries {
    fn read(parent: Option<&OwnedFd>, registry: &Path, owner: u32) -> Result<Self, LaneError> {
        let mut result = Self::default();
        if let Some(parent) = parent {
            let mut directory = Dir::openat(
                parent,
                ".",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| at(registry, error))?;
            for entry in directory.iter() {
                let entry = entry.map_err(|error| at(registry, error))?;
                let bytes = entry.file_name().to_bytes();
                if matches!(bytes, b"." | b"..") {
                    continue;
                }
                result.names.insert(bytes.to_vec());
                result.check_bounds(registry)?;
                if let Ok(name) = std::str::from_utf8(bytes)
                    && entry_name(name)
                {
                    let path = registry.join(name);
                    let text = super::store::read_leaf(parent, name, owner, 65_536)
                        .map_err(|error| at(&path, error.detail))?
                        .ok_or_else(|| at(&path, "registry entry disappeared"))?;
                    result.texts.insert(name.to_owned(), text);
                }
            }
        }
        Ok(result)
    }

    fn check_bounds(&self, registry: &Path) -> Result<(), LaneError> {
        if self.names.len() > 1024
            || self.names.iter().map(|name| name.len() + 1).sum::<usize>() > 65_536
        {
            return Err(at(registry, "registry listing exceeds reader limits"));
        }
        Ok(())
    }

    fn parsed(&self, registry: &Path, deployment: bool) -> Result<Vec<ParsedEntry>, LaneError> {
        let client = super::channel_client::Client::for_registry(registry)
            .map_err(|error| at(registry, error.detail))?;
        let response = client
            .call(
                "--registry-validate",
                if deployment { "deployment" } else { "parse" },
                "",
                Some(&serde_json::to_value(&self.texts).map_err(failure)?),
            )
            .map_err(|error| at(registry, error.detail))?;
        if response["schema"] != 1 {
            return Err(at(registry, "registry validation reply schema"));
        }
        response["entries"]
            .as_array()
            .ok_or_else(|| at(registry, "registry validation entries absent"))?
            .iter()
            .map(|entry| {
                let name = entry["name"]
                    .as_str()
                    .ok_or_else(|| at(registry, "entry name absent"))?
                    .to_owned();
                let state_root = entry["state_root"]
                    .as_str()
                    .map(PathBuf::from)
                    .filter(|path| normal(path))
                    .ok_or_else(|| {
                        at(
                            registry,
                            format!("{name}: LOOP_STATE_ROOT must be an absolute normal path"),
                        )
                    })?;
                let home = entry["home"].as_str().map(PathBuf::from);
                Ok(ParsedEntry {
                    name,
                    state_root,
                    home,
                })
            })
            .collect()
    }
}

struct ParsedEntry {
    name: String,
    state_root: PathBuf,
    home: Option<PathBuf>,
}

pub(super) fn run(
    home: &Path,
    loop_name: &str,
    state: Option<&Path>,
    dry: bool,
) -> Result<Value, LaneError> {
    let source = loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
    let owner = nix::unistd::Uid::effective().as_raw();
    let parent = crate::home::pin_parent(
        source
            .parent()
            .ok_or_else(|| failure("registry parent absent"))?,
        owner,
    )
    .map_err(|error| at(&source, error))?;
    let fd = openat2(
        &parent,
        Path::new(
            source
                .file_name()
                .ok_or_else(|| failure("registry name absent"))?,
        ),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| at(&source, error))?;
    let stat = fstat(&fd).map_err(|error| at(&source, error))?;
    if stat.st_uid != owner
        || stat.st_mode & 0o022 != 0
        || SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
    {
        return Err(at(
            &source,
            "estate registry must be a protected regular file owned by the calling uid",
        ));
    }
    let estate =
        loop_home::registry::load_registry_from_file(&mut File::from(fd)).map_err(failure)?;
    let row = estate.row(loop_name, home).map_err(failure)?;
    let registry = std::env::var_os("PERMISSION_TRIAGE_LOOP_REGISTRY").map_or_else(
        || home.join(".local/state/superloop/requests-registry"),
        PathBuf::from,
    );
    let state = state.map_or_else(
        || {
            home.join(".local/state/superloop/permission-state")
                .join(loop_name)
        },
        Path::to_path_buf,
    );
    provision(
        home,
        &source,
        &row,
        &estate.rows(home),
        &registry,
        &state,
        dry,
    )
}

fn entry_text(
    home: &Path,
    row: &loop_home::LoopRecord,
    rows: &[loop_home::LoopRecord],
    registry: &Path,
    state: &Path,
) -> Result<String, LaneError> {
    let session = row
        .session
        .as_deref()
        .ok_or_else(|| failure("estate row requires session for LOOP_SID"))?;
    if session.len() > 1024
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(failure(
            "estate session is not a valid private-registry LOOP_SID",
        ));
    }
    destination(home, registry)?;
    destination(home, state)?;
    for peer in rows {
        for path in [registry, state, &row.launch] {
            if path.starts_with(&peer.home) {
                return Err(at(
                    path,
                    format!(
                        "destination is inside estate LOOP_HOME of {} ({})",
                        peer.name,
                        peer.home.display()
                    ),
                ));
            }
        }
        if ["local/permissions/domain.md", "local/permissions/owner.md"]
            .iter()
            .any(|path| peer.launch.join(path).starts_with(state))
        {
            return Err(at(
                state,
                format!("state root contains authorization source of {}", peer.name),
            ));
        }
    }
    if registry.starts_with(state) || state.starts_with(registry) {
        return Err(at(
            state,
            format!(
                "state root and registry {} must be separate",
                registry.display()
            ),
        ));
    }
    Ok(format!(
        "LOOP_NAME={}\nLOOP_SID={}\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\nLOOP_UID={}\nLOOP_HOME={}\n",
        literal(&row.name)?,
        literal(session)?,
        literal(
            row.launch
                .to_str()
                .ok_or_else(|| failure("launch is not UTF-8"))?
        )?,
        literal(
            state
                .to_str()
                .ok_or_else(|| failure("state is not UTF-8"))?
        )?,
        row.uid,
        literal(
            row.home
                .to_str()
                .ok_or_else(|| failure("loop home is not UTF-8"))?
        )?
    ))
}

fn provision(
    home: &Path,
    source: &Path,
    row: &loop_home::LoopRecord,
    rows: &[loop_home::LoopRecord],
    registry: &Path,
    state: &Path,
    dry: bool,
) -> Result<Value, LaneError> {
    provision_with(
        home,
        source,
        row,
        rows,
        registry,
        state,
        dry,
        |home, row| super::store::Store::open_for_snapshot(home, &row.name)?.publish_snapshot(),
    )
}

#[allow(clippy::too_many_arguments)] // Mirror provision's inputs and inject only the publication boundary.
fn provision_with(
    home: &Path,
    source: &Path,
    row: &loop_home::LoopRecord,
    rows: &[loop_home::LoopRecord],
    registry: &Path,
    state: &Path,
    dry: bool,
    publish: impl FnOnce(&Path, &loop_home::LoopRecord) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let started = Instant::now();
    let text = entry_text(home, row, rows, registry, state)?;
    let pinned = PinnedHome::open(home)?;
    let registry_walk = pinned.walk(registry, dry)?;
    let parent = registry_walk.directory.as_ref();
    let _hold = parent
        .map(|fd| {
            Flock::lock(
                File::from(nix::unistd::dup(fd).map_err(|error| at(registry, error))?),
                FlockArg::LockExclusiveNonblock,
            )
            .map_err(|(_, error)| at(registry, error))
        })
        .transpose()?;
    let mut entries = Entries::read(parent, registry, pinned.owner)?;
    let existing = entries.parsed(registry, false)?;
    if let Some(entry) = existing.iter().find(|entry| entry.name == row.name)
        && entry.state_root != state
    {
        return Err(at(
            state,
            format!(
                "existing LOOP_STATE_ROOT differs; use --state-root {} to retain the journal; provisioning does not migrate it",
                entry.state_root.display()
            ),
        ));
    }
    let name = format!("{}.env", row.name);
    let record_name = format!("{}.provision.json", row.name);
    let before = entries.texts.insert(name.clone(), text.as_bytes().to_vec());
    entries.names.insert(name.as_bytes().to_vec());
    entries.names.insert(record_name.as_bytes().to_vec());
    entries.check_bounds(registry)?;
    let candidate = entries
        .parsed(registry, true)
        .map_err(|error| at(state, error.detail))?;
    for entry in candidate {
        if entry
            .home
            .as_ref()
            .is_some_and(|path| registry.starts_with(path))
        {
            return Err(at(
                registry,
                format!("registry is inside registered LOOP_HOME of {}", entry.name),
            ));
        }
    }
    // Existing entry checks above precede the only state-root walk, and hence every state create.
    let state_walk = pinned.walk(state, dry)?;
    let entry_changed = before.as_deref() != Some(text.as_bytes());
    let changed = entry_changed
        || registry_walk.created
        || registry_walk.missing
        || state_walk.created
        || state_walk.missing;
    let mut report = json!({"schema":1,"command":"requests provision-registry","loop":row.name,
        "direct_snapshot":row.home.join("policy/snapshot.json"),"direct_journal":row.home.join("direct/command-requests.jsonl"),
        "source":source,"registry":registry,"entry":registry.join(&name),"state_root":state,
        "owner_uid":pinned.owner,"dry_run":dry,"changed":changed,"entry_changed":entry_changed,
        "created_registry":registry_walk.created,"created_state":state_walk.created,
        "would_create_registry":registry_walk.missing,"would_create_state":state_walk.missing,
        "registry_identity":registry_walk.identity,"state_identity":state_walk.identity,"record":registry.join(&record_name),
        "before":before.as_ref().map(|bytes| String::from_utf8_lossy(bytes).into_owned()),"after":text});
    if dry {
        report["wall_ms"] = json!(started.elapsed().as_millis());
    } else {
        let parent = parent.ok_or_else(|| at(registry, "private registry was not created"))?;
        if entry_changed {
            super::store::replace_leaf(parent, &name, text.as_bytes(), pinned.owner, 65_536)
                .map_err(|error| at(&registry.join(&name), error.detail))?;
        }
        report["direct_policy"] = publish(home, row)
            .unwrap_or_else(|error| super::store::Store::report_snapshot_failure(&error));
        report["wall_ms"] = json!(started.elapsed().as_millis());
        super::store::replace_leaf(
            parent,
            &record_name,
            &serde_json::to_vec(&report).map_err(failure)?,
            pinned.owner,
            131_072,
        )
        .map_err(|error| at(&registry.join(&record_name), error.detail))?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    struct Fixture {
        root: tempfile::TempDir,
        rows: Vec<loop_home::LoopRecord>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir_in("/tmp").expect("tiny private records");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("home mode");
            let rows = [("alpha", 41001), ("beta", 41002)]
                .into_iter()
                .map(|(name, uid)| loop_home::LoopRecord {
                    name: name.into(),
                    uid,
                    home: root.path().join(".var/loops").join(name),
                    launch: root.path().join(format!("checkout-{name}")),
                    session: Some(format!("session-{name}")),
                    door_floor: None,
                })
                .collect();
            Self { root, rows }
        }

        fn run(
            &self,
            index: usize,
            registry: &Path,
            state: &Path,
            dry: bool,
        ) -> Result<Value, LaneError> {
            provision_with(
                self.root.path(),
                &self.root.path().join("loops.toml"),
                &self.rows[index],
                &self.rows,
                registry,
                state,
                dry,
                |_, _| Ok(json!({"published":true,"fixture":"registry custody only"})),
            )
        }
    }

    /// ´test:unit:registry-provision-retains-entry-on-snapshot-failure´
    #[test]
    fn registry_provision_retains_entry_on_snapshot_failure() {
        let fixture = Fixture::new();
        let registry = fixture.root.path().join("registry");
        let state = fixture.root.path().join("state");
        let report = provision_with(
            fixture.root.path(),
            &fixture.root.path().join("loops.toml"),
            &fixture.rows[0],
            &fixture.rows,
            &registry,
            &state,
            false,
            |_, _| {
                Err(LaneError::input(
                    "execute-command-snapshot-custody",
                    "policy tier absent",
                ))
            },
        )
        .expect("private entry must still be provisioned");
        assert!(registry.join("alpha.env").is_file());
        assert_eq!(
            report["direct_policy"]["rule"],
            "execute-command-snapshot-custody"
        );
        assert_eq!(report["direct_policy"]["published"], false);
    }

    fn refused(error: LaneError, path: &Path, detail: &str) {
        let LaneError {
            kind,
            detail: actual,
            ..
        } = error;
        assert_eq!(kind, "requests-registry-refusal");
        assert!(
            actual.contains(path.to_str().expect("fixture path")),
            "{}",
            actual
        );
        assert!(actual.contains(detail), "{}", actual);
    }

    fn identity(path: &Path) -> Value {
        let metadata = fs::metadata(path).expect("directory identity");
        json!({"st_dev":metadata.dev(),"st_ino":metadata.ino()})
    }

    /// The report measures actual creation and pinned identities; the helper skips the rewritten report.
    /// ´claim:requests:private-registry-deployment´
    /// ´test:unit:registry-provision-is-private-idempotent-and-recorded´
    #[test]
    fn registry_provision_is_private_idempotent_and_recorded() {
        let fixture = Fixture::new();
        let registry = fixture.root.path().join("registry");
        let state = fixture.root.path().join("state");
        let preview = fixture.run(0, &registry, &state, true).expect("preview");
        for key in ["created_registry", "created_state"] {
            assert_eq!(preview[key], false);
        }
        for key in ["would_create_registry", "would_create_state"] {
            assert_eq!(preview[key], true);
        }
        for key in ["registry_identity", "state_identity"] {
            assert_eq!(preview[key], Value::Null);
        }
        assert!(!registry.exists());
        assert!(!state.exists());
        let first = fixture.run(0, &registry, &state, false).expect("provision");
        assert_eq!(first["created_registry"], true);
        assert_eq!(first["created_state"], true);
        assert_eq!(first["registry_identity"], identity(&registry));
        assert_eq!(first["state_identity"], identity(&state));
        let entry = registry.join("alpha.env");
        let inode = fs::metadata(&entry).expect("entry").ino();
        let record = registry.join("alpha.provision.json");
        fs::write(&record, b"old report").expect("stale report");
        let second = fixture.run(0, &registry, &state, false).expect("repeat");
        assert_eq!(second["changed"], false);
        assert_eq!(second["created_registry"], false);
        assert_eq!(second["created_state"], false);
        assert_eq!(second["registry_identity"], first["registry_identity"]);
        assert_eq!(second["state_identity"], first["state_identity"]);
        assert_eq!(fs::metadata(&entry).expect("entry").ino(), inode);
        assert_eq!(fs::metadata(&entry).expect("entry").mode() & 0o7777, 0o600);
        assert_eq!(
            fs::metadata(&registry).expect("registry").mode() & 0o7777,
            0o700
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&record).expect("report"))
                .expect("report JSON"),
            second
        );
        let output = std::process::Command::new(super::super::store::test_helper::binary())
            .args(["--owner-read", "--loop", "alpha"])
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", &registry)
            .output()
            .expect("private dispatcher");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o755))
            .expect("nonprivate registry");
        refused(
            fixture
                .run(0, &registry, &state, false)
                .expect_err("private boundary"),
            &registry,
            "not a private directory",
        );
    }

    /// Linked destinations and nonprivate entries produce named, path-bearing refusals without writes.
    /// ´claim:requests:registry-provision-custody-boundary´
    /// ´test:unit:registry-provision-refuses-links-and-nonprivate-entry´
    #[test]
    fn registry_provision_refuses_links_and_nonprivate_entry() {
        let fixture = Fixture::new();
        let home = fixture.root.path();
        let registry = home.join("registry");
        let state = home.join("state");
        symlink(home, &registry).expect("linked registry");
        for dry in [true, false] {
            refused(
                fixture
                    .run(0, &registry, &state, dry)
                    .expect_err("link refused"),
                &registry,
                "ELOOP",
            );
            assert!(!state.exists());
        }
        fs::remove_file(&registry).expect("unlink");
        fixture.run(0, &registry, &state, false).expect("provision");
        let entry = registry.join("alpha.env");
        let before = fs::read(&entry).expect("entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).expect("nonprivate entry");
        refused(
            fixture
                .run(0, &registry, &state, false)
                .expect_err("mode refused"),
            &entry,
            "owner, mode or size differs",
        );
        assert_eq!(fs::read(&entry).expect("unchanged"), before);
        fs::remove_file(&entry).expect("remove");
        symlink(home.join("outside"), &entry).expect("linked entry");
        refused(
            fixture
                .run(0, &registry, &state, false)
                .expect_err("entry link refused"),
            &entry,
            "ELOOP",
        );
        assert!(!home.join("outside").exists());
    }

    /// Injecting the expected uid exercises the same ownership refusal without privileged chown.
    /// ´test:unit:registry-provision-refuses-foreign-owner´
    #[test]
    fn registry_provision_refuses_foreign_owner() {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("foreign");
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        let mut pinned = PinnedHome::open(fixture.root.path()).expect("pin");
        let actual = pinned.owner;
        pinned.owner = actual.wrapping_add(1);
        for dry in [true, false] {
            refused(
                pinned.walk(&path, dry).err().expect("owner refused"),
                &path,
                &format!("foreign owner: expected {}, found {actual}", pinned.owner),
            );
        }
        assert_eq!(fs::read_dir(&path).expect("unchanged directory").count(), 0);
    }

    /// Every estate home is excluded before either destination can be created, including an unprovisioned peer.
    /// ´test:unit:registry-provision-separates-all-estate-homes´
    #[test]
    fn registry_provision_separates_all_estate_homes() {
        let fixture = Fixture::new();
        let peer = &fixture.rows[1];
        fs::create_dir_all(&peer.home).expect("peer home");
        fs::set_permissions(&peer.home, fs::Permissions::from_mode(0o711))
            .expect("estate home mode");
        for dry in [true, false] {
            for registry_inside in [true, false] {
                let registry = if registry_inside {
                    peer.home.join("registry")
                } else {
                    fixture.root.path().join("registry")
                };
                let state = if registry_inside {
                    fixture.root.path().join("state")
                } else {
                    peer.home.join("state")
                };
                let bad = if registry_inside { &registry } else { &state };
                refused(
                    fixture
                        .run(0, &registry, &state, dry)
                        .expect_err("separation"),
                    bad,
                    "inside estate LOOP_HOME of beta",
                );
                assert!(!registry.exists());
                assert!(!state.exists());
            }
        }
        assert_eq!(
            fs::read_dir(&peer.home).expect("empty peer home").count(),
            0
        );
    }

    /// The helper's structure validator rejects equal, nested and enclosing state roots before state creation.
    /// ´test:unit:registry-provision-separates-existing-state-roots´
    #[test]
    fn registry_provision_separates_existing_state_roots() {
        let fixture = Fixture::new();
        let registry = fixture.root.path().join("registry");
        let peer_state = fixture.root.path().join("states/beta");
        fixture
            .run(1, &registry, &peer_state, false)
            .expect("provision peer");
        let before = fs::read(registry.join("beta.env")).expect("peer entry");
        for dry in [true, false] {
            for state in [
                peer_state.clone(),
                peer_state.join("nested"),
                fixture.root.path().join("states"),
            ] {
                refused(
                    fixture.run(0, &registry, &state, dry).expect_err("overlap"),
                    &state,
                    "overlapping state roots",
                );
                assert!(!registry.join("alpha.env").exists());
                assert!(!registry.join("alpha.provision.json").exists());
                assert!(!peer_state.join("nested").exists());
                assert_eq!(
                    fs::read(registry.join("beta.env")).expect("peer unchanged"),
                    before
                );
            }
        }
    }

    /// A later default or alternative cannot silently relocate an existing permission journal.
    /// ´test:unit:registry-provision-retains-existing-journal´
    #[test]
    fn registry_provision_retains_existing_journal() {
        let fixture = Fixture::new();
        let registry = fixture.root.path().join("registry");
        let state = fixture.root.path().join("custom-state");
        fixture
            .run(0, &registry, &state, false)
            .expect("custom journal");
        let record = fs::read(registry.join("alpha.provision.json")).expect("record");
        let other = fixture.root.path().join("default-state");
        for dry in [true, false] {
            refused(
                fixture
                    .run(0, &registry, &other, dry)
                    .expect_err("journal mismatch"),
                &other,
                &format!(
                    "existing LOOP_STATE_ROOT differs; use --state-root {}",
                    state.display()
                ),
            );
            assert!(!other.exists());
            assert_eq!(
                fs::read(registry.join("alpha.provision.json")).expect("unchanged"),
                record
            );
        }
        assert_eq!(
            fixture
                .run(0, &registry, &state, false)
                .expect("explicit existing root")["changed"],
            false
        );
    }

    /// Both walks stay attached to the single pinned home even if its pathname is replaced.
    /// ´test:unit:registry-provision-pins-home-once´
    #[test]
    fn registry_provision_pins_home_once() {
        let fixture = Fixture::new();
        let home = fixture.root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("mode");
        let pinned = PinnedHome::open(&home).expect("one home pin");
        let held = fixture.root.path().join("held-home");
        fs::rename(&home, &held).expect("replace pathname");
        fs::create_dir(&home).expect("replacement");
        for leaf in ["registry", "state"] {
            let path = home.join(leaf);
            let preview = pinned.walk(&path, true).expect("preview");
            assert!(preview.missing);
            assert!(!preview.created);
            let first = pinned.walk(&path, false).expect("create in pinned home");
            assert!(first.created);
            assert_eq!(first.identity, identity(&held.join(leaf)));
            assert!(!path.exists());
            let repeat = pinned.walk(&path, false).expect("reuse");
            assert!(!repeat.created);
            assert_eq!(repeat.identity, first.identity);
        }
    }
}
