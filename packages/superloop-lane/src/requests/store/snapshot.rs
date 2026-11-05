//! Publication into the owner-held, loop-group-readable policy tier.

use super::*;
use execute_command::snapshot::{PolicySnapshot, Source};
use nix::sys::stat::fchmod;

impl Store {
    pub(crate) fn report_snapshot_failure(error: &LaneError) -> Value {
        let report = json!({"published":false,"rule":error.kind,"detail":error.detail});
        let _diagnostic = writeln!(
            std::io::stderr().lock(),
            "direct-policy-publication {report}"
        );
        report
    }
    fn policy_directory(
        &self,
        required: bool,
        publishing: bool,
    ) -> Result<Option<OwnedFd>, LaneError> {
        if !required
            && std::fs::symlink_metadata(&self.loop_root)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        let root = crate::home::pin_parent(&self.loop_root, self.owner)?;
        let directory = match open_child(&root, "policy", OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0) {
            Ok(fd) => fd,
            Err(error) => {
                // Before ensure installs the new tier, no direct reader can act.
                if !required
                    && matches!(
                        nix::sys::stat::fstatat(
                            &root,
                            "policy",
                            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW
                        ),
                        Err(Errno::ENOENT)
                    )
                {
                    return Ok(None);
                }
                return Err(problem("execute-command-snapshot-custody", error.detail));
            }
        };
        let stat = fstat(&directory)
            .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        if stat.st_uid != self.owner || stat.st_mode & 0o022 != 0 {
            return Err(problem(
                "execute-command-snapshot-custody",
                "policy directory is not held exclusively by the owner",
            ));
        }
        if publishing
            && (stat.st_gid != self.observed_loop_identity(&root)?.1
                || stat.st_mode & 0o7777 != 0o2750)
        {
            return Err(problem(
                "execute-command-snapshot-custody",
                "run loop-home ensure for the owner-held loop-group policy tier",
            ));
        }
        Ok(Some(directory))
    }

    fn observed_loop_identity(&self, root: &OwnedFd) -> Result<(u32, u32), LaneError> {
        let refusal = |detail: String| problem("execute-command-snapshot-custody", detail);
        if self.owner != nix::unistd::geteuid().as_raw() {
            return Err(refusal(
                "snapshot writer differs from the effective owner".into(),
            ));
        }
        let mut identity = None;
        for name in ["shared", "private", "direct"] {
            let fd = nix::fcntl::openat2(
                root,
                name,
                nix::fcntl::OpenHow::new()
                    .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                    .resolve(
                        nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS
                            | nix::fcntl::ResolveFlag::RESOLVE_BENEATH,
                    ),
            )
            .map_err(|error| refusal(error.to_string()))?;
            let stat = fstat(&fd).map_err(|error| refusal(error.to_string()))?;
            let current = (stat.st_uid, stat.st_gid);
            if stat.st_uid == self.owner
                || stat.st_mode & 0o022 != 0
                || identity.is_some_and(|expected| expected != current)
                || name != "shared" && stat.st_mode & 0o7707 != 0o700
            {
                return Err(refusal("shared, private and direct must have the same independent loop owner and group".into()));
            }
            identity = Some(current);
        }
        identity.ok_or_else(|| refusal("loop identity tiers are absent".into()))
    }

    pub(super) fn invalidate_snapshot(&self) -> Result<(), LaneError> {
        if let Some(directory) = self.policy_directory(false, false)? {
            match unlinkat(&directory, "snapshot.json", UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(error) => {
                    return Err(problem(
                        "execute-command-snapshot-custody",
                        error.to_string(),
                    ));
                }
            }
            File::from(directory)
                .sync_all()
                .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn withdraw_snapshot_for_write(&self) {
        if let Err(error) = self.invalidate_snapshot() {
            Self::report_snapshot_failure(&error);
        }
    }

    pub(super) fn publish_after_write(&self) -> Value {
        match self.publish_snapshot_locked(true) {
            Ok(report) => report,
            Err(error) => {
                // Also withdraw a rename that succeeded before a directory-sync failure.
                self.withdraw_snapshot_for_write();
                Self::report_snapshot_failure(&error)
            }
        }
    }

    /// Publish policy while holding the same exclusive lock as its source writers.
    ///
    /// # Errors
    /// Refuses unsafe tiers, unreadable sources or incomplete publication.
    pub fn publish_snapshot(&self) -> Result<Value, LaneError> {
        let _lock = self.lock(true)?;
        self.invalidate_snapshot()?;
        self.publish_snapshot_locked(true)
            .inspect_err(|_| self.withdraw_snapshot_for_write())
    }

    fn snapshot_rubric(&self, configuration: Option<Vec<u8>>) -> Result<Value, LaneError> {
        match configuration {
            None => Ok(json!({"path":null,"sha256":null,"text":null,"agent":null})),
            Some(bytes) => {
                let table = crate::door::config::parse(&bytes)?;
                let root = table["rubric_root"]
                    .as_str()
                    .ok_or_else(|| problem("door-rubric-unavailable", "rubric_root is absent"))?;
                let path = Path::new(root).join("permissions/door.md");
                let root_fd = crate::home::pin_parent(&self.loop_root, self.owner)?;
                let (loop_uid, group) = self.observed_loop_identity(&root_fd)?;
                let fd = rubric_file(&path, self.owner, loop_uid)?;
                let stat = fstat(&fd)
                    .map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
                if ![0, self.owner, loop_uid].contains(&stat.st_uid)
                    || stat.st_mode & 0o022 != 0
                    || SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
                {
                    return Err(problem(
                        "door-rubric-unavailable",
                        "published rubric custody differs",
                    ));
                }
                let mut text = String::new();
                File::from(fd)
                    .take(65_537)
                    .read_to_string(&mut text)
                    .map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
                if text.len() > 65_536 || text.trim().is_empty() {
                    return Err(problem("door-rubric-unavailable", "rubric exceeds bound"));
                }
                let readable = loop_readable(&path, loop_uid, group);
                Ok(
                    json!({"path":path,"sha256":execute_command::rubric::sha256_digest(text.as_bytes()),"text":if readable {None} else {Some(text)},"agent":table}),
                )
            }
        }
    }

    pub(super) fn publish_snapshot_locked(&self, required: bool) -> Result<Value, LaneError> {
        let Some(directory) = self.policy_directory(required, true)? else {
            return Ok(json!({"published":false,"reason":"policy tier is not provisioned"}));
        };
        let current = self.current_snapshot_store()?;
        let source = |revision: String, value: Value| {
            Source::new(revision, value).map_err(super::super::command::shape)
        };
        let ledger = self.read_modes()?;
        let modes = ledger.value();
        let mut effective = serde_json::Map::new();
        for class in modes["classes"].as_array().into_iter().flatten() {
            let name = class["class"]
                .as_str()
                .ok_or_else(|| problem("door-mode-record-refusal", "class absent"))?;
            if ledger.current(&ModeTarget::Loop).is_some() {
                effective.insert(name.to_owned(), current.effective_locked(&ledger, name)?);
            }
        }
        let configuration = read_leaf(self.state_dir(), "door.toml", self.owner, 65_536)?;
        let door = read_leaf(
            self.state_dir(),
            "door-install-generation.json",
            self.owner,
            65_536,
        )?
        .is_some();
        let rubric = self.snapshot_rubric(configuration)?;
        let learned = if door {
            self.read_learned()?
        } else {
            json!({"schema":1,"groups":{},"absent_door":true})
        };
        let stamp = now_nanos().to_string();
        let snapshot = PolicySnapshot {
            schema: 1,
            loop_name: self.loop_name.clone(),
            loop_uid: self.loop_uid,
            written_at: stamp.clone(),
            door,
            registry: source(
                current.registry_digest.clone(),
                json!({"floor":current.floor.as_str(),"root":self.loop_root}),
            )?,
            modes: source(
                modes["revision"].to_string(),
                json!({"ledger":modes,"effective":effective}),
            )?,
            learned: source(
                execute_command::rubric::sha256_digest(
                    &serde_json::to_vec(&learned)
                        .map_err(|error| problem("requests-learned-index", error.to_string()))?,
                ),
                learned,
            )?,
            rubric: source(
                rubric["sha256"].as_str().unwrap_or("absent").to_owned(),
                rubric,
            )?,
        };
        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|error| problem("execute-command-record-shape", error.to_string()))?;
        let temporary = format!(
            ".snapshot.{}.{}.tmp",
            std::process::id(),
            STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let fd = open_child(
            &directory,
            &temporary,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            0o640,
        )?;
        fchmod(&fd, FileMode::from_bits_truncate(0o640))
            .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        let mut file = File::from(fd);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        nix::fcntl::renameat(&directory, temporary.as_str(), &directory, "snapshot.json")
            .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        File::from(directory)
            .sync_all()
            .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))?;
        Ok(
            json!({"published":true,"path":self.loop_root.join("policy/snapshot.json"),"sha256":execute_command::rubric::sha256_digest(&bytes),"written_at":stamp}),
        )
    }

    fn current_snapshot_store(&self) -> Result<Self, LaneError> {
        let owner_home = self.loop_root.ancestors().nth(3).ok_or_else(|| {
            problem(
                "execute-command-snapshot-custody",
                "registered loop root is incomplete",
            )
        })?;
        let current = Self::open_for_snapshot(owner_home, &self.loop_name)?;
        let identity = |store: &Self| {
            fstat(store.state_dir())
                .map(|stat| (stat.st_dev, stat.st_ino))
                .map_err(|error| problem("execute-command-snapshot-custody", error.to_string()))
        };
        if current.loop_uid != self.loop_uid
            || current.loop_root != self.loop_root
            || identity(&current)? != identity(self)?
        {
            return Err(problem(
                "execute-command-snapshot-identity",
                "registry custody changed while the store was open",
            ));
        }
        Ok(current)
    }
}

fn rubric_file(path: &Path, owner: u32, loop_uid: u32) -> Result<OwnedFd, LaneError> {
    let mut parent = nix::fcntl::open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        FileMode::empty(),
    )
    .map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
    let relative = path
        .strip_prefix("/")
        .map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(problem(
                "door-rubric-unavailable",
                "rubric path is not normal",
            ));
        };
        let last = components.peek().is_none();
        let fd = nix::fcntl::openat2(
            &parent,
            Path::new(name),
            nix::fcntl::OpenHow::new()
                .flags(if last {
                    OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
                } else {
                    OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC
                })
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
        .map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
        if last {
            return Ok(fd);
        }
        let stat =
            fstat(&fd).map_err(|error| problem("door-rubric-unavailable", error.to_string()))?;
        let sticky_root = [0, 65534].contains(&stat.st_uid) && stat.st_mode & 0o1777 == 0o1777;
        if ![0, 65534, owner, loop_uid].contains(&stat.st_uid)
            || stat.st_mode & 0o022 != 0 && !sticky_root
        {
            return Err(problem(
                "door-rubric-unavailable",
                "published rubric ancestor is replaceable",
            ));
        }
        parent = fd;
    }
    Err(problem("door-rubric-unavailable", "rubric file is absent"))
}

fn loop_readable(path: &Path, uid: u32, gid: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    path.ancestors().all(|component| {
        std::fs::symlink_metadata(component).is_ok_and(|metadata| {
            let bits = if metadata.uid() == uid {
                metadata.mode() >> 6
            } else if metadata.gid() == gid {
                metadata.mode() >> 3
            } else {
                metadata.mode()
            };
            !metadata.file_type().is_symlink()
                && if component == path {
                    bits & 4 != 0
                } else {
                    metadata.is_dir() && bits & 1 != 0
                }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;

    fn fixture() -> (super::super::tests::Fixture, Store) {
        let fixture = super::super::tests::Fixture::new();
        let store = fixture.snapshot_store();
        (fixture, store)
    }

    /// ´test:unit:direct-policy-writer-compares-policy-group-with-observed-loop-tiers´
    #[test]
    fn direct_policy_writer_compares_policy_group_with_observed_loop_tiers() {
        let (_fixture, store) = fixture();
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_none() {
            assert_eq!(
                store
                    .publish_snapshot()
                    .expect_err("independent tiers required")
                    .kind,
                "execute-command-snapshot-custody"
            );
            return;
        }
        store.publish_snapshot().expect("observed loop group");
        let policy = store.loop_root.join("policy");
        let group = fs::metadata(store.loop_root.join("shared"))
            .expect("loop group")
            .gid();
        let wrong_group = nix::unistd::getegid();
        assert_ne!(wrong_group.as_raw(), group);
        nix::unistd::chown(&policy, None, Some(wrong_group)).expect("owner group twin");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o2750)).expect("twin mode");
        assert_eq!(
            store
                .publish_snapshot()
                .expect_err("owner group is not the loop group")
                .kind,
            "execute-command-snapshot-custody"
        );
        nix::unistd::chown(&policy, None, Some(nix::unistd::Gid::from_raw(group)))
            .expect("restore loop group");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o2750)).expect("restored mode");
        store.publish_snapshot().expect("restored observed group");
    }

    /// ´test:unit:direct-policy-publication-preserves-floor-derived-absence-and-mode-revisions´
    #[test]
    fn direct_policy_publication_preserves_floor_derived_absence_and_mode_revisions() {
        let (_fixture, store) = fixture();
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_none() {
            assert_eq!(
                store
                    .publish_snapshot()
                    .expect_err("independent loop tiers required")
                    .kind,
                "execute-command-snapshot-custody"
            );
            return;
        }
        let published = store.publish_snapshot().expect("publish absent settings");
        let path = store.loop_root.join("policy/snapshot.json");
        let first = PolicySnapshot::decode(&fs::read(&path).expect("snapshot")).expect("shape");
        assert_eq!(first.modes.value["ledger"]["revision"], 0);
        assert_eq!(first.registry.value["floor"], "audit");
        assert!(!first.door);
        assert_eq!(first.learned.value["groups"], json!({}));
        assert_eq!(
            fs::metadata(&path).expect("metadata").mode() & 0o7777,
            0o640
        );
        assert_eq!(
            fs::metadata(&path).expect("metadata").gid(),
            fs::metadata(store.loop_root.join("shared"))
                .expect("loop group")
                .gid()
        );
        assert!(store.loop_root.join("direct").is_dir());
        store.ensure_first_mode("compute").expect("first settings");
        let second =
            PolicySnapshot::decode(&fs::read(&path).expect("updated snapshot")).expect("shape");
        assert_eq!(second.modes.value["ledger"]["revision"], 2);
        assert_ne!(first.modes.sha256, second.modes.sha256);
        assert_eq!(second.modes.value["effective"]["compute"]["mode"], "audit");
        assert_ne!(
            published["sha256"],
            execute_command::rubric::sha256_digest(&fs::read(&path).expect("bytes"))
        );
    }

    /// ´test:unit:direct-policy-publication-failure-withdraws-stale-policy´
    #[test]
    fn direct_policy_publication_failure_withdraws_stale_policy() {
        let (_fixture, store) = fixture();
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_none() {
            assert_eq!(
                store
                    .publish_snapshot()
                    .expect_err("independent loop tiers required")
                    .kind,
                "execute-command-snapshot-custody"
            );
            return;
        }
        store.publish_snapshot().expect("initial snapshot");
        replace_leaf(
            store.state_dir(),
            "door.toml",
            b"not valid toml",
            store.owner,
            65_536,
        )
        .expect("changed source");
        assert!(store.publish_snapshot().is_err());
        assert!(!store.loop_root.join("policy/snapshot.json").exists());
    }

    /// ´test:unit:direct-policy-publication-refreshes-a-long-lived-stores-registry-floor´
    #[test]
    fn direct_policy_publication_refreshes_a_long_lived_stores_registry_floor() {
        let (fixture, store) = fixture();
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_none() {
            assert_eq!(
                store
                    .publish_snapshot()
                    .expect_err("independent loop tiers required")
                    .kind,
                "execute-command-snapshot-custody"
            );
            return;
        }
        store.publish_snapshot().expect("initial policy");
        let path = store.loop_root.join("policy/snapshot.json");
        let first = PolicySnapshot::decode(&fs::read(&path).expect("snapshot")).expect("shape");
        let registry = fixture.home.join(".config/loops/registry.toml");
        let source = fs::read_to_string(&registry).expect("registry");
        fs::write(
            &registry,
            source.replace(
                "name = \"alpha\"",
                "name = \"alpha\", door_floor = \"enforce\"",
            ),
        )
        .expect("owner changes floor");
        store
            .publish_snapshot()
            .expect("long-lived store republishes");
        let next = PolicySnapshot::decode(&fs::read(&path).expect("snapshot")).expect("shape");
        assert_eq!(next.registry.value["floor"], "enforce");
        assert_ne!(first.registry.revision, next.registry.revision);
    }
}
