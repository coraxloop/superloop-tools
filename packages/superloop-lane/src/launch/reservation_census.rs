//! Reservation census uses the received runs directory or one host-verified directory.
use crate::{LaneError, home};
use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{SFlag, fstatat};
use nix::unistd::Uid;
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

struct Census<'a> {
    path: &'a Path,
    root: OwnedFd,
}
impl<'a> Census<'a> {
    fn open(path: &'a Path) -> Result<Self, LaneError> {
        let root = if home::private_is_active() {
            let declared = home::private_runs_path()
                .ok_or_else(|| LaneError::input("runs-root", "received runs root is absent"))?;
            if declared != path {
                return Err(LaneError::input(
                    "runs-root",
                    "census differs from received runs root",
                ));
            }
            home::pin_parent_beneath(path, path, Uid::effective().as_raw())?
        } else {
            home::pin_parent(path, Uid::effective().as_raw())?
        };
        Ok(Self { path, root })
    }
    fn reservation(&self, name: &OsStr) -> Result<Option<Value>, LaneError> {
        let path = self.path.join(name);
        let opened = openat2(
            &self.root,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_SYMLINKS
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS,
                ),
        )
        .map(File::from)
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32));
        super::read_reservation_file(opened, &path, true).map_err(|error| {
            LaneError::input(
                "launch-reservation",
                format!("{}: {}", path.display(), error.detail),
            )
        })
    }
    fn run_reservation(&self, run: &str) -> Result<Option<Value>, LaneError> {
        self.reservation(OsStr::new(&format!(".reservation-{run}.json")))
    }
    fn mode(&self, name: &OsStr) -> Result<Option<SFlag>, LaneError> {
        match fstatat(&self.root, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(info) => Ok(Some(
                SFlag::from_bits_truncate(info.st_mode) & SFlag::S_IFMT,
            )),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(error) => Err(LaneError::input(
                "runs-root",
                format!("{}: {error}", self.path.join(name).display()),
            )),
        }
    }
    fn enumerated_mode(&self, name: &OsStr) -> Result<SFlag, LaneError> {
        self.mode(name)?.ok_or_else(|| {
            LaneError::input(
                "runs-root",
                format!("{} vanished during census", self.path.join(name).display()),
            )
        })
    }
    fn names(&self) -> Result<Vec<OsString>, LaneError> {
        let fd = openat2(
            &self.root,
            ".",
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_SYMLINKS
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS,
                ),
        )
        .map_err(|error| LaneError::input("runs-root", error.to_string()))?;
        let mut directory = nix::dir::Dir::from_fd(fd)
            .map_err(|error| LaneError::input("runs-root", error.to_string()))?;
        directory
            .iter()
            .map(|entry| {
                entry
                    .map(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_owned())
                    .map_err(|error| LaneError::input("runs-root", error.to_string()))
            })
            .collect()
    }
    fn refuse_residue(&self, run: &str) -> Result<(), LaneError> {
        let names = std::iter::once(format!(".launch-{run}"))
            .chain((1..=4).map(|attempt| format!(".container-{run}-attempt-{attempt}.id")));
        for name in names {
            if self.mode(OsStr::new(&name))?.is_some() {
                return Err(LaneError::input(
                    "already-exists",
                    format!(
                        "{} has protected launch inputs",
                        self.path.join(run).display()
                    ),
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn records(root: &Path) -> Result<Vec<(String, Value)>, LaneError> {
    let census = Census::open(root)?;
    let mut rows = Vec::new();
    for name in census.names()? {
        let text = name.to_string_lossy();
        let Some(run) = text
            .strip_prefix(".reservation-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        if !crate::valid_run_name(run) {
            return Err(LaneError::input(
                "exercise-record",
                format!("invalid reservation name {text}"),
            ));
        }
        let record = census
            .reservation(&name)?
            .ok_or_else(|| LaneError::input("exercise-record", format!("{text} vanished")))?;
        rows.push((run.to_owned(), record));
    }
    Ok(rows)
}

fn pending(record: Option<&Value>, base: u32, count: u32) -> Result<Option<u32>, LaneError> {
    let Some(record) = record.filter(|record| {
        record["phase"] == "preparing"
            || (record["phase"] == "failed" && record["pre_driver_failure"].is_string())
    }) else {
        return Ok(None);
    };
    record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .filter(|uid| *uid >= base && *uid < base + count)
        .map(Some)
        .ok_or_else(|| LaneError::input("uid-table", "pending worker UID is outside the grant"))
}
pub(super) fn select(
    root: &Path,
    run: &str,
    base: u32,
    count: u32,
    reserved: &BTreeSet<u32>,
) -> Result<(u32, Vec<String>), LaneError> {
    if !crate::valid_run_name(run) {
        return Err(LaneError::input(
            "run-name",
            "census run is not a bounded component",
        ));
    }
    let census = Census::open(root)?;
    let own = census.run_reservation(run)?;
    let pending = pending(own.as_ref(), base, count)?;
    if pending.is_none() {
        if own.is_some() || census.mode(OsStr::new(run))?.is_some() {
            return Err(LaneError::input(
                "already-exists",
                format!("{} already exists", root.join(run).display()),
            ));
        }
        census.refuse_residue(run)?;
    }
    let mut used = reserved.clone();
    let mut skipped = Vec::new();
    for name in census.names()? {
        let text = name.to_string_lossy();
        if text.starts_with(".reservation-") && text.ends_with(".json") {
            let record = census.reservation(&name)?.ok_or_else(|| {
                LaneError::input(
                    "launch-reservation",
                    "reservation disappeared during census",
                )
            })?;
            let uid = record["worker_uid"]
                .as_u64()
                .and_then(|uid| u32::try_from(uid).ok())
                .ok_or_else(|| LaneError::input("uid-table", "reservation has no worker UID"))?;
            used.insert(uid);
        } else if !text.starts_with('.') && census.enumerated_mode(&name)? == SFlag::S_IFDIR {
            let Some(record) = census.run_reservation(&text)? else {
                skipped.push(text.into_owned());
                continue;
            };
            let uid = record["worker_uid"]
                .as_u64()
                .and_then(|uid| u32::try_from(uid).ok())
                .ok_or_else(|| {
                    LaneError::input(
                        "uid-table",
                        format!("{} has no worker UID", root.join(&name).display()),
                    )
                })?;
            used.insert(uid);
        }
    }
    skipped.sort();
    pending
        .or_else(|| (base..base + count).find(|uid| !used.contains(uid)))
        .map(|uid| (uid, skipped))
        .ok_or_else(|| {
            LaneError::input(
                "uid-range",
                format!("{} has no free worker identity", root.display()),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    struct Fixture {
        _guard: home::PrivateHomeGuard,
        _root: tempfile::TempDir,
        runs: std::path::PathBuf,
        held: std::path::PathBuf,
    }
    /// # Panics
    /// Panics if the fixture cannot retain and substitute its verified directory.
    fn fixture() -> Fixture {
        let fixture = tempfile::tempdir().expect("fixture");
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        for path in [&home, &runs] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let held = fixture.path().join("held");
        let record = json!({
            "schema":1, "phase":"started", "loop":"alpha", "run":"A", "worker_uid":3000, "plan":{}
        });
        super::super::publish_reservation(&runs.join(".reservation-A.json"), &record)
            .expect("reservation");
        fs::create_dir(runs.join("orphan")).expect("unreserved driver");
        fs::create_dir(runs.join(".launch-blocked")).expect("protected residue");
        let home_fd = File::open(&home).expect("home");
        let runs_fd = File::open(&runs).expect("runs");
        let guard = home::activate_private_launch(
            &home,
            &home_fd,
            &runs,
            &runs_fd,
            None,
            Uid::effective().as_raw(),
        )
        .expect("received roots");
        fs::rename(&runs, &held).expect("retain directory");
        fs::create_dir(&runs).expect("replacement");
        fs::write(
            runs.join(".reservation-A.json"),
            b"replacement is not authority",
        )
        .expect("replacement record");
        Fixture {
            _guard: guard,
            _root: fixture,
            runs,
            held,
        }
    }

    /// # Panics
    /// Panics if the received root stops determining the census after pathname replacement.
    /// ´claim:superlooplane:reservation-census-stays-beneath-received-root´
    /// ´test:unit:reservation-census-stays-beneath-received-root´
    #[test]
    fn reservation_census_stays_beneath_received_root() {
        let fixture = fixture();
        let runs = &fixture.runs;
        let held = &fixture.held;
        assert_eq!(records(runs).expect("held records")[0].0, "A");
        let census = Census::open(runs).expect("received census");
        fs::write(held.join("vanishing"), "entry").expect("entry");
        let enumerated = census.names().expect("enumeration");
        assert!(enumerated.iter().any(|name| name == "vanishing"));
        fs::remove_file(held.join("vanishing")).expect("remove entry after enumeration");
        assert_eq!(
            census
                .enumerated_mode(OsStr::new("vanishing"))
                .expect_err("vanished entry refuses")
                .kind,
            "runs-root"
        );

        assert_eq!(
            select(runs, "../escape", 3000, 3, &BTreeSet::new())
                .expect_err("path escape")
                .kind,
            "run-name"
        );
        assert_eq!(
            select(runs, "next", 3000, 3, &BTreeSet::new()).expect("held census"),
            (3001, vec!["orphan".into()])
        );
        assert_eq!(
            select(runs, "blocked", 3000, 3, &BTreeSet::new())
                .expect_err("held residue")
                .kind,
            "already-exists"
        );
        assert_eq!(
            select(held, "next", 3000, 3, &BTreeSet::new())
                .expect_err("undeclared root")
                .kind,
            "runs-root"
        );
        symlink(
            runs.join(".reservation-A.json"),
            held.join(".reservation-link.json"),
        )
        .expect("linked record");
        assert_eq!(
            select(runs, "next", 3000, 3, &BTreeSet::new())
                .expect_err("link")
                .kind,
            "launch-reservation"
        );
        fs::remove_file(held.join(".reservation-link.json")).expect("remove link");
        fs::write(held.join(".reservation-A.json"), b"malformed").expect("malformed held record");
        assert_eq!(
            select(runs, "next", 3000, 3, &BTreeSet::new())
                .expect_err("malformed")
                .kind,
            "launch-reservation"
        );
        fs::set_permissions(held, fs::Permissions::from_mode(0o770)).expect("widen held root");
        assert_eq!(
            select(runs, "next", 3000, 3, &BTreeSet::new())
                .expect_err("widened root")
                .kind,
            "unsafe-path"
        );
    }
}
