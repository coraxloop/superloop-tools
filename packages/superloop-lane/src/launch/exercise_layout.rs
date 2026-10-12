//! Measure home write boundaries with a worker process in the bound private namespace.

use super::*;
use crate::home;
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{Gid, UnlinkatFlags, unlinkat};
use std::io::stdin;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Command, Stdio};

pub(super) const CANARY: &str = ".superloop-home-layout-canary";

fn refusal(error: Errno) -> Value {
    json!({"state":"refused","errno":format!("{error:?}"),"created":false,"removed":false,"residue":false})
}

fn canary(anchor: &impl AsFd, relative: &str, worker: u32) -> Result<Value, LaneError> {
    let mut directory = nix::unistd::dup(anchor.as_fd())
        .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
    if relative.is_empty() {
        return Err(LaneError::input(
            "exercise-layout-canary",
            "directory is empty",
        ));
    }
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LaneError::input(
                "exercise-layout-canary",
                "directory is not relative",
            ));
        };
        directory = match openat2(
            &directory,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(error) => return Ok(refusal(error)),
        };
        let stat = fstat(&directory)
            .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Ok(
                json!({"state":"invalid-directory","errno":null,"created":false,"removed":false,"residue":false}),
            );
        }
    }
    let created = match openat2(
        &directory,
        CANARY,
        OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(error) => return Ok(refusal(error)),
    };
    let stat = fstat(&created);
    let owned = stat.as_ref().is_ok_and(|stat| {
        stat.st_uid == worker
            && SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG
    });
    drop(created);
    if let Err(error) = unlinkat(&directory, CANARY, UnlinkatFlags::NoRemoveDir) {
        return Ok(
            json!({"state":"cleanup-refused","errno":format!("{error:?}"),"created":true,"removed":false,"residue":true}),
        );
    }
    let absent = matches!(
        openat2(
            &directory,
            CANARY,
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ),
        Err(Errno::ENOENT)
    );
    Ok(
        json!({"state":if owned && absent {"created-removed"} else {"cleanup-unverified"},"errno":stat.err().map(|error| format!("{error:?}")),"created":true,"removed":absent,"residue":!absent}),
    )
}

/// Attempt one reserved file creation and removal under the inherited directory.
///
/// # Errors
///
/// Refuses a changed worker identity or an invalid relative directory.
pub fn worker_canary(relative: &str, worker: u32, loop_uid: u32) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() || worker == 0 || worker == loop_uid {
        return Err(LaneError::input(
            "exercise-layout-canary",
            "rootless owner and distinct worker are required",
        ));
    }
    nix::unistd::setgroups(&[Gid::from_raw(loop_uid)])
        .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
    nix::unistd::setgid(Gid::from_raw(worker))
        .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
    nix::unistd::setuid(Uid::from_raw(worker))
        .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
    if Uid::effective().as_raw() != worker || Gid::effective().as_raw() != worker {
        return Err(LaneError::input(
            "exercise-layout-canary",
            "worker identity differs",
        ));
    }
    canary(&stdin(), relative, worker)
}

fn probe_reserved(anchor: &OwnedFd, relative: &str, worker: u32) -> (Option<OwnedFd>, Value) {
    let name = format!("{relative}/{CANARY}");
    let mut directory = match nix::unistd::dup(anchor) {
        Ok(fd) => fd,
        Err(error) => {
            return (
                None,
                json!({"name":name,"present":null,"valid":false,"reason":format!("duplicate: {error}")}),
            );
        }
    };
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(part) = component else {
            return (
                None,
                json!({"name":name,"present":null,"valid":false,"reason":"non-normal directory"}),
            );
        };
        directory = match openat2(
            &directory,
            part,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                return (
                    None,
                    json!({"name":name,"present":false,"valid":true,"reason":"directory absent"}),
                );
            }
            Err(error) => {
                return (
                    None,
                    json!({"name":name,"present":null,"valid":false,"reason":format!("directory: {error:?}")}),
                );
            }
        };
    }
    let file = match openat2(
        &directory,
        CANARY,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            return (
                Some(directory),
                json!({"name":name,"present":false,"valid":true,"reason":"name absent"}),
            );
        }
        Err(error) => {
            return (
                Some(directory),
                json!({"name":name,"present":null,"valid":false,"reason":format!("name: {error:?}")}),
            );
        }
    };
    let stat = match fstat(&file) {
        Ok(stat) => stat,
        Err(error) => {
            return (
                Some(directory),
                json!({"name":name,"present":null,"valid":false,"reason":format!("stat: {error:?}")}),
            );
        }
    };
    let valid = stat.st_uid == worker
        && SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
    (
        Some(directory),
        json!({"name":name,"present":true,"valid":valid,"reason":if valid {"worker regular file"} else {"name is not a worker regular file"}}),
    )
}

fn recover_reserved(anchor: &OwnedFd, relative: &str, worker: u32) -> Value {
    let (directory, probe) = probe_reserved(anchor, relative, worker);
    if probe["present"] == false {
        return json!({"name":probe["name"],"state":"absent","residue":false,"reason":probe["reason"]});
    }
    if probe["present"] != true || probe["valid"] != true {
        return json!({"name":probe["name"],"state":"refused","residue":probe["present"],"reason":probe["reason"]});
    }
    let Some(directory) = directory else {
        return json!({"name":probe["name"],"state":"refused","residue":null,"reason":"directory descriptor is absent"});
    };
    if let Err(error) = unlinkat(&directory, CANARY, UnlinkatFlags::NoRemoveDir) {
        return json!({"name":probe["name"],"state":"refused","residue":true,"reason":format!("unlink: {error:?}")});
    }
    match openat2(
        &directory,
        CANARY,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Err(Errno::ENOENT) => {
            json!({"name":probe["name"],"state":"removed","residue":false,"reason":"reserved worker file removed through held directory"})
        }
        Ok(_) => {
            json!({"name":probe["name"],"state":"refused","residue":true,"reason":"name remains after unlink"})
        }
        Err(error) => {
            json!({"name":probe["name"],"state":"refused","residue":null,"reason":format!("verify: {error:?}")})
        }
    }
}

fn failure_observation(mut result: Value, anchor: &OwnedFd, relative: &str, worker: u32) -> Value {
    let (_, probe) = probe_reserved(anchor, relative, worker);
    if let Some(fields) = result.as_object_mut() {
        fields.entry("created").or_insert(Value::Null);
        fields.entry("removed").or_insert(json!(false));
        fields.insert(String::from("residue"), probe["present"].clone());
        fields.insert(String::from("residue_name"), probe["name"].clone());
        fields.insert(String::from("residue_probe"), probe["reason"].clone());
    }
    result
}

fn child_canary(
    exe: &Path,
    anchor: &OwnedFd,
    relative: &str,
    worker: u32,
    loop_uid: u32,
) -> (Value, Value) {
    let recovery = recover_reserved(anchor, relative, worker);
    if recovery["state"] == "refused" {
        return (
            failure_observation(
                json!({"state":"recovery-refused","reason":"reserved canary recovery refused"}),
                anchor,
                relative,
                worker,
            ),
            recovery,
        );
    }
    let passed = match nix::unistd::dup(anchor) {
        Ok(fd) => fd,
        Err(error) => {
            return (
                failure_observation(
                    json!({"state":"launch-refused","reason":error.to_string()}),
                    anchor,
                    relative,
                    worker,
                ),
                recovery,
            );
        }
    };
    let output = Command::new(exe)
        .arg("_exercise-layout-canary")
        .arg(relative)
        .arg(worker.to_string())
        .arg(loop_uid.to_string())
        .stdin(Stdio::from(passed))
        .output();
    let observation = match output {
        Ok(output) if output.status.success() => serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| json!({"state":"report-invalid"})),
        Ok(output) => json!({"state":"worker-refused","status":output.status.code()}),
        Err(error) => json!({"state":"launch-refused","reason":error.to_string()}),
    };
    let observation = if observation.is_object() {
        observation
    } else {
        json!({"state":"report-invalid"})
    };
    let observation = if matches!(
        observation["state"].as_str(),
        Some("refused" | "created-removed")
    ) {
        observation
    } else {
        failure_observation(observation, anchor, relative, worker)
    };
    (observation, recovery)
}

fn names_claim(home_fd: &OwnedFd) -> Value {
    let expected_home = [".cache", ".codex", ".gitconfig", ".local", ".ssh"];
    let expected_local = [
        "bin", "door", "inbox", "libexec", "outbox", "sources", "vendor",
    ];
    let home_names = match checkpoint::directory_names(home_fd, Path::new(".")) {
        Ok(names) => names,
        Err(error) => return json!({"verdict":"fail","reason":error.line()}),
    };
    let local = match openat2(
        home_fd,
        ".local",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(error) => {
            return json!({"verdict":"fail","reason":format!("local directory refused: {error}")});
        }
    };
    let local_names = match checkpoint::directory_names(&local, Path::new(".local")) {
        Ok(names) => names,
        Err(error) => return json!({"verdict":"fail","reason":error.line()}),
    };
    let extras: Vec<_> = home_names
        .iter()
        .filter(|name| !expected_home.contains(&name.as_str()))
        .map(ToString::to_string)
        .chain(
            local_names
                .iter()
                .filter(|name| !expected_local.contains(&name.as_str()))
                .map(|name| format!(".local/{name}")),
        )
        .collect();
    json!({"verdict":if extras.is_empty() {"pass"} else {"fail"},"reason":if extras.is_empty() {"only planned top-level areas are present"} else {"unplanned home area is present"},"extra_paths":extras,"method":"names-only; no credential or session bytes opened"})
}

fn require_record_identity(actual: &str, expected: &str) -> Result<(), LaneError> {
    if actual != expected {
        return Err(LaneError::input(
            "exercise-home-layout-record",
            "private reservation identity differs from the public read",
        ));
    }
    Ok(())
}

/// Measure worker writes in the existing private namespace through held directories.
///
/// # Errors
///
/// Refuses an unbound namespace or a malformed reservation.
pub fn private_measure(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    expected_record: &str,
) -> Result<Value, LaneError> {
    if !home::private_is_active() || !Uid::effective().is_root() {
        return Err(LaneError::input(
            "exercise-home-layout",
            "bound private namespace is absent",
        ));
    }
    private_measure_body(owner_home, loop_name, run, expected_record, 0)
}

pub fn private_measure_body(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    expected_record: &str,
    namespace_owner: u32,
) -> Result<Value, LaneError> {
    let (plan, settings) = crate::load_plan_for_record(
        owner_home,
        loop_name,
        run,
        (namespace_owner, namespace_owner),
    )?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "runs root is absent"))?;
    let runs = home::pin_parent(root, namespace_owner)?;
    let (record, actual_record) = checkout::read_record_bound(&runs, run, namespace_owner)?;
    require_record_identity(&actual_record, expected_record)?;
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "exercise-home-layout",
            "run identity differs",
        ));
    }
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "rounds are absent"))?;
    if rounds.is_empty() || rounds.iter().any(|round| round["phase"] != "settled") {
        return Ok(json!({"state":"unmeasured","reason":"run is not settled"}));
    }
    let Some(lane_home) = cases::home_descriptor(&plan.home)? else {
        return Ok(json!({"state":"unmeasured","reason":"home was collected"}));
    };
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("exercise-home-layout", "worker UID is absent"))?;
    let loop_uid = super::recorded_loop_uid(&record)?;
    if worker == 0 || worker == loop_uid {
        return Err(LaneError::input(
            "exercise-home-layout",
            "worker and owner identities overlap",
        ));
    }
    let owner = home::pin_parent(owner_home, namespace_owner)?;
    // The running executable's kernel handle stays bound across the worker exec.
    let exe = Path::new("/proc/self/exe");
    let protected = [
        ("fixed-input", &lane_home, ".local/inbox"),
        ("routing", &lane_home, ".ssh"),
        (
            "sign-in-source",
            &owner,
            &format!(".config/loops/{loop_name}/lanes/codex"),
        ),
        ("preserved", &runs, &format!("{run}/preserved")),
    ];
    let protected: Vec<_> = protected.iter().map(|(name, fd, relative)| {
        let (observation, recovery) = child_canary(exe, fd, relative, worker, loop_uid);
        json!({"area":name,"observation":observation,"recovery":recovery,"verdict":if matches!(recovery["state"].as_str(), Some("absent" | "removed")) && observation["state"] == "refused" && matches!(observation["errno"].as_str(), Some("EACCES" | "EPERM" | "EROFS")) {"pass"} else {"fail"}})
    }).collect();
    let writable: Vec<_> = [("scratch", ".cache/work"), ("outbox", ".local/outbox")]
        .iter().map(|(name, relative)| {
            let (observation, recovery) = child_canary(exe, &lane_home, relative, worker, loop_uid);
            json!({"area":name,"observation":observation,"recovery":recovery,"verdict":if matches!(recovery["state"].as_str(), Some("absent" | "removed")) && observation["state"] == "created-removed" && observation["residue"] == false {"pass"} else {"fail"}})
        }).collect();
    let path_metadata = cases::private_path_metadata(&record, &plan, &lane_home)?;
    Ok(
        json!({"state":"measured","worker_uid":worker,"protected":protected,"writable":writable,"no_copy":names_claim(&lane_home),"path_frame":"private-namespace","path_metadata":path_metadata}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// ´test:unit:interrupted-child-canary-is-observed-and-recovered-next-call´
    #[test]
    fn interrupted_child_canary_is_observed_and_recovered_next_call() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::create_dir_all(fixture.path().join(".cache/work")).expect("scratch");
        let home: OwnedFd = fs::File::open(fixture.path()).expect("held home").into();
        let scratch = openat2(
            &home,
            ".cache/work",
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .expect("held scratch");
        let worker = Uid::effective().as_raw();
        let owner = worker.checked_add(1).expect("distinct owner");
        assert_ne!(owner, worker);
        let created = openat2(
            &scratch,
            CANARY,
            OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                )
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .expect("interrupted child creation");
        drop(created);
        let failure = failure_observation(
            json!({"state":"worker-refused","status":null}),
            &home,
            ".cache/work",
            worker,
        );
        assert_eq!(failure["residue"], true);
        assert_eq!(failure["residue_name"], format!(".cache/work/{CANARY}"));
        let (later, recovery) = child_canary(
            Path::new("/usr/bin/false"),
            &home,
            ".cache/work",
            worker,
            owner,
        );
        assert_eq!(recovery["state"], "removed");
        assert_eq!(recovery["name"], format!(".cache/work/{CANARY}"));
        assert_eq!(later["state"], "worker-refused");
        assert_eq!(later["residue"], false);
        assert!(!fixture.path().join(".cache/work").join(CANARY).exists());
    }

    /// ´test:unit:private-layout-refuses-replaced-reservation-identity´
    #[test]
    fn private_layout_refuses_replaced_reservation_identity() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root: OwnedFd = fs::File::open(fixture.path()).expect("root").into();
        let owner = Uid::effective().as_raw();
        let mut record = json!({"schema":1,"worker_uid":3000,"loop":"alpha","run":"R"});
        checkout::publish_record(&root, "R", &record, &"a".repeat(32)).expect("first record");
        let (_, first) = checkout::read_record_bound(&root, "R", owner).expect("first identity");
        record["generation"] = json!(2);
        checkout::publish_record(&root, "R", &record, &"b".repeat(32)).expect("replacement");
        let (_, second) = checkout::read_record_bound(&root, "R", owner).expect("second identity");
        require_record_identity(&first, &first).expect("same record");
        assert_eq!(
            require_record_identity(&second, &first)
                .expect_err("replaced record")
                .kind,
            "exercise-home-layout-record"
        );
    }

    /// ´test:unit:settled-worker-canaries-refuse-protected-and-clean-writable´
    #[test]
    fn settled_worker_canaries_refuse_protected_and_clean_writable() {
        let fixture = tempfile::tempdir().expect("fixture");
        let home_path = fixture.path().join("lane-alpha-R");
        for relative in [
            ".ssh",
            ".codex",
            ".cache/work",
            ".local/inbox",
            ".local/outbox",
            ".local/bin",
            ".local/door",
            ".local/libexec",
            ".local/sources",
            ".local/vendor",
        ] {
            fs::create_dir_all(home_path.join(relative)).expect("fixture directory");
        }
        fs::write(home_path.join(".gitconfig"), b"").expect("fixture Git config");
        fs::set_permissions(
            home_path.join(".local/inbox"),
            fs::Permissions::from_mode(0o500),
        )
        .expect("protected mode");
        let home = fs::File::open(&home_path).expect("held home");
        let worker = Uid::effective().as_raw();
        let owner = worker.checked_add(1).expect("distinct owner");
        assert_ne!(owner, worker);
        if worker != 0 {
            let protected = canary(&home, ".local/inbox", worker).expect("protected canary");
            assert_eq!(protected["state"], "refused");
            assert_eq!(protected["errno"], "EACCES");
        }
        for directory in [".cache/work", ".local/outbox"] {
            let writable = canary(&home, directory, worker).expect("writable canary");
            assert_eq!(writable["state"], "created-removed");
            assert_eq!(writable["residue"], false);
            assert!(!home_path.join(directory).join(CANARY).exists());
        }
        assert_eq!(
            names_claim(&nix::unistd::dup(&home).expect("held duplicate"))["verdict"],
            "pass"
        );
        fs::create_dir(home_path.join(".local/sessions")).expect("unplanned session area");
        assert_eq!(
            names_claim(&nix::unistd::dup(&home).expect("held duplicate"))["verdict"],
            "fail"
        );
    }
}
