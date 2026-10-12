//! Explicit, digest-bound evidence for historical absences at retirement.

use super::*;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("retire-absence", detail)
}

pub(super) fn hash(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(text, "{byte:02x}");
    }
    text
}

pub(super) fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, LaneError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(refusal(format!("{}: {error}", path.display()))),
    };
    let meta = file
        .metadata()
        .map_err(|error| refusal(error.to_string()))?;
    if !meta.is_file()
        || meta.uid() != Uid::effective().as_raw()
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > MAX_RESERVATION_BYTES
    {
        return Err(refusal("record is not owner-private bounded custody"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RESERVATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refusal(error.to_string()))?;
    if bytes.len() as u64 > MAX_RESERVATION_BYTES {
        return Err(refusal("record exceeds reader bound"));
    }
    Ok(Some(bytes))
}

fn flags(request: &RetireRequest) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if request.confirm_missing_lease {
        flags.push("--confirm-missing-lease");
    }
    if request.confirm_missing_harvest_fields {
        flags.push("--confirm-missing-harvest-fields");
    }
    if request.confirm_uncertain {
        flags.push("--confirm-uncertain");
    }
    flags
}

/// Validate explicitly accepted historical absences without inferring consent.
///
/// # Errors
/// Refuses malformed, unbound, or contradictory confirmation evidence.
pub fn validate(record: &Value) -> Result<(), LaneError> {
    let Some(value) = record["current_retirement"].get("accepted_absences") else {
        return Ok(());
    };
    let keys = [
        "schema",
        "names",
        "owner_uid",
        "flags",
        "original_fields",
        "preview_sha256",
    ];
    let names = value["names"]
        .as_array()
        .ok_or_else(|| refusal("absence names absent"))?;
    let flags = value["flags"]
        .as_array()
        .ok_or_else(|| refusal("confirmation flags absent"))?;
    if value.as_object().is_none_or(|object| {
        object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key))
    }) || value["schema"] != 1
        || value["owner_uid"] != Uid::effective().as_raw()
        || names.is_empty()
        || names.len() > 3
        || flags.is_empty()
        || names.iter().any(|name| {
            ![
                json!("preparation_lease"),
                json!("harvest_agreement"),
                json!("collection"),
            ]
            .contains(name)
        })
        || names
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            != names.len()
        || flags.iter().any(|flag| {
            ![
                json!("--confirm-missing-lease"),
                json!("--confirm-missing-harvest-fields"),
                json!("--confirm-uncertain"),
            ]
            .contains(flag)
        })
        || value["preview_sha256"].as_str().is_none_or(|digest| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(refusal("accepted_absences shape differs"));
    }
    for name in names {
        let key = name
            .as_str()
            .ok_or_else(|| refusal("absence name is not text"))?;
        let evidence = &value["original_fields"][key];
        let required = if key == "preparation_lease" {
            "--confirm-missing-lease"
        } else {
            "--confirm-missing-harvest-fields"
        };
        if evidence != &json!({"present":false,"value":null})
            || !flags.contains(&json!(required))
            || (key != "preparation_lease" && record.get(key) != Some(&Value::Null))
        {
            return Err(refusal(
                "accepted absence contradicts its original field or flag",
            ));
        }
    }
    let plan = &record["retirement_absence_plan"];
    let mut unbound = value.clone();
    unbound["preview_sha256"] = Value::Null;
    if plan["schema"] != 1
        || node::digest(plan) != value["preview_sha256"]
        || plan["owner_uid"] != value["owner_uid"]
        || plan["loop"] != record["loop"]
        || plan["run"] != record["run"]
        || plan["flags"] != value["flags"]
        || plan["after"]["current_retirement"]["accepted_absences"] != unbound
        || value["original_fields"]
            .as_object()
            .is_none_or(|fields| fields.len() != names.len())
        || flags
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            != flags.len()
    {
        return Err(refusal("accepted absence plan binding differs"));
    }
    Ok(())
}

pub(super) fn metadata(path: &Path) -> Result<Value, LaneError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(
            json!({"present":true,"device":meta.dev(),"inode":meta.ino(),"mode":meta.mode(),"uid":meta.uid()}),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({"present":false})),
        Err(error) => Err(refusal(format!("{}: {error}", path.display()))),
    }
}

fn path_inputs(journal: &Value) -> Result<Value, LaneError> {
    let mut paths = Vec::new();
    for pair in journal["planned_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&journal["reservation_path"]))
    {
        let source = pair["source"]
            .as_str()
            .ok_or_else(|| refusal("source absent"))?;
        let target = pair["target"]
            .as_str()
            .ok_or_else(|| refusal("target absent"))?;
        paths.push(json!({"source":source,"source_identity":metadata(Path::new(source))?,"target":target,"target_identity":metadata(Path::new(target))?}));
    }
    Ok(json!(paths))
}

fn normalized(
    saved: &Value,
    request: &RetireRequest,
    missing_lease: bool,
) -> Result<Value, LaneError> {
    if !["preparing", "settled", "failed"].contains(&saved["phase"].as_str().unwrap_or_default()) {
        return Err(refusal(
            "confirmed absence requires a preparing, settled or failed reservation",
        ));
    }
    let mut record = saved.clone();
    let mut names = Vec::new();
    let mut original = serde_json::Map::new();
    if request.confirm_missing_lease {
        if !missing_lease {
            return Err(refusal(
                "preparation lease is present; omit --confirm-missing-lease",
            ));
        }
        names.push("preparation_lease");
        original.insert(
            "preparation_lease".into(),
            json!({"present":false,"value":null}),
        );
    }
    if request.confirm_missing_harvest_fields {
        for key in ["harvest_agreement", "collection"] {
            if saved.get(key).is_none() {
                names.push(key);
                original.insert(key.into(), json!({"present":false,"value":null}));
                record[key] = Value::Null;
            }
        }
        if !names.iter().any(|key| *key != "preparation_lease") {
            return Err(refusal(
                "harvest fields are present; omit --confirm-missing-harvest-fields",
            ));
        }
    }
    super::super::harvest::harvest_fields(&record)?;
    record["current_retirement"] = json!({"accepted_absences":{"schema":1,"names":names,"owner_uid":Uid::effective().as_raw(),"flags":flags(request),"original_fields":original,"preview_sha256":null}});
    Ok(record)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run(
    owner_home: &Path,
    root: &Path,
    request: &RetireRequest,
    runner: Option<&dyn node::Runner>,
    budget: Duration,
    begun: Instant,
    runs_guard: nix::fcntl::Flock<std::os::fd::OwnedFd>,
) -> Result<Value, LaneError> {
    let run = request
        .run
        .as_deref()
        .ok_or_else(|| refusal("run absent"))?;
    let owner = Uid::effective().as_raw();
    let lease_path = root.join(format!(".prepare-{run}.lock"));
    let mut lease = probe_retirement_lease(root, run, owner)?;
    let missing = lease.is_none();
    let lease_state = if let Some(held) = lease.as_ref() {
        let meta = held
            .metadata()
            .map_err(|error| refusal(error.to_string()))?;
        json!({"present":true,"device":meta.dev(),"inode":meta.ino(),"mode":meta.mode(),"uid":meta.uid()})
    } else {
        json!({"present":false})
    };
    if missing && !request.confirm_missing_lease {
        return Err(refusal(
            "lease absent; preview with --confirm-missing-lease",
        ));
    }
    let mailbox = lock_retirement_mailbox(root, run, owner, request.dry_run)?;
    let store = crate::requests::store::Store::open(owner_home, &request.loop_name, false)?;
    let requests_guard = store.retirement_guard(run, &*runs_guard, request.dry_run)?;
    let path = reservation_path(root, run);
    let saved = read_reservation(&path)?.ok_or_else(|| refusal("reservation absent"))?;
    if super::proof::needed(&saved) {
        return Err(LaneError::input(
            "retire-confirmation-missing-identity",
            "absence confirmation does not admit missing-identity runs; ordinary retirement requires the recorded lease and harvest fields",
        ));
    }
    let allocation = worker_range(owner_home, &request.loop_name)?;
    let home = owner_home
        .join(".cache/tmp")
        .join(format!("lane-{}-{run}", request.loop_name));
    let uid = saved["worker_uid"]
        .as_u64()
        .ok_or_else(|| refusal("worker uid absent"))?;
    if saved["loop"] != request.loop_name
        || saved["run"] != run
        || saved["plan"]["home"] != home.to_string_lossy().as_ref()
        || saved["plan"]["driver_dir"] != root.join(run).to_string_lossy().as_ref()
        || uid < u64::from(allocation.0)
        || uid >= u64::from(allocation.0) + u64::from(allocation.1)
    {
        return Err(refusal("reservation identity, paths or allocation differ"));
    }
    node_record::read(&saved)?;
    let route = node::plan(owner_home, &request.loop_name, run);
    let pending = node_record::pending(&route.value);
    let retry = saved.get("retirement_absence_plan").is_some();
    let mut after;
    let plan = if retry {
        validate(&saved)?;
        let plan = saved["retirement_absence_plan"].clone();
        if plan["flags"] != json!(flags(request))
            || plan["allocation"] != json!(allocation)
            || plan["node_plan"] != route.value
        {
            return Err(refusal(
                "pending absence plan inputs changed; restore inputs and repeat preview",
            ));
        }
        let mut expected = plan["after"].clone();
        expected["current_retirement"]["accepted_absences"]["preview_sha256"] =
            saved["current_retirement"]["accepted_absences"]["preview_sha256"].clone();
        expected["retirement_absence_plan"] = plan.clone();
        expected["phase"] = saved["phase"].clone();
        for key in ["state", "observer_socket_disposition", "retired_paths"] {
            if let Some(value) = saved["current_retirement"].get(key) {
                expected["current_retirement"][key] = value.clone();
            }
        }
        if expected != saved
            || !["retiring", "retired"].contains(&saved["phase"].as_str().unwrap_or_default())
        {
            return Err(refusal("reservation changed during confirmed retirement"));
        }
        after = saved;
        plan
    } else {
        after = normalized(&saved, request, missing)?;
        refuse_pending_collection(&after)?;
        refuse_import_evidence(&after)?;
        after = super::super::reaping::retirement_reconciliation(&after, owner_home)?;
        let program = after["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| refusal("runtime absent"))?
            .to_owned();
        let preview = retire_record_confirmed_with(
            owner_home,
            root,
            run,
            &home,
            &after,
            None,
            None,
            true,
            request.confirm_uncertain,
            Some(&pending),
            None,
            true,
            crate::container_helper::process_presence,
            || container_absent_for_run(Path::new(&program), owner_home, &request.loop_name, run),
        )?;
        after["current_retirement"] = preview["journal"].clone();
        after["node_retirement"] = preview["node_retirement"].clone();
        after["phase"] = json!("retiring");
        let bytes = read_bytes(&path)?.ok_or_else(|| refusal("reservation vanished"))?;
        json!({"schema":1,"command":"retire","owner_uid":owner,"loop":request.loop_name,"run":run,"flags":flags(request),
            "before_sha256":hash(&bytes),"before":saved,"after":after,"paths":path_inputs(&after["current_retirement"])?,
            "lease":{"path":lease_path,"before":lease_state,"action":if missing {"create-owner-0600"} else {"lock-existing"}},
            "allocation":allocation,"node_plan":route.value})
    };
    let digest = node::digest(&plan);
    if retry {
        for row in plan["paths"]
            .as_array()
            .ok_or_else(|| refusal("pending path inputs absent"))?
        {
            let source = Path::new(
                row["source"]
                    .as_str()
                    .ok_or_else(|| refusal("pending source absent"))?,
            );
            if source == path {
                continue;
            }
            let target = Path::new(
                row["target"]
                    .as_str()
                    .ok_or_else(|| refusal("pending target absent"))?,
            );
            let current_source = metadata(source)?;
            let current_target = metadata(target)?;
            let unchanged = current_source == row["source_identity"]
                && current_target == row["target_identity"];
            let moved =
                current_source["present"] == false && current_target == row["source_identity"];
            if !unchanged && !moved {
                return Err(refusal(
                    "custody identity changed during retirement; restore the journaled paths",
                ));
            }
        }
    }
    after["current_retirement"]["accepted_absences"]["preview_sha256"] = json!(digest);
    after["retirement_absence_plan"] = plan.clone();
    validate(&after)?;
    let length = serde_json::to_vec(&after)
        .map_err(|error| refusal(error.to_string()))?
        .len();
    if length as u64 > MAX_RESERVATION_BYTES {
        return Err(LaneError::input(
            "reservation-size",
            format!(
                "confirmed retirement record is {length} bytes; reader limit is {MAX_RESERVATION_BYTES} bytes"
            ),
        ));
    }
    let program = after["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| refusal("runtime absent"))?
        .to_owned();
    let mut presence_record = after.clone();
    presence_record["phase"] = after["current_retirement"]["prior_phase"].clone();
    checked_presence(
        owner_home,
        &presence_record,
        confirmed_uncertainty(&after, request.confirm_uncertain)?,
        crate::container_helper::process_presence,
    )?;
    if !container_absent_for_run(Path::new(&program), owner_home, &request.loop_name, run)? {
        return Err(LaneError::input(
            "retire-busy",
            "labelled container is still present",
        ));
    }
    validate_retirement_paths(&after)?;
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"retire","loop":request.loop_name,"run":run,"dry_run":true,"preview_sha256":digest,"plan":plan,"resuming":retry,"worker_uid_released":null,"retirement":{"state":"would-retire","journal":after["current_retirement"]},"wall_seconds":begun.elapsed().as_secs_f64()}),
        );
    }
    if request.expect_digest.is_none() {
        return Err(refusal(
            "confirmed retirement requires --expect-digest from the same confirmation's --dry-run",
        ));
    }
    node_record::check_digest(request.expect_digest.as_deref(), &digest)?;
    if !retry {
        let bytes = read_bytes(&path)?.ok_or_else(|| refusal("reservation vanished"))?;
        if hash(&bytes) != plan["before_sha256"]
            || path_inputs(&after["current_retirement"])? != plan["paths"]
            || metadata(&lease_path)? != plan["lease"]["before"]
        {
            return Err(refusal(
                "reservation bytes or path identities changed; repeat the dry run",
            ));
        }
        publish_reservation(&path, &after)?;
    }
    if missing {
        lease = Some(lock_run_preparation(root, run, owner)?);
    }
    let mut result = retire_record_confirmed_with(
        owner_home,
        root,
        run,
        &home,
        &after,
        None,
        None,
        false,
        request.confirm_uncertain,
        Some(&pending),
        None,
        true,
        crate::container_helper::process_presence,
        || container_absent_for_run(Path::new(&program), owner_home, &request.loop_name, run),
    )?;
    drop(mailbox);
    drop(requests_guard);
    drop(runs_guard);
    let archive = result["record"]
        .as_str()
        .ok_or_else(|| refusal("archive absent"))?
        .to_owned();
    result["node_retirement"] = node_record::finish(Path::new(&archive), &route, runner, budget)?;
    result["preview_sha256"] = json!(digest);
    drop(lease);
    Ok(
        json!({"schema":1,"command":"retire","loop":request.loop_name,"run":run,"dry_run":false,"preview_sha256":digest,"plan":plan,"worker_uid_released":uid,"retirement":result,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(worker: u32) -> (tempfile::TempDir, PathBuf, RetireRequest, Value) {
        let (home, root, request) = super::super::tests::public_fixture();
        let runtime = home.path().join("runtime");
        crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n").expect("runtime");
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,
            "imports":[],"harvest_agreement":null,"collection":null,
            "plan":{"home":home.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},
            "launcher_pid":u32::MAX-worker,"launcher_start":worker,"driver_entry_pid":u32::MAX-worker,"driver_entry_start":worker,
            "helper_pid":u32::MAX-worker,"helper_start":worker,"helper_parent_pid":u32::MAX-worker,"helper_parent_start":worker,
            "observer_state":"ended","observer_pid":u32::MAX-worker,"observer_start":worker});
        (home, root, request, record)
    }

    /// # Panics
    /// Panics only if fixture setup or retirement violates the asserted contract.
    /// ´test:unit:confirmed-absence-preview-apply-and-retired-readers´
    #[test]
    fn confirmed_absence_preview_apply_and_retired_readers() {
        for worker in [3000, 3001] {
            let (home, mut request, mut runner) =
                super::super::node_tests::fixture(worker, true, "unreachable");
            let root = runner.root.clone();
            fs::remove_file(root.join(".prepare-R.lock")).expect("missing lease");
            let mut record = read_reservation(&reservation_path(&root, "R"))
                .expect("reader")
                .expect("record");
            record
                .as_object_mut()
                .expect("record")
                .remove("harvest_agreement");
            record.as_object_mut().expect("record").remove("collection");
            publish_reservation(&reservation_path(&root, "R"), &record).expect("older record");
            request.confirm_missing_lease = true;
            request.confirm_missing_harvest_fields = true;
            let preview =
                super::super::node_tests::execute(home.path(), &request, &runner).expect("preview");
            assert!(!root.join(".letter-R.lock").exists());
            let held = lock_mailbox(&root, "R", Uid::effective().as_raw()).expect("letter writer");
            let busy = super::super::node_tests::execute(home.path(), &request, &runner)
                .expect_err("held mailbox refuses preview");
            assert_eq!(busy.kind, "retire-busy");
            assert!(busy.detail.contains("mailbox lock"));
            drop(held);
            assert_eq!(preview["retirement"]["state"], "would-retire");
            assert_eq!(
                preview["plan"]["after"]["current_retirement"]["accepted_absences"]["names"],
                json!(["preparation_lease", "harvest_agreement", "collection"])
            );
            assert!(!root.join(".prepare-R.lock").exists());
            assert_eq!(
                read_reservation(&reservation_path(&root, "R"))
                    .expect("read")
                    .expect("record"),
                record
            );
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let result =
                super::super::node_tests::execute(home.path(), &request, &runner).expect("apply");
            assert_eq!(result["worker_uid_released"], worker);
            assert_eq!(result["retirement"]["state"], "retired");
            let archive = Path::new(result["retirement"]["record"].as_str().expect("archive"));
            let retired = read_reservation(archive).expect("reader").expect("record");
            let accepted = retired["current_retirement"]["accepted_absences"].clone();
            assert_eq!(accepted["preview_sha256"], preview["preview_sha256"]);
            assert!(retired["harvest_agreement"].is_null());
            assert!(retired["collection"].is_null());
            let census = super::super::super::census::run(home.path(), "alpha").expect("census");
            assert_eq!(census["retired_records"][0]["accepted_absences"], accepted);
            assert_eq!(retired["node_retirement"]["outcome"]["owed"], true);
            assert_eq!(
                retired["node_retirement"]["outcome"]["reason"],
                "node-retirement-unreachable"
            );
            runner.mode = "success";
            request.node = true;
            request.confirm_missing_lease = false;
            request.confirm_missing_harvest_fields = false;
            request.dry_run = true;
            request.expect_digest = None;
            let preview = super::super::node_tests::execute(home.path(), &request, &runner)
                .expect("node preview");
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            super::super::node_tests::execute(home.path(), &request, &runner)
                .expect("node completion");
            assert_eq!(
                read_reservation(archive).expect("reader").expect("record")["current_retirement"]["accepted_absences"],
                accepted
            );
            let completed = read_reservation(archive).expect("reader").expect("record");
            assert_eq!(completed["node_retirement"]["outcome"]["owed"], false);
            assert_eq!(runner.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            let mut malformed = retired;
            assert_ne!(Uid::effective().as_raw(), worker);
            malformed["current_retirement"]["accepted_absences"]["owner_uid"] = json!(worker);
            publish_reservation(archive, &malformed).expect("malformed evidence");
            assert_eq!(
                read_reservation(archive).expect_err("strict reader").kind,
                "retire-absence"
            );
        }
    }

    /// # Panics
    /// Panics only if fixture setup or retirement violates the asserted contract.
    /// ´test:unit:confirmed-absence-without-registration-refuses-node-completion´
    #[test]
    fn confirmed_absence_without_registration_refuses_node_completion() {
        let (home, root, mut request, record) = fixture(3000);
        publish_reservation(&reservation_path(&root, "R"), &record).expect("record");
        request.confirm_missing_lease = true;
        let preview = super::super::run(home.path(), &request).expect("preview");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let result = super::super::run(home.path(), &request).expect("archive");
        let archive = Path::new(result["retirement"]["record"].as_str().expect("archive"));
        let before = fs::read(archive).expect("archive bytes");
        let retired = read_reservation(archive).expect("reader").expect("record");
        assert_eq!(
            retired["node_retirement"]["outcome"]["reason"],
            "node-retirement-no-registration"
        );
        assert_eq!(retired["node_retirement"]["outcome"]["owed"], false);
        request.node = true;
        request.confirm_missing_lease = false;
        for dry_run in [true, false] {
            request.dry_run = dry_run;
            assert_eq!(
                super::super::run(home.path(), &request)
                    .expect_err("nothing owed")
                    .kind,
                "retire-node-not-owed"
            );
            assert_eq!(fs::read(archive).expect("unchanged archive"), before);
        }
    }

    /// ´test:unit:preparing-absence-preview-and-act-retain-reader-evidence´
    #[allow(clippy::too_many_lines)]
    #[test]
    fn preparing_absence_preview_and_act_retain_reader_evidence() {
        for case in [
            "absent",
            "live",
            "starting",
            "missing-state",
            "container",
            "socket-absent",
            "socket-present",
            "contradictory-end",
            "unknown",
        ] {
            let (home, root, mut request, mut record) = fixture(3000);
            let _scope = super::super::super::reaping::RetirementScopeFixture::new(&mut record);
            record["phase"] = json!("preparing");
            record["helper_spawn_state"] = json!("not-started");
            record["observer_state"] = json!("not-started");
            for field in [
                "driver_entry_pid",
                "driver_entry_start",
                "helper_pid",
                "helper_start",
                "helper_parent_pid",
                "helper_parent_start",
                "observer_pid",
                "observer_start",
                "harvest_agreement",
                "collection",
            ] {
                record.as_object_mut().expect("record").remove(field);
            }
            match case {
                "socket-absent" | "socket-present" => {
                    let sockets = home.path().join("vendor");
                    fs::create_dir(&sockets).expect("socket directory");
                    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))
                        .expect("socket mode");
                    record["plan"]["vendor_mode"] = json!("fixture");
                    record["plan"]["vendor_socket"] = json!("observer.sock");
                    record["plan"]["mounts"] =
                        json!([{"source":sockets,"target":"/home/worker/.local/vendor"}]);
                    if case == "socket-present" {
                        let socket =
                            std::os::unix::net::UnixListener::bind(sockets.join("observer.sock"))
                                .expect("observer socket");
                        drop(socket);
                    }
                }
                "contradictory-end" => {
                    record["helper_end"] = json!({"state":"not-started","pid":42});
                }
                "live" => {
                    record["launcher_pid"] = json!(std::process::id());
                    record["launcher_start"] = json!(
                        crate::container_helper::process_start(std::process::id()).expect("tick")
                    );
                }
                "starting" => record["helper_spawn_state"] = json!("starting"),
                "missing-state" => {
                    record
                        .as_object_mut()
                        .expect("record")
                        .remove("helper_spawn_state");
                }
                "container" => crate::fixture_exec::write_executable(
                    &home.path().join("runtime"),
                    b"#!/bin/sh\nprintf 'container-id\\n'\n",
                )
                .expect("present container"),
                "unknown" => {
                    let error =
                        super::super::checked_presence(Path::new("/"), &record, false, |_, _| {
                            crate::container_helper::ProcessPresence::Unknown
                        })
                        .expect_err("unknown launcher");
                    assert_eq!(error.kind, "retire-uncertain");
                    continue;
                }
                _ => {}
            }
            let path = reservation_path(&root, "R");
            publish_reservation(&path, &record).expect("stuck preparation");
            drop(
                lock_run_preparation(&root, "R", Uid::effective().as_raw())
                    .expect("reservation lease"),
            );
            let refusal =
                super::super::run(home.path(), &request).expect_err("missing harvest fields");
            assert_eq!(refusal.kind, "harvest-record");
            assert_eq!(
                refusal.detail.contains("; preview retire "),
                case == "absent" || case == "socket-absent",
                "{refusal:?}"
            );
            request.confirm_missing_harvest_fields = true;
            let preview = super::super::run(home.path(), &request);
            if case != "absent" && case != "socket-absent" {
                let error = preview.expect_err("unproved absence refuses");
                assert_eq!(
                    error.kind,
                    if case == "live" || case == "container" {
                        "retire-busy"
                    } else {
                        "retire-uncertain"
                    }
                );
                assert_eq!(
                    read_reservation(&path).expect("reader").expect("record"),
                    record
                );
                continue;
            }
            let preview = preview.expect("dead unstarted preparation preview");
            assert_eq!(preview["plan"]["before"], record);
            assert_eq!(
                read_reservation(&path).expect("reader").expect("record"),
                record
            );
            request.dry_run = false;
            request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
            let done = super::super::run(home.path(), &request).expect("retire preparation");
            let archive = Path::new(done["retirement"]["record"].as_str().expect("archive"));
            let retired = read_reservation(archive)
                .expect("strict reader")
                .expect("retired");
            assert_eq!(
                retired["retirement_absence_plan"]["before"]["phase"],
                "preparing"
            );
            let census = super::super::super::census::run(home.path(), "alpha").expect("census");
            assert_eq!(
                census["retired_records"][0]["accepted_absences"],
                retired["current_retirement"]["accepted_absences"]
            );
            crate::requests::store::Store::open(home.path(), "alpha", false)
                .expect("request reader")
                .list_with_status()
                .expect("status after retirement");
            assert!(!path.exists());
        }
    }

    /// ´test:unit:preparing-retirement-measures-recorded-work-subtree´
    #[test]
    fn preparing_retirement_measures_recorded_work_subtree() {
        let (home, root, mut request, mut record) = fixture(3000);
        record["phase"] = json!("preparing");
        record["helper_spawn_state"] = json!("not-started");
        record["observer_state"] = json!("not-started");
        for field in [
            "driver_entry_pid",
            "driver_entry_start",
            "helper_pid",
            "helper_start",
            "helper_parent_pid",
            "helper_parent_start",
            "observer_pid",
            "observer_start",
            "harvest_agreement",
            "collection",
        ] {
            record.as_object_mut().expect("record").remove(field);
        }
        let scope = super::super::super::reaping::RetirementScopeFixture::new(&mut record);
        let nested = scope.path.join("private-step");
        fs::create_dir(&nested).expect("nested work scope");
        let mut child = std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("live private step");
        // Fixture controller files expose a real child's PID to the production subtree reader.
        fs::write(nested.join("cgroup.procs"), format!("{}\n", child.id())).expect("scope child");
        fs::write(scope.path.join("cgroup.events"), "populated 1\n").expect("populated");
        let path = reservation_path(&root, "R");
        publish_reservation(&path, &record).expect("preparation");
        request.confirm_missing_lease = true;
        request.confirm_missing_harvest_fields = true;
        let live = super::super::run(home.path(), &request);
        // Even an inconsistent empty events file cannot hide a child in a nested scope.
        fs::write(scope.path.join("cgroup.events"), "populated 0\n").expect("inconsistent");
        let inconsistent = super::super::run(home.path(), &request);
        drop(child.stdin.take());
        assert!(child.wait().expect("wait private step").success());
        for result in [live, inconsistent] {
            let error = result.expect_err("scoped child blocks retirement");
            assert_eq!(error.kind, "retire-busy");
            assert!(error.detail.contains("recorded run scope"));
        }
        fs::write(nested.join("cgroup.procs"), "").expect("empty subtree");
        super::super::run(home.path(), &request).expect("empty scope preview");
        fs::remove_file(scope.path.join("cgroup.events")).expect("unreadable controller");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("unmeasured scope")
                .kind,
            "run-cgroup"
        );
        fs::write(scope.path.join("cgroup.events"), "populated 0\n").expect("restore controller");
        record["run_scope"]["inode"] =
            json!(record["run_scope"]["inode"].as_u64().expect("inode") + 1);
        publish_reservation(&path, &record).expect("substituted scope identity");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("changed scope")
                .kind,
            "run-scope-record"
        );
        record.as_object_mut().expect("record").remove("run_scope");
        publish_reservation(&path, &record).expect("missing scope identity");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("missing scope")
                .kind,
            "run-scope-record"
        );
        assert_eq!(
            read_reservation(&path)
                .expect("read")
                .expect("reservation retained"),
            record
        );
        assert!(!root.join(".prepare-R.lock").exists());
    }

    /// ´test:unit:confirmed-absence-refuses-live-unknown-and-stale-evidence´
    #[test]
    fn confirmed_absence_refuses_live_unknown_and_stale_evidence() {
        let (home, root, mut request, mut record) = fixture(3000);
        let path = reservation_path(&root, "R");
        request.confirm_missing_lease = true;
        record["launcher_pid"] = json!(std::process::id());
        record["launcher_start"] =
            json!(crate::container_helper::process_start(std::process::id()).expect("identity"));
        publish_reservation(&path, &record).expect("live");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("live")
                .kind,
            "retire-busy"
        );
        record["launcher_pid"] = json!(u32::MAX);
        record["launcher_start"] = json!(1);
        record
            .as_object_mut()
            .expect("record")
            .remove("driver_entry_start");
        publish_reservation(&path, &record).expect("half identity");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("unknown")
                .kind,
            "settlement-identity"
        );
        record["driver_entry_start"] = json!(3000);
        publish_reservation(&path, &record).expect("absent");
        let preview = super::super::run(home.path(), &request).expect("preview");
        record["changed"] = json!(true);
        publish_reservation(&path, &record).expect("changed");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("stale digest")
                .kind,
            "retire-digest"
        );
        assert!(!root.join(".prepare-R.lock").exists());
    }

    /// ´test:unit:confirmed-absence-resumes-journal-before-lease-creation´
    #[test]
    fn confirmed_absence_resumes_journal_before_lease_creation() {
        let (home, root, mut request, record) = fixture(3001);
        let path = reservation_path(&root, "R");
        publish_reservation(&path, &record).expect("record");
        request.confirm_missing_lease = true;
        let preview = super::super::run(home.path(), &request).expect("preview");
        let mut pending = preview["plan"]["after"].clone();
        pending["current_retirement"]["accepted_absences"]["preview_sha256"] =
            preview["preview_sha256"].clone();
        pending["retirement_absence_plan"] = preview["plan"].clone();
        publish_reservation(&path, &pending).expect("interrupted after journal");
        let resumed = super::super::run(home.path(), &request).expect("resume preview");
        assert_eq!(resumed["resuming"], true);
        assert_eq!(resumed["preview_sha256"], preview["preview_sha256"]);
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request).expect("resume apply")["retirement"]["state"],
            "retired"
        );
    }

    /// ´test:unit:confirmed-harvest-absence-never-invents-agreement´
    #[test]
    fn confirmed_harvest_absence_never_invents_agreement() {
        let (home, root, mut request, mut record) = fixture(3000);
        drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("lease"));
        record
            .as_object_mut()
            .expect("record")
            .remove("harvest_agreement");
        record["collection"] = json!({"state":"collected"});
        publish_reservation(&reservation_path(&root, "R"), &record).expect("contradiction");
        request.confirm_missing_harvest_fields = true;
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("agreement cannot be invented")
                .kind,
            "harvest-record"
        );
    }

    /// ´test:unit:confirmed-harvest-only-and-unsafe-lease-refusals´
    #[test]
    fn confirmed_harvest_only_and_unsafe_lease_refusals() {
        let (home, root, mut request, mut record) = fixture(3001);
        let lease = root.join(".prepare-R.lock");
        drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("lease"));
        record
            .as_object_mut()
            .expect("record")
            .remove("harvest_agreement");
        publish_reservation(&reservation_path(&root, "R"), &record).expect("record");
        let ordinary = super::super::run(home.path(), &request)
            .expect_err("ordinary preview names correction");
        assert_eq!(ordinary.kind, "harvest-record");
        assert!(
            ordinary
                .detail
                .contains("retire alpha R --confirm-missing-harvest-fields --dry-run")
        );
        assert!(!root.join(".letter-R.lock").exists());
        request.confirm_missing_harvest_fields = true;
        let preview = super::super::run(home.path(), &request).expect("harvest only preview");
        assert_eq!(
            preview["plan"]["after"]["current_retirement"]["accepted_absences"]["names"],
            json!(["harvest_agreement"])
        );
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o644)).expect("unsafe lease");
        assert_eq!(
            super::super::run(home.path(), &request)
                .expect_err("unsafe lease")
                .kind,
            "retire-lease"
        );
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("restore lease");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        assert_eq!(
            super::super::run(home.path(), &request).expect("harvest only apply")["retirement"]["state"],
            "retired"
        );
    }

    /// ´test:unit:confirmed-absence-recovery-refuses-replaced-custody-in-preview´
    #[test]
    fn confirmed_absence_recovery_refuses_replaced_custody_in_preview() {
        let (home, root, mut request, record) = fixture(3000);
        let path = reservation_path(&root, "R");
        fs::create_dir(root.join("R")).expect("driver");
        publish_reservation(&path, &record).expect("record");
        request.confirm_missing_lease = true;
        let preview = super::super::run(home.path(), &request).expect("preview");
        let mut pending = preview["plan"]["after"].clone();
        pending["current_retirement"]["accepted_absences"]["preview_sha256"] =
            preview["preview_sha256"].clone();
        pending["retirement_absence_plan"] = preview["plan"].clone();
        publish_reservation(&path, &pending).expect("interrupted journal");
        fs::rename(root.join("R"), root.join("original-driver")).expect("retain original inode");
        fs::create_dir(root.join("R")).expect("replacement");
        let dry = super::super::run(home.path(), &request).expect_err("preview refuses");
        assert_eq!(dry.kind, "retire-absence");
        assert!(dry.detail.contains("custody identity changed"));
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let changing = super::super::run(home.path(), &request).expect_err("apply refuses");
        assert_eq!(changing.kind, dry.kind);
        assert!(changing.detail.contains("custody identity changed"));
    }

    /// ´test:unit:retire-absence-command-forms-name-only-run-confirmations´
    #[test]
    fn retire_absence_command_forms_name_only_run_confirmations() {
        for words in [
            vec!["alpha", "R", "--confirm-missing-lease", "--dry-run"],
            vec![
                "alpha",
                "R",
                "--confirm-missing-harvest-fields",
                "--dry-run",
            ],
        ] {
            let parsed =
                RetireRequest::parse(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .expect("confirmed form");
            assert!(parsed.confirm_missing_lease || parsed.confirm_missing_harvest_fields);
        }
        for words in [
            vec!["alpha", "--generations", "--confirm-missing-lease"],
            vec!["alpha", "R", "--node", "--confirm-missing-harvest-fields"],
            vec![
                "alpha",
                "R",
                "--confirm-missing-lease",
                "--confirm-missing-lease",
            ],
        ] {
            assert_eq!(
                RetireRequest::parse(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .expect_err("wrong family")
                    .kind,
                "retire-usage"
            );
        }
    }

    /// ´test:unit:confirmed-absence-preview-refuses-oversized-journal´
    #[test]
    fn confirmed_absence_preview_refuses_oversized_journal() {
        let (home, root, mut request, mut record) = fixture(3000);
        record["retained_evidence"] = json!("x".repeat(1_500_000));
        publish_reservation(&reservation_path(&root, "R"), &record).expect("bounded original");
        request.confirm_missing_lease = true;
        let error = super::super::run(home.path(), &request)
            .expect_err("preview names changing size refusal");
        assert_eq!(error.kind, "reservation-size");
        assert!(!root.join(".prepare-R.lock").exists());
    }
}
