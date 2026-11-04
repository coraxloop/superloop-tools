//! Bind a service delivery to a protected worker reservation before resume.
use super::{lock_mailbox, publish_reservation, read_reservation, reservation_path};
use crate::{build, error::LaneError, home, plan::Plan};
use nix::unistd::Uid;
use serde_json::{Value, json};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

pub struct Request {
    pub loop_name: String,
    pub run: String,
    pub step: String,
    pub delivery: String,
}
impl Request {
    /// Parse a service-assigned delivery selection, never a legacy letter path.
    ///
    /// # Errors
    /// Refuses missing, repeated or malformed arguments.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, step_flag, step, delivery_flag, delivery] = args else {
            return Err(LaneError::input(
                "mail-usage",
                "bind-mail LOOP RUN --step STEP --delivery UTC_INSTANT",
            ));
        };
        if step_flag != "--step" || delivery_flag != "--delivery" {
            return Err(LaneError::input(
                "mail-usage",
                "expected --step and --delivery",
            ));
        }
        loop_home::validate_name(loop_name).map_err(failure)?;
        if !crate::valid_run_name(run) {
            return Err(failure("invalid run name"));
        }
        super::letters::valid_step(step)?;
        loop_home::mail::instant::Instant::parse(delivery)
            .map_err(|error| LaneError::input("mail-delivery", error.to_string()))?;
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            step: step.clone(),
            delivery: delivery.clone(),
        })
    }
}
fn failure(error: impl std::fmt::Display) -> LaneError {
    LaneError::input("mail-delivery", error.to_string())
}
fn identity(record: &Value) -> Result<loop_home::mail::birth::Identity, LaneError> {
    serde_json::from_value(record["mail_birth"].clone()).map_err(failure)
}
pub(super) fn evidence(plan: &Plan, step: &str) -> PathBuf {
    plan.driver_dir.join(format!("mail-{step}.txt"))
}

/// Verify and pin a delivered own-loop brief, then publish its reservation binding.
///
/// # Errors
/// Refuses an unavailable delivery, changed worker or conflicting step binding.
pub fn run(owner_home: &Path, request: &Request, reply: bool) -> Result<Value, LaneError> {
    let (plan, _) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| failure("runs root absent"))?;
    let _mailbox = lock_mailbox(root, &request.run, Uid::effective().as_raw())?;
    let path = reservation_path(root, &request.run);
    let mut record = read_reservation(&path)?.ok_or_else(|| failure("reservation absent"))?;
    if record.get("letters").is_some() {
        return Err(failure(
            "legacy reservation requires mail cutover reconciliation",
        ));
    }
    if !matches!(record["phase"].as_str(), Some("started" | "settled")) {
        return Err(failure("binding requires a started or settled reservation"));
    }
    let key = if reply { "mail_replies" } else { "mail" };
    let prior = record[key]
        .as_array()
        .ok_or_else(|| failure("mail bindings absent"))?
        .iter()
        .find(|prior| prior["step"] == request.step);
    if prior.is_some_and(|prior| prior["delivery"] != request.delivery) {
        return Err(failure("step already binds another delivery"));
    }
    let exe = std::env::current_exe().map_err(failure)?;
    let binding = verify_kind(
        owner_home,
        &plan,
        &record,
        &request.step,
        &request.delivery,
        reply,
        false,
        (Path::new("/"), 0, exe.as_path()),
    )?;
    let mail = record[if reply { "mail_replies" } else { "mail" }]
        .as_array_mut()
        .ok_or_else(|| failure("mail bindings absent"))?;
    if let Some(prior) = mail.iter().find(|prior| prior["step"] == request.step) {
        if prior != &binding {
            return Err(failure("step already binds another delivery"));
        }
    } else {
        mail.push(binding.clone());
        publish_reservation(&path, &record)?;
    }
    Ok(
        json!({"command":if reply { "bind-reply" } else { "bind-mail" },"mail":binding,"resume_authorized":false}),
    )
}

/// Reverify the exact delivery on every resume; the service pin precedes return.
///
/// # Errors
/// Refuses a moved inbox entry, forged principal, changed bytes or private entry failure.
pub(super) fn verify(
    owner_home: &Path,
    plan: &Plan,
    record: &Value,
    step: &str,
    delivery: &str,
    verify_only: bool,
    host: (&Path, u32, &Path),
) -> Result<Value, LaneError> {
    verify_kind(
        owner_home,
        plan,
        record,
        step,
        delivery,
        false,
        verify_only,
        host,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_kind(
    owner_home: &Path,
    plan: &Plan,
    record: &Value,
    step: &str,
    delivery: &str,
    reply: bool,
    verify_only: bool,
    host: (&Path, u32, &Path),
) -> Result<Value, LaneError> {
    super::letters::valid_step(step)?;
    let caller = Uid::effective().as_raw();
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| failure("runs root absent"))?;
    let podman = PathBuf::from(
        record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| failure("container program absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = crate::pinned::owner_executable_word(host.2, caller)?;
    let verified_home = home::verify_host_prefix_from(host.0, owner_home, caller, host.1)?;
    let verified_runs = home::verify_host_launch_root(host.0, owner_home, root, caller, host.1)?;
    let argv = binding_argv(
        exe,
        record,
        owner_home,
        step,
        delivery,
        (reply, verify_only),
    )?;
    let output = build::run_checked_with_private_launch(
        &podman,
        argv,
        &super::launch_environment(owner_home)?,
        owner_home,
        60,
        "bind-mail",
        &verified_home,
        root,
        &verified_runs,
        None,
    )?;
    let binding: Value = serde_json::from_str(&output).map_err(failure)?;
    let worker = identity(record)?;
    let principal = record["loop"]
        .as_str()
        .ok_or_else(|| failure("loop absent"))?;
    let worker_address = format!("{principal}+{}", worker.name);
    let (sender, recipient) = if reply {
        (worker_address.as_str(), principal)
    } else {
        (principal, worker_address.as_str())
    };
    if binding["worker_uid"] != worker.uid
        || binding["sender"] != sender
        || binding["recipient"] != recipient
        || binding["step"] != step
        || binding["delivery"] != delivery
    {
        return Err(failure("private binding differs from reservation"));
    }

    Ok(binding)
}

fn binding_argv(
    exe: String,
    record: &Value,
    owner_home: &Path,
    step: &str,
    delivery: &str,
    direction: (bool, bool),
) -> Result<Vec<String>, LaneError> {
    let (reply, verify_only) = direction;
    let mut argv = vec![
        "unshare".into(),
        exe,
        if reply {
            "_bind-reply".into()
        } else {
            "_bind-mail".into()
        },
        record["loop"]
            .as_str()
            .ok_or_else(|| failure("loop absent"))?
            .into(),
        record["run"]
            .as_str()
            .ok_or_else(|| failure("run absent"))?
            .into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--step".into(),
        step.into(),
        "--delivery".into(),
        delivery.into(),
    ];
    if verify_only {
        argv.push("--verify-only".into());
    }
    Ok(argv)
}

/// Namespace-root production entry; verify the birth before dropping to service UID.
///
/// The preopened evidence descriptor grants no access to other host files.
///
/// # Errors
/// Refuses changed custody, identity, delivery or evidence publication.
pub fn private_bind(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    step: &str,
    delivery: &str,
    reply: bool,
    verify_only: bool,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(failure("namespace-root entry required"));
    }
    super::letters::valid_step(step)?;
    let (plan, _) = crate::load_plan_for_record(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| failure("runs root absent"))?;
    let record = read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| failure("reservation absent"))?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(failure("reservation identity differs"));
    }
    let worker = identity(&record)?;
    let loop_uid = super::recorded_loop_uid(&record)?;
    let directory = home::pin_loop_round(root, &plan.driver_dir, 0, loop_uid)?;
    let mut file = File::from(
        nix::fcntl::openat2(
            &directory,
            format!("{}-{step}.txt", if reply { "reply" } else { "mail" }).as_str(),
            nix::fcntl::OpenHow::new()
                .flags(
                    (if verify_only {
                        nix::fcntl::OFlag::O_RDONLY
                    } else {
                        nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CREAT
                    }) | nix::fcntl::OFlag::O_CLOEXEC
                        | nix::fcntl::OFlag::O_NONBLOCK,
                )
                .mode(nix::sys::stat::Mode::from_bits_truncate(if verify_only {
                    0
                } else {
                    0o600
                }))
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
        .map_err(failure)?,
    );
    let meta = file.metadata().map_err(failure)?;
    if !meta.is_file()
        || meta.uid() != super::recorded_loop_uid(&record)? && meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
    {
        return Err(failure("evidence custody differs"));
    }
    if !verify_only {
        nix::unistd::fchown(
            &file,
            Some(Uid::from_raw(loop_uid)),
            Some(nix::unistd::Gid::from_raw(loop_uid)),
        )
        .map_err(failure)?;
    }
    let instant = loop_home::mail::instant::Instant::parse(delivery).map_err(failure)?;
    let resolve = if verify_only {
        loop_home::mail::steering::verify
    } else if reply {
        loop_home::mail::steering::reply
    } else {
        loop_home::mail::steering::bind
    };
    let (delivery, bytes) =
        resolve(owner_home, loop_name, &worker, step, &instant).map_err(failure)?;
    if verify_only {
        let mut evidence = Vec::new();
        file.take(loop_home::mail::journal::MAX_LETTER_BYTES + 1)
            .read_to_end(&mut evidence)
            .map_err(failure)?;
        if evidence != bytes {
            return Err(failure("retained evidence differs from verified delivery"));
        }
    } else {
        file.set_len(0).map_err(failure)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(failure)?;
        nix::unistd::fsync(&directory).map_err(failure)?;
    }
    let stopped = !reply && declarations(&bytes, &record)?;
    Ok(
        json!({"worker_uid":worker.uid,"sender":delivery.sender,"recipient":delivery.recipient,"delivery":delivery.delivery.to_string(),"journal_identity":format!("{}:{}",loop_home::mail::journal::digest(owner_home.as_os_str().as_encoded_bytes()),delivery.delivery),"inbox_name":delivery.inbox_name,"step":step,"evidence_digest":delivery.digest,"bytes":delivery.bytes,"stop":stopped}),
    )
}

// Mail remains opaque: only a UTF-8 brief participates in the optional
// launcher declaration convention; binary deliveries retain every byte.
fn declarations(bytes: &[u8], record: &Value) -> Result<bool, LaneError> {
    if std::str::from_utf8(bytes).is_err() {
        return Ok(false);
    }
    let selection = super::LaunchModel::select(
        bytes,
        record["model_selection"]["model"].as_str(),
        record["model_selection"]["effort"].as_str(),
    )?;
    if selection.model != record["model_selection"]["model"]
        || selection.effort != record["model_selection"]["effort"]
    {
        return Err(failure("steering selection differs from recorded model"));
    }
    super::letters::stop_declaration(bytes)
}

/// The initial brief and a journal-verified steering binding carry stop declarations.
pub(super) fn stop_brief<'a>(record: &'a Value, step: &str) -> Option<&'a Value> {
    if step == "dispatch" && record["initial_brief"]["stop"] == true {
        return Some(&record["initial_brief"]);
    }
    record["mail"]
        .as_array()?
        .iter()
        .find(|binding| binding["step"] == step && binding["stop"] == true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:mail-launcher-preview-appends-verify-only´
    #[test]
    fn mail_launcher_preview_appends_verify_only() {
        let record = json!({"loop":"alpha", "run":"R"});
        let argv = |verify_only| {
            binding_argv(
                "/entry".into(),
                &record,
                Path::new("/owner"),
                "review",
                "2026-01-01T00:00:00.000Z",
                (false, verify_only),
            )
            .expect("private argv")
        };
        let ordinary = argv(false);
        assert!(!ordinary.iter().any(|word| word == "--verify-only"));
        let preview = argv(true);
        assert_eq!(&preview[..ordinary.len()], &ordinary);
        assert_eq!(preview.last().map(String::as_str), Some("--verify-only"));
        assert_eq!(preview.len(), ordinary.len() + 1);
    }

    /// ´test:unit:opaque-mail-does-not-require-text-declarations´
    #[test]
    fn opaque_mail_does_not_require_text_declarations() {
        let record = json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}});
        assert!(!declarations(b"\0\xff", &record).expect("binary brief"));
        assert!(!declarations(b"", &record).expect("empty brief"));
        assert!(declarations(b"Stop: yes\n", &record).expect("cooperative stop"));
        assert!(declarations(b"Model: another-model\n", &record).is_err());
    }

    /// ´test:unit:mail-binding-selects-an-instant-and-never-a-letter-path´
    #[test]
    fn mail_binding_selects_an_instant_and_never_a_letter_path() {
        let words = [
            "alpha",
            "R",
            "--step",
            "review",
            "--delivery",
            "2026-01-01T00:00:00.000Z",
        ]
        .map(str::to_owned);
        let request = Request::parse(&words).expect("delivery selection");
        assert_eq!(request.step, "review");
        for (index, invalid) in [
            (0, "-alpha"),
            (1, "../R"),
            (2, "--letter"),
            (3, "../review"),
            (4, "--letter"),
            (5, "/tmp/letter"),
        ] {
            let mut malformed = words.clone();
            malformed[index] = invalid.into();
            assert!(Request::parse(&malformed).is_err(), "{index}: {invalid}");
        }
        let mut repeated = words.to_vec();
        repeated.extend(["--delivery".into(), words[5].clone()]);
        assert!(Request::parse(&repeated).is_err());
    }
}
