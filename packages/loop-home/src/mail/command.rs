//! Host-session entry into the existing subordinate-identity namespace.
use super::{
    directory::Directory,
    io,
    journal::{Journal, MailError, Result},
    publication::Durability,
    service::Service,
};
use nix::unistd::{Gid, Uid, setgroups, setresgid, setresuid};
use serde::Deserialize;
use std::ffi::OsString;
use std::os::unix::{fs::MetadataExt as _, process::CommandExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    version: u32,
    pub(super) uid: u32,
    pub(super) crash_consistent_rename: bool,
    pub(super) durable_sync: bool,
}
pub(super) fn settings(home: &Path) -> Result<Settings> {
    let file = io::absolute(&home.join(".config/loops/mail-service.toml"), false)?;
    let info = file.metadata()?;
    if info.uid() != io::search_directory(home)?.metadata()?.uid() || info.mode() & 0o022 != 0 {
        return Err(MailError::Invalid(
            "unsafe-storage: service settings custody",
        ));
    }
    let bytes = io::bounded(&file, 4096)?;
    let settings: Settings = toml::from_str(
        std::str::from_utf8(&bytes)
            .map_err(|_| MailError::Invalid("invalid-directory: service settings encoding"))?,
    )
    .map_err(|_| MailError::Invalid("invalid-directory: service settings schema"))?;
    if settings.version != 1 || !(1000..=65535).contains(&settings.uid) || settings.uid == 65534 {
        return Err(MailError::Invalid(
            "unsafe-storage: service identity or durability is not established",
        ));
    }
    Ok(settings)
}
pub(super) fn enter(home: &Path, settings: &Settings) -> Result<()> {
    if Uid::effective().as_raw() != 0 {
        return Err(MailError::Invalid(
            "unsafe-storage: namespace-root entry required",
        ));
    }
    let registry = crate::load_registry(&home.join(".config/loops/registry.toml"))
        .map_err(|_| MailError::Invalid("invalid-directory: registry"))?;
    let allocations =
        crate::allocations::Allocations::read(&home.join(".config/loops/allocations.toml"))
            .map_err(|_| MailError::Invalid("invalid-directory: allocations"))?;
    if allocations.mail_uid() != Some(settings.uid) {
        return Err(MailError::Invalid(
            "unsafe-storage: service identity is not reserved",
        ));
    }
    let private = registry
        .rows(home)
        .into_iter()
        .map(|row| row.uid)
        .collect::<Vec<_>>();
    let mut groups = vec![Gid::from_raw(settings.uid)];
    for group in allocations.mail_group_ids() {
        if private.contains(&group) || group == settings.uid {
            return Err(MailError::Invalid(
                "unsafe-storage: mailbox group overlaps private identity",
            ));
        }
        groups.push(Gid::from_raw(group));
    }
    groups.sort_unstable_by_key(|group| group.as_raw());
    groups.dedup();
    setgroups(&groups)?;
    let gid = Gid::from_raw(settings.uid);
    setresgid(gid, gid, gid)?;
    let uid = Uid::from_raw(settings.uid);
    setresuid(uid, uid, uid)?;
    nix::sys::prctl::set_no_new_privs()?;
    Ok(())
}
fn service(home: &Path, settings: &Settings) -> Result<Service> {
    if !settings.crash_consistent_rename || !settings.durable_sync {
        return Err(MailError::Invalid(
            "unsafe-storage: durability is not established",
        ));
    }
    if Uid::effective().as_raw() != settings.uid {
        return Err(MailError::Invalid(
            "unsafe-storage: dedicated service identity required",
        ));
    }
    let directory = Directory {
        home: home.to_owned(),
        service: settings.uid,
        owner: io::search_directory(home)?.metadata()?.uid(),
        durability: Durability {
            crash_consistent_rename: settings.crash_consistent_rename,
            durable_sync: settings.durable_sync,
        },
    };
    let journal = Journal::open(io::absolute(&home.join(".var/loops/.mail-service"), true)?)?;
    Ok(Service::new(directory, journal))
}
fn run(arguments: &[OsString], report: &mut dyn std::io::Write) -> Result<()> {
    let [mode, home] = arguments else {
        return Err(MailError::Invalid(
            "usage: superloop-mail {serve|scan|initialize} HOST_HOME",
        ));
    };
    let home = PathBuf::from(home);
    if mode == "serve" {
        let podman = crate::app::resolve_podman(
            std::env::var_os("ENTER_LOOP_PODMAN"),
            std::env::var_os("PATH").as_deref(),
        )
        .map_err(|_| MailError::Invalid("io-failure: identity-entry machinery unavailable"))?;
        let executable = std::env::current_exe()?;
        let error = Command::new(&podman[0])
            .args(&podman[1..])
            .arg("unshare")
            .arg(executable)
            .arg("_serve")
            .arg(&home)
            .exec();
        return Err(error.into());
    }
    if mode != "_serve" && mode != "scan" && mode != "initialize" {
        return Err(MailError::Invalid(
            "usage: superloop-mail {serve|scan|initialize} HOST_HOME",
        ));
    }
    let settings = settings(&home)?;
    if mode == "_serve" {
        enter(&home, &settings)?;
    }
    if mode == "initialize" {
        if Uid::effective().as_raw() != settings.uid {
            return Err(MailError::Invalid(
                "unsafe-storage: dedicated service identity required",
            ));
        }
        Journal::create(io::absolute(&home.join(".var/loops/.mail-service"), true)?)?;
        return Ok(());
    }
    let mut service = service(&home, &settings)?;
    loop {
        for failure in service.scan()? {
            writeln!(report, "{failure}")?;
        }
        if mode == "scan" {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
/// Execute delivery or report an explicit refusal without enabling a unit.
pub fn entry(arguments: &[OsString], report: &mut dyn std::io::Write) -> u8 {
    match run(arguments, report) {
        Ok(()) => 0,
        Err(error) => {
            let _written = writeln!(report, "{error}");
            if matches!(error, MailError::Invalid(_)) {
                2
            } else {
                1
            }
        }
    }
}
