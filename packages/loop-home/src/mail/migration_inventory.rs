//! Close the migration move set over the registry and native boxed-run census.
use super::{
    birth::Identity,
    io,
    journal::{MailError, Result, digest},
    migration::Source,
    migration_tree,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub present: bool,
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub loop_name: String,
    pub identity: Identity,
    pub sources: Vec<PathBuf>,
    pub record: PathBuf,
    pub record_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub registry_digest: String,
    pub loops: Vec<String>,
    pub sources: Vec<Source>,
    pub workers: Vec<Worker>,
    pub exclusions: Vec<Exclusion>,
    pub inert_leaves: Vec<PathBuf>,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn path(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| invalid("invalid-directory: migration census path"))
}
fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| invalid("invalid-directory: migration census array"))
}
fn fingerprint(path: &Path, required: bool) -> Result<Exclusion> {
    let file = match io::absolute(path, true) {
        Ok(file) => file,
        Err(MailError::Io(error)) if !required && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Exclusion {
                present: false,
                path: path.to_owned(),
                device: 0,
                inode: 0,
                digest: String::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let info = file.metadata()?;
    Ok(Exclusion {
        present: true,
        path: path.to_owned(),
        device: info.dev(),
        inode: info.ino(),
        digest: migration_tree::fingerprint(&file)?,
    })
}
/// Consume fresh output from the pinned native census, not an operator-written phase.
///
/// Every registry row must have exactly one census or a proved absent lane grant.
///
/// # Errors
/// Refuses live/uncertain runs, missing expected homes, unaccounted names and duplicate stores.
#[allow(clippy::too_many_lines)]
pub fn close(
    home: &Path,
    registry_bytes: &[u8],
    censuses: &[(String, Option<Value>)],
) -> Result<Inventory> {
    let text = std::str::from_utf8(registry_bytes)
        .map_err(|_| invalid("invalid-directory: migration registry encoding"))?;
    let registry = crate::registry::parse_registry(text)
        .map_err(|_| invalid("invalid-directory: migration registry"))?;
    let rows = registry.rows(home);
    let mut expected = rows.iter().map(|row| row.name.clone()).collect::<Vec<_>>();
    expected.sort();
    let mut provided = censuses
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    provided.sort();
    if expected != provided {
        return Err(invalid(
            "changed-source: migration census does not cover exact registry",
        ));
    }
    let mut result = Inventory {
        registry_digest: digest(registry_bytes),
        loops: expected,
        sources: Vec::new(),
        workers: Vec::new(),
        exclusions: Vec::new(),
        inert_leaves: Vec::new(),
    };
    let mut sources = BTreeSet::new();
    let mut exclusion_paths = BTreeSet::new();
    for row in rows {
        let legacy = row.home.join("inbox");
        let expected = match io::absolute(&legacy, true) {
            Ok(_) => true,
            Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        for leaf in ["new", "cur"] {
            let source = legacy.join(leaf);
            sources.insert(source.clone());
            result.sources.push(Source {
                path: source,
                read: row.home.join("mail/read"),
                expected,
            });
        }
        let census = censuses
            .iter()
            .find(|(name, _)| name == &row.name)
            .and_then(|(_, census)| census.as_ref());
        let Some(census) = census else {
            // Absence is derived independently: a registered lane grant cannot be omitted.
            if io::absolute(&home.join(".config/loops").join(&row.name), true).is_ok()
                || registry.runs_root(&row.name).is_some()
            {
                return Err(invalid("invalid-directory: missing expected lane census"));
            }
            continue;
        };
        if census["schema"] != 1 || census["command"] != "census" || census["loop"] != row.name {
            return Err(invalid("invalid-directory: native census identity"));
        }
        if census["admission"]["state"] != "paused" {
            return Err(invalid(
                "changed-source: pause native lane admission before migration",
            ));
        }
        if !array(&census["reservations"])?.is_empty() {
            return Err(invalid(
                "changed-source: drain or reconcile pre-cutover boxed runs before migration",
            ));
        }
        if !array(&census["mail_migration"]["unattributed_names"])?.is_empty() {
            return Err(invalid(
                "changed-source: native census has unattributed names",
            ));
        }
        for retired in array(&census["retired_records"])? {
            if !array(&retired["ambiguous_journaled_names"])?.is_empty() {
                return Err(invalid("invalid-directory: ambiguous retained run history"));
            }
            let identities = retired["identities"]
                .as_object()
                .ok_or_else(|| invalid("invalid-directory: retirement process evidence absent"))?;
            if identities.values().any(|identity| {
                !matches!(
                    identity["presence"].as_str(),
                    Some("absent" | "not-recorded")
                )
            }) {
                return Err(invalid(
                    "changed-source: retired run has a live or uncertain process",
                ));
            }
        }
        for record in array(&census["mail_migration"]["records"])? {
            if !array(&record["reconciliation_refusals"])?.is_empty() {
                return Err(invalid(
                    "changed-source: native boxed-run reconciliation is incomplete",
                ));
            }
            let uid = record["worker_uid"]
                .as_u64()
                .and_then(|uid| u32::try_from(uid).ok())
                .ok_or_else(|| invalid("invalid-directory: historical worker identity"))?;
            let record_path = path(&record["record"])?;
            let record_digest = record["record_sha256"]
                .as_str()
                .ok_or_else(|| invalid("invalid-directory: protected reservation digest absent"))?
                .to_owned();
            let identity = if record["mail_birth"].is_null() {
                Identity::for_reservation(
                    uid,
                    format!(
                        "migration:{}:{}:{}",
                        row.name,
                        record_path.display(),
                        record_digest
                    ),
                )
            } else {
                serde_json::from_value(record["mail_birth"].clone())
                    .map_err(|_| invalid("invalid-directory: existing mail birth mapping"))?
            };
            let mut worker = Worker {
                loop_name: row.name.clone(),
                identity,
                sources: Vec::new(),
                record: record_path,
                record_digest,
            };
            for home in array(&record["homes"])? {
                if home["present"] != true || home["required"] != true {
                    return Err(invalid("invalid-directory: expected box home is missing"));
                }
                let home_path = path(&home["path"])?;
                for leaf in ["inbox", "outbox"] {
                    let source = home_path.join(".local").join(leaf);
                    if !sources.insert(source.clone()) {
                        return Err(invalid(
                            "invalid-directory: duplicated migration source attribution",
                        ));
                    }
                    if leaf == "outbox" {
                        result.inert_leaves.push(source.clone());
                    }
                    worker.sources.push(source);
                }
            }
            for excluded in array(&record["exclusions"])? {
                let path = path(&excluded["path"])?;
                if exclusion_paths.insert(path.clone()) {
                    result
                        .exclusions
                        .push(fingerprint(&path, excluded["required"] != false)?);
                }
            }
            result.workers.push(worker);
        }
    }
    Ok(result)
}
impl Inventory {
    /// Add worker moves only after common birth and retirement establish sealed read custody.
    #[must_use]
    pub fn mapped_sources(&self, home: &Path) -> Vec<Source> {
        let mut result = self.sources.clone();
        for worker in &self.workers {
            let read = home
                .join(".var/loops")
                .join(&worker.loop_name)
                .join("workers")
                .join(&worker.identity.name)
                .join("mail/read");
            result.extend(worker.sources.iter().map(|path| Source {
                path: path.clone(),
                read: read.clone(),
                expected: true,
            }));
        }
        result
    }
    /// Driver trees retain their exact bytes and inode identity through conversion.
    ///
    /// # Errors
    /// A changed or missing driver tree blocks verification and activation.
    pub fn verify_exclusions(&self) -> Result<()> {
        for expected in &self.exclusions {
            let actual = fingerprint(&expected.path, expected.present)?;
            if actual.present != expected.present
                || actual.device != expected.device
                || actual.inode != expected.inode
                || actual.digest != expected.digest
            {
                return Err(invalid(
                    "changed-source: driver step or brief evidence changed",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    fn fixture(tag: &str) -> (PathBuf, Vec<u8>) {
        let home =
            std::env::temp_dir().join(format!("mail-inventory-{tag}-{}", std::process::id()));
        fs::create_dir(&home).expect("fixture");
        fs::create_dir_all(home.join(".config/loops")).expect("configuration");
        fs::create_dir_all(home.join(".var/loops/alpha")).expect("loop home");
        let registry=b"namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=3000,launch='dev/alpha'}]\n".to_vec();
        (home, registry)
    }
    /// ´claim:loophome:migration-inventory-covers-the-registry-and-never-downgrades-expected-stores´
    /// ´test:unit:migration-inventory-covers-the-registry-and-never-downgrades-expected-stores´
    #[test]
    fn migration_inventory_covers_the_registry_and_never_downgrades_expected_stores() {
        let (home, registry) = fixture("registry");
        assert!(close(&home, &registry, &[]).is_err());
        let census = vec![("alpha".into(), None)];
        let absent = close(&home, &registry, &census).expect("explicit absent loop stores");
        assert!(absent.sources.iter().all(|source| !source.expected));
        fs::create_dir_all(home.join(".var/loops/alpha/inbox/new")).expect("partial legacy store");
        let partial = close(&home, &registry, &census).expect("inventory marks both expected");
        assert!(partial.sources.iter().all(|source| source.expected));
        fs::create_dir(home.join(".config/loops/alpha")).expect("lane grant");
        assert!(close(&home, &registry, &census).is_err());
        fs::remove_dir_all(home).expect("cleanup");
    }
    /// ´claim:loophome:migration-inventory-requires-native-retirement-and-retains-driver-evidence´
    /// ´test:unit:migration-inventory-requires-native-retirement-and-retains-driver-evidence´
    #[test]
    fn migration_inventory_requires_native_retirement_and_retains_driver_evidence() {
        let (home, registry) = fixture("boxed");
        let driver = home.join("driver");
        fs::create_dir(&driver).expect("driver");
        fs::write(driver.join("step-1.txt"), b"steering evidence").expect("step");
        let boxed = home.join("box");
        fs::create_dir_all(boxed.join(".local/inbox")).expect("inbox");
        fs::create_dir(boxed.join(".local/outbox")).expect("outbox");
        let mut census = json!({"schema":1,"command":"census","loop":"alpha","admission":{"state":"paused"},"reservations":[],"retired_records":[{"ambiguous_journaled_names":[],"identities":{"driver":{"presence":"absent"}}}],"mail_migration":{"unattributed_names":[],"records":[{"worker_uid":4000,"record":home.join("reservation"),"record_sha256":"a".repeat(64),"mail_birth":null,"reconciliation_refusals":[],"homes":[{"path":boxed,"present":true,"required":true}],"exclusions":[{"path":driver}]}]}});
        let inventory = close(&home, &registry, &[("alpha".into(), Some(census.clone()))])
            .expect("closed native census");
        assert_eq!(inventory.workers.len(), 1);
        assert_eq!(inventory.workers[0].sources.len(), 2);
        assert_eq!(inventory.inert_leaves, vec![boxed.join(".local/outbox")]);
        inventory.verify_exclusions().expect("step retained");
        census["reservations"] = json!([{"phase":"running"}]);
        assert!(close(&home, &registry, &[("alpha".into(), Some(census.clone()))]).is_err());
        census["reservations"] = json!([]);
        census["mail_migration"]["records"][0]["reconciliation_refusals"] =
            json!(["legacy letters require reconciliation"]);
        assert!(close(&home, &registry, &[("alpha".into(), Some(census.clone()))]).is_err());
        let retained = home.join("retained-driver");
        fs::rename(&driver, &retained).expect("native driver retirement");
        census["mail_migration"]["records"][0]["reconciliation_refusals"] = json!([]);
        census["mail_migration"]["records"][0]["exclusions"] =
            json!([{"path":driver,"required":false},{"path":retained,"required":true}]);
        let retired = close(&home, &registry, &[("alpha".into(), Some(census.clone()))])
            .expect("retirement explains absent original driver");
        retired
            .verify_exclusions()
            .expect("retained driver remains unchanged");
        assert!(!retired.exclusions[0].present);
        fs::remove_file(retained.join("step-1.txt")).expect("remove step");
        assert!(retired.verify_exclusions().is_err());
        fs::remove_dir(&retained).expect("remove expected driver");
        assert!(close(&home, &registry, &[("alpha".into(), Some(census))]).is_err());
        assert!(inventory.verify_exclusions().is_err());
        fs::remove_dir_all(home).expect("cleanup");
    }
}
