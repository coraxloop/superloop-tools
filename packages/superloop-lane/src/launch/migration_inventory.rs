//! Derive migration sources from protected boxed-run history, never driver listings.
use super::*;

fn refusal(reason: impl Into<String>) -> LaneError {
    LaneError::input("mail-migration-inventory", reason)
}
fn path(value: &Value) -> Result<&Path, LaneError> {
    value
        .as_str()
        .map(Path::new)
        .ok_or_else(|| refusal("recorded path is absent"))
}
fn observation(path: &Path) -> Result<Value, LaneError> {
    match fs::symlink_metadata(path) {
        Ok(info) => {
            if !info.is_dir() {
                return Err(refusal(format!(
                    "{} is not a real home directory",
                    path.display()
                )));
            }
            Ok(
                json!({"path":path,"present":true,"device":info.dev(),"inode":info.ino(),"uid":info.uid(),"gid":info.gid(),"mode":info.mode() & 0o7777}),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(json!({"path":path,"present":false}))
        }
        Err(error) => Err(refusal(format!("{}: {error}", path.display()))),
    }
}
fn retained_home(home: &Path, run: &str, pair: &Value) -> Result<Value, LaneError> {
    let target = path(&pair["target"])?;
    let observed = observation(target)?;
    if target.parent() != home.parent() {
        return Err(refusal("retired home leaves its original parent"));
    }
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| refusal("retired home name encoding"))?;
    let suffix = name
        .strip_prefix(&format!(".retired-{run}-1-"))
        .ok_or_else(|| refusal("retired home lacks its home-slot identity"))?;
    let base = match suffix.split_once('.') {
        Some((base, collision))
            if !collision.is_empty()
                && !collision.starts_with('0')
                && collision.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            base
        }
        Some(_) => return Err(refusal("retired home collision suffix differs")),
        None => suffix,
    };
    let (device, inode) = base
        .split_once('-')
        .ok_or_else(|| refusal("retired home inode is absent"))?;
    let device = device
        .parse::<u64>()
        .map_err(|_| refusal("retired home device is malformed"))?;
    let inode = inode
        .parse::<u64>()
        .map_err(|_| refusal("retired home inode is malformed"))?;
    if observed["present"] == true && (observed["device"] != device || observed["inode"] != inode) {
        return Err(refusal(
            "retired home differs from its protected rename witness",
        ));
    }
    Ok(observed)
}
/// Derive all recorded home generations and exclusions under the census locks.
/// Missing homes remain missing expected state; an operator cannot turn that into
/// optional absence by omitting the corresponding source from a migration plan.
pub(super) fn row(
    owner_home: &Path,
    root: &Path,
    loop_name: &str,
    record_path: &Path,
    record: &Value,
) -> Result<Value, LaneError> {
    let run = record["run"]
        .as_str()
        .filter(|run| valid_run_name(run))
        .ok_or_else(|| refusal("run name is absent"))?;
    let home = owner_home
        .join(".cache/tmp")
        .join(format!("lane-{loop_name}-{run}"));
    let driver = root.join(run);
    if path(&record["plan"]["home"])? != home || path(&record["plan"]["driver_dir"])? != driver {
        return Err(refusal(
            "protected run paths differ from their loop and run",
        ));
    }
    let mut homes = Vec::new();
    let mut exclusions = vec![
        json!({"path":driver,"required":true,"reason":"driver step and brief evidence; never a mail source"}),
    ];
    let mut seen = BTreeSet::new();
    for (kind, journal) in std::iter::once(("current_retirement", &record["current_retirement"]))
        .chain(std::iter::once((
            "dead_preparation_retired",
            &record["dead_preparation_retired"],
        )))
        .chain(
            record["retry_retirements"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|journal| ("retry_retirements", journal)),
        )
    {
        if journal.is_null() {
            continue;
        }
        let pairs = journal["planned_paths"]
            .as_array()
            .ok_or_else(|| refusal("retirement journal has no planned paths"))?;
        for pair in pairs {
            let source = path(&pair["source"])?;
            if source == home {
                let mut observed = retained_home(&home, run, pair)?;
                let target = path(&pair["target"])?;
                if !seen.insert(target.to_path_buf()) {
                    return Err(refusal("home is attributed to two retirement journals"));
                }
                observed["journal"] = json!(kind);
                observed["required"] = json!(true);
                observed["stores"] =
                    json!([target.join(".local/inbox"), target.join(".local/outbox")]);
                homes.push(observed);
            } else if source == driver {
                exclusions[0]["required"] = json!(false);
                exclusions.push(json!({"path":path(&pair["target"])?,"required":true,"reason":"retained driver step and brief evidence; never a mail source"}));
            }
        }
    }
    if record["phase"] != "retired" {
        let mut current = observation(&home)?;
        current["journal"] = json!("current");
        current["required"] = json!(true);
        current["stores"] = json!([home.join(".local/inbox"), home.join(".local/outbox")]);
        homes.push(current);
    }
    let current_home_recorded = record["current_retirement"]["planned_paths"]
        .as_array()
        .is_some_and(|pairs| {
            pairs
                .iter()
                .any(|pair| pair["source"] == home.to_string_lossy().as_ref())
        });
    let mut refusals = Vec::new();
    if record["phase"] != "retired" {
        refusals.push("drain and retire this boxed run through the native retirement command before mail cutover");
    }
    if record["phase"] == "retired" && !current_home_recorded {
        refusals.push("missing expected current home; reconcile its history before mail cutover");
    }
    if homes.iter().any(|home| home["present"] != true) {
        refusals
            .push("missing expected home generation; reconcile its history before mail cutover");
    }
    let bytes = serde_json::to_vec(record).map_err(|error| refusal(error.to_string()))?;
    Ok(
        json!({"loop":loop_name,"run":run,"worker_uid":record["worker_uid"],"mail_birth":record["mail_birth"],"record":record_path,"record_sha256":loop_home::mail::journal::digest(&bytes),"homes":homes,"exclusions":exclusions,"reconciliation_refusals":refusals,"retirement":record["current_retirement"],"node_retirement":record["node_retirement"]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´claim:superlooplane:migration-inventory-retains-every-home-generation-and-excludes-driver-evidence´
    /// ´test:unit:migration-inventory-retains-every-home-generation-and-excludes-driver-evidence´
    #[test]
    fn migration_inventory_retains_every_home_generation_and_excludes_driver_evidence() {
        let fixture = tempfile::tempdir().expect("fixture");
        let owner = fixture.path();
        let parent = owner.join(".cache/tmp");
        fs::create_dir_all(&parent).expect("cache");
        let root = owner.join("runs");
        fs::create_dir(&root).expect("runs");
        let driver = root.join("R");
        let home = parent.join("lane-alpha-R");
        let mut pairs = Vec::new();
        for index in 0..2 {
            let stage = parent.join(format!("stage-{index}"));
            fs::create_dir(&stage).expect("home");
            let info = fs::metadata(&stage).expect("identity");
            let target = parent.join(format!(".retired-R-1-{}-{}", info.dev(), info.ino()));
            fs::rename(stage, &target).expect("retained home");
            pairs.push(json!({"source":home,"target":target}));
        }
        let record = json!({"run":"R","phase":"retired","plan":{"home":home,"driver_dir":driver},"current_retirement":{"planned_paths":[pairs[1],{"source":driver,"target":root.join("retained-driver")}]},"retry_retirements":[{"planned_paths":[pairs[0]]}]});
        let observed =
            row(owner, &root, "alpha", &root.join("record"), &record).expect("inventory");
        assert_eq!(observed["homes"].as_array().expect("homes").len(), 2);
        assert_eq!(
            observed["exclusions"]
                .as_array()
                .expect("driver exclusions")
                .len(),
            2
        );
        assert_eq!(observed["reconciliation_refusals"], json!([]));
        fs::remove_dir(path(&pairs[0]["target"]).expect("target")).expect("remove expected home");
        let missing =
            row(owner, &root, "alpha", &root.join("record"), &record).expect("missing evidence");
        assert_ne!(missing["reconciliation_refusals"], json!([]));
        let mut active = record;
        active["phase"] = json!("settled");
        assert_ne!(
            row(owner, &root, "alpha", &root.join("record"), &active).expect("active evidence")["reconciliation_refusals"],
            json!([])
        );
    }
}
