use crate::Result;
use std::ffi::OsString;
use std::path::PathBuf;

pub struct Config {
    pub store: PathBuf,
    pub operation: Operation,
}
pub enum Operation {
    Prune,
    Admit {
        source: PathBuf,
        manifest: PathBuf,
        name: String,
        keep: bool,
        quota: u64,
    },
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub fn parse() -> Result<Config> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().ok_or("usage: admit|prune --store ROOT")?;
    let mut values = std::collections::BTreeMap::<OsString, OsString>::new();
    let mut keep = false;
    while let Some(key) = args.next() {
        if key == "--keep-previous" && !keep {
            keep = true;
            continue;
        }
        if ![
            "--store",
            "--source",
            "--manifest",
            "--name",
            "--quota-bytes",
        ]
        .iter()
        .any(|v| key == *v)
        {
            return Err("usage: unknown or duplicate flag".into());
        }
        let value = args.next().ok_or("usage: missing option value")?;
        if values.insert(key, value).is_some() {
            return Err("usage: duplicate option".into());
        }
    }
    let store = values
        .remove(&OsString::from("--store"))
        .ok_or("usage: --store required")?
        .into();
    let operation = if command == "prune" && !keep && values.is_empty() {
        Operation::Prune
    } else if command == "admit" {
        let source = values
            .remove(&OsString::from("--source"))
            .ok_or("usage: --source required")?
            .into();
        let manifest = values
            .remove(&OsString::from("--manifest"))
            .ok_or("usage: --manifest required")?
            .into();
        let name = values
            .remove(&OsString::from("--name"))
            .ok_or("usage: --name required")?
            .into_string()
            .map_err(|_| "invalid-name")?;
        if !valid_name(&name) {
            return Err("invalid-name".into());
        }
        let quota =
            values
                .remove(&OsString::from("--quota-bytes"))
                .map_or(Ok(5_000_000_000), |v| {
                    v.to_str()
                        .ok_or("invalid-quota")?
                        .parse()
                        .map_err(|_| "invalid-quota")
                })?;
        Operation::Admit {
            source,
            manifest,
            name,
            keep,
            quota,
        }
    } else {
        return Err("usage: admit|prune --store ROOT".into());
    };
    Ok(Config { store, operation })
}
