//! Measure recorded sandbox roots against the current driver locks without writes.

use std::ffi::OsString;
use std::fs;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::driver::monitor_lock;

struct Request {
    runs_root: PathBuf,
    paths: Vec<PathBuf>,
}

impl Request {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        let [flag, root, paths @ ..] = args else {
            return Err("bound-roots-usage");
        };
        if flag != "--runs-root" || paths.is_empty() {
            return Err("bound-roots-usage");
        }
        let paths = paths.iter().map(PathBuf::from).collect::<Vec<_>>();
        if paths.iter().any(|path| {
            !path.is_absolute()
                || path.to_str().is_none()
                || fs::canonicalize(path)
                    .map_or(true, |canonical| canonical.as_os_str() != path.as_os_str())
        }) {
            return Err("bound-roots-path");
        }
        Ok(Self {
            runs_root: PathBuf::from(root),
            paths,
        })
    }
}

fn record_roots(bytes: &[u8]) -> Result<Vec<PathBuf>, &'static str> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "bound-roots-shape")?;
    let object = value.as_object().ok_or("bound-roots-shape")?;
    if object.len() != 2 || value["schema"].as_u64() != Some(1) {
        return Err("bound-roots-shape");
    }
    value["roots"]
        .as_array()
        .ok_or("bound-roots-shape")?
        .iter()
        .map(|root| {
            let root = PathBuf::from(root.as_str().ok_or("bound-roots-shape")?);
            if root.is_absolute() {
                Ok(root)
            } else {
                Err("bound-roots-shape")
            }
        })
        .collect()
}

fn run_evidence(run: &str, directory: &Path) -> (Value, bool) {
    let mut invalid = false;
    let mut locks = Vec::new();
    for name in [".codex-lane.lock", ".claude-lane.lock"] {
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                invalid = true;
                continue;
            }
            Ok(_) => {}
        }
        let measured = fs::metadata(&path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|metadata| metadata.modified().ok())
            .zip(
                fs::read(&path)
                    .ok()
                    .and_then(|bytes| monitor_lock::parse_lock(&bytes)),
            );
        if let Some((modified, (pid, child))) = measured {
            let live = monitor_lock::pid_live_from_proc(pid)
                || child.is_some_and(monitor_lock::pid_live_from_proc);
            locks.push(((live, modified, name), (name, pid, child, live)));
        } else {
            invalid = true;
        }
    }
    let lock = locks
        .into_iter()
        .max_by_key(|(key, _)| *key)
        .map(|(_, lock)| lock);
    (
        json!({
            "run": run,
            "lock": lock.map(|(name, _, _, _)| name),
            "driver_pid": lock.map(|(_, pid, _, _)| pid),
            "child_pid": lock.and_then(|(_, _, child, _)| child),
            "live": lock.is_some_and(|(_, _, _, live)| live),
        }),
        invalid,
    )
}

fn scan(request: &Request) -> Result<(Value, u8), &'static str> {
    let entries = fs::read_dir(&request.runs_root).map_err(|_| "bound-roots-read")?;
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "bound-roots-read")?;
        if entry.file_type().map_err(|_| "bound-roots-read")?.is_dir() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "bound-roots-name")?;
            directories.push((name, entry.path()));
        }
    }
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    let mut matches = vec![Vec::new(); request.paths.len()];
    let mut unrecorded = Vec::new();
    let mut live_runs = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    for (name, directory) in directories {
        let (evidence, invalid_lock) = run_evidence(&name, &directory);
        if invalid_lock {
            failures.push(json!({"kind": "bound-roots-lock", "run": name}));
        }
        let roots = match fs::read(directory.join("bound-roots.json")) {
            Ok(bytes) => record_roots(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if evidence["live"] == true {
                    unrecorded.push(evidence);
                }
                continue;
            }
            Err(_) => Err("bound-roots-read"),
        };
        match roots {
            Ok(roots) => {
                for (path, runs) in request.paths.iter().zip(&mut matches) {
                    if roots.iter().any(|root| root.starts_with(path)) {
                        runs.push(evidence.clone());
                        if evidence["live"] == true {
                            live_runs.insert(name.clone());
                        }
                    }
                }
            }
            Err(kind) => failures.push(json!({"kind": kind, "run": name})),
        }
    }
    let (refusal, status) = if !failures.is_empty() {
        (
            json!({"kind": failures[0]["kind"], "runs": failures.iter().map(|failure| failure["run"].clone()).collect::<Vec<_>>()}),
            1,
        )
    } else if !unrecorded.is_empty() {
        (
            json!({"kind": "bound-roots-unrecorded", "runs": unrecorded.iter().map(|run| run["run"].clone()).collect::<Vec<_>>()}),
            3,
        )
    } else if !live_runs.is_empty() {
        (json!({"kind": "bound-roots-live", "runs": live_runs}), 3)
    } else {
        (Value::Null, 0)
    };
    let report = json!({
        "schema": 1,
        "paths": request.paths.iter().zip(matches).map(|(path, runs)| json!({"path": path, "runs": runs})).collect::<Vec<_>>(),
        "unrecorded_live_runs": unrecorded,
        "verdict": if status == 0 { "clear" } else { "refused" },
        "refusal": refusal,
    });
    if status == 1 {
        Ok((
            json!({"schema": 1, "command": "superloop-lane bound-roots", "class": "runtime", "kind": report["refusal"]["kind"], "failures": failures, "evidence": report}),
            status,
        ))
    } else {
        Ok((report, status))
    }
}

fn diagnostic(kind: &str, status: u8) -> ExitCode {
    let report = json!({"schema": 1, "command": "superloop-lane bound-roots", "class": if status == 2 { "usage" } else { "runtime" }, "kind": kind});
    let _written = writeln!(std::io::stderr().lock(), "{report}");
    ExitCode::from(status)
}

/// Publish one clearance result, or a classed diagnostic, without changing runs.
pub fn command(args: &[OsString]) -> ExitCode {
    superloop_cli_common::install_json_panic_hook("superloop-lane bound-roots");
    if std::io::stdout().is_terminal() {
        return diagnostic("bound-roots-terminal", 2);
    }
    let request = match Request::parse(args) {
        Ok(request) => request,
        Err(kind) => return diagnostic(kind, 2),
    };
    let (report, status) = match scan(&request) {
        Ok(result) => result,
        Err(kind) => return diagnostic(kind, 1),
    };
    let published = if status == 1 {
        writeln!(std::io::stderr().lock(), "{report}")
    } else {
        writeln!(std::io::stdout().lock(), "{report}")
    };
    if published.is_err() {
        return diagnostic("bound-roots-publication", 1);
    }
    ExitCode::from(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().expect("fixture")
    }

    fn run(root: &Path, name: &str, record: Option<Value>, pid: Option<u32>) {
        let directory = root.join(name);
        fs::create_dir(&directory).expect("run directory");
        if let Some(record) = record {
            fs::write(directory.join("bound-roots.json"), record.to_string()).expect("record");
        }
        if let Some(pid) = pid {
            fs::write(directory.join(".codex-lane.lock"), format!("{pid}\n")).expect("lock");
        }
    }

    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("child");
        let pid = child.id();
        assert!(child.wait().expect("reap").success());
        assert!(!monitor_lock::pid_live_from_proc(pid));
        pid
    }

    fn inspect(root: &Path) -> (Value, u8) {
        scan(&Request {
            runs_root: root.into(),
            paths: vec!["/clone".into(), "/clon".into()],
        })
        .expect("scan")
    }

    /// A live driver blocks an ancestor of its recorded root, without matching a string prefix.
    ///
    /// # Panics
    /// Panics only if fixture setup or the clearance assertions fail.
    ///
    /// ´test:unit:bound-roots-live-driver-blocks-ancestor´
    #[test]
    fn bound_roots_live_driver_blocks_ancestor() {
        let root = fixture();
        run(
            root.path(),
            "live",
            Some(json!({"schema":1,"roots":["/clone/.git"]})),
            Some(std::process::id()),
        );
        let (report, status) = inspect(root.path());
        assert_eq!(status, 3);
        assert_eq!(
            report["refusal"],
            json!({"kind":"bound-roots-live","runs":["live"]})
        );
        assert_eq!(
            report["paths"][0]["runs"],
            json!([{"run":"live","lock":".codex-lane.lock","driver_pid":std::process::id(),"child_pid":null,"live":true}])
        );
        assert_eq!(report["paths"][1]["runs"], json!([]));
        assert_eq!(report["unrecorded_live_runs"], json!([]));
    }

    /// Dead and absent driver locks retain matching evidence but permit clearance.
    ///
    /// # Panics
    /// Panics only if fixture setup, child reaping or the clearance assertions fail.
    ///
    /// ´test:unit:bound-roots-dead-and-absent-locks-clear´
    #[test]
    fn bound_roots_dead_and_absent_locks_clear() {
        let root = fixture();
        let pid = dead_pid();
        for (name, pid) in [("dead", Some(pid)), ("no-lock", None)] {
            run(
                root.path(),
                name,
                Some(json!({"schema":1,"roots":["/clone"]})),
                pid,
            );
        }
        run(root.path(), "empty", None, None);
        let (report, status) = inspect(root.path());
        assert_eq!(status, 0);
        assert_eq!(report["verdict"], "clear");
        assert_eq!(report["refusal"], Value::Null);
        assert_eq!(
            report["paths"][0]["runs"],
            json!([
                {"run":"dead","lock":".codex-lane.lock","driver_pid":pid,"child_pid":null,"live":false},
                {"run":"no-lock","lock":null,"driver_pid":null,"child_pid":null,"live":false}
            ])
        );
        assert_eq!(report["unrecorded_live_runs"], json!([]));
    }

    /// Unrecorded live drivers prevent clearance even when matching evidence also exists.
    ///
    /// # Panics
    /// Panics only if fixture setup or the refusal assertions fail.
    ///
    /// ´test:unit:bound-roots-unrecorded-live-driver-refuses´
    #[test]
    fn bound_roots_unrecorded_live_driver_refuses() {
        let root = fixture();
        run(root.path(), "unknown", None, Some(std::process::id()));
        run(
            root.path(),
            "known",
            Some(json!({"schema":1,"roots":["/clone"]})),
            Some(std::process::id()),
        );
        let (report, status) = inspect(root.path());
        assert_eq!(status, 3);
        assert_eq!(
            report["refusal"],
            json!({"kind":"bound-roots-unrecorded","runs":["unknown"]})
        );
        assert_eq!(
            report["unrecorded_live_runs"],
            json!([{"run":"unknown","lock":".codex-lane.lock","driver_pid":std::process::id(),"child_pid":null,"live":true}])
        );
        assert_eq!(report["paths"][0]["runs"][0]["run"], "known");
    }

    /// Invalid record syntax and every driver shape violation prevent clearance without losing evidence.
    ///
    /// # Panics
    /// Panics only if fixture setup or the validation assertions fail.
    ///
    /// ´test:unit:bound-roots-malformed-record-preserves-evidence´
    #[test]
    fn bound_roots_malformed_record_preserves_evidence() {
        for bytes in [
            "{",
            "[]",
            r#"{"schema":2,"roots":[]}"#,
            r#"{"schema":1}"#,
            r#"{"schema":1,"roots":[],"extra":0}"#,
            r#"{"schema":1,"roots":null}"#,
            r#"{"schema":1,"roots":[1]}"#,
            r#"{"schema":1,"roots":["relative"]}"#,
        ] {
            assert_eq!(
                record_roots(bytes.as_bytes()).expect_err("invalid record"),
                "bound-roots-shape"
            );
        }
        let root = fixture();
        run(
            root.path(),
            "malformed",
            Some(json!({"schema":1,"roots":["relative"]})),
            None,
        );
        run(
            root.path(),
            "known",
            Some(json!({"schema":1,"roots":["/clone"]})),
            Some(std::process::id()),
        );
        let (report, status) = inspect(root.path());
        assert_eq!(status, 1);
        assert_eq!(report["kind"], "bound-roots-shape");
        assert_eq!(
            report["failures"],
            json!([{"kind":"bound-roots-shape","run":"malformed"}])
        );
        assert_eq!(report["evidence"]["verdict"], "refused");
        assert_eq!(report["evidence"]["paths"][0]["runs"][0]["run"], "known");
    }

    /// A surviving sandbox child blocks clearance even after its driver dies.
    ///
    /// # Panics
    /// Panics only if fixture setup or liveness assertions fail.
    ///
    /// ´test:unit:bound-roots-live-child-under-dead-driver-refuses´
    #[test]
    fn bound_roots_live_child_under_dead_driver_refuses() {
        let root = fixture();
        let dead = dead_pid();
        let live = std::process::id();
        run(
            root.path(),
            "orphan",
            Some(json!({"schema":1,"roots":["/clone"]})),
            Some(dead),
        );
        fs::write(
            root.path().join("orphan/.codex-lane.lock"),
            format!("{dead}\n{live}\n"),
        )
        .expect("child lock");
        // A competing dead lock must not hide the live sandbox child.
        fs::write(
            root.path().join("orphan/.claude-lane.lock"),
            format!("{dead}\n"),
        )
        .expect("dead lock");
        let (report, status) = inspect(root.path());
        assert_eq!(status, 3);
        assert_eq!(
            report["refusal"],
            json!({"kind":"bound-roots-live","runs":["orphan"]})
        );
        assert_eq!(
            report["paths"][0]["runs"][0],
            json!({"run":"orphan","lock":".codex-lane.lock","driver_pid":dead,"child_pid":live,"live":true})
        );
    }

    /// Empty, malformed and unreadable locks refuse while valid matching evidence survives.
    ///
    /// # Panics
    /// Panics only if fixture setup or refusal assertions fail.
    ///
    /// ´test:unit:bound-roots-unmeasured-lock-refuses´
    #[test]
    fn bound_roots_unmeasured_lock_refuses() {
        for bytes in ["", "garbage\n"] {
            let root = fixture();
            run(
                root.path(),
                "uncertain",
                Some(json!({"schema":1,"roots":["/clone"]})),
                Some(std::process::id()),
            );
            fs::write(root.path().join("uncertain/.claude-lane.lock"), bytes)
                .expect("invalid lock");
            let (report, status) = inspect(root.path());
            assert_eq!(status, 1);
            assert_eq!(report["kind"], "bound-roots-lock");
            assert_eq!(
                report["failures"],
                json!([{"kind":"bound-roots-lock","run":"uncertain"}])
            );
            assert_eq!(report["evidence"]["paths"][0]["runs"][0]["live"], true);
        }
        let root = fixture();
        run(root.path(), "unreadable", None, None);
        std::os::unix::fs::symlink(
            root.path().join("missing"),
            root.path().join("unreadable/.codex-lane.lock"),
        )
        .expect("dangling lock");
        let (report, status) = inspect(root.path());
        assert_eq!(status, 1);
        assert_eq!(
            report["failures"],
            json!([{"kind":"bound-roots-lock","run":"unreadable"}])
        );
    }

    /// Only an existing canonical spelling is admitted as a clearance path.
    ///
    /// # Panics
    /// Panics only if fixture setup or path validation assertions fail.
    ///
    /// ´test:unit:bound-roots-noncanonical-path-refuses´
    #[test]
    fn bound_roots_noncanonical_path_refuses() {
        let root = fixture();
        let canonical = fs::canonicalize(root.path()).expect("canonical fixture");
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&canonical, &alias).expect("symlink");
        for path in [
            alias,
            canonical
                .join("..")
                .join(canonical.file_name().expect("name")),
            canonical.join("missing"),
        ] {
            let args = [
                OsString::from("--runs-root"),
                canonical.clone().into_os_string(),
                path.into_os_string(),
            ];
            assert_eq!(Request::parse(&args).err(), Some("bound-roots-path"));
        }
        let args = [
            OsString::from("--runs-root"),
            canonical.clone().into_os_string(),
            canonical.into_os_string(),
        ];
        assert!(Request::parse(&args).is_ok());
    }
}
