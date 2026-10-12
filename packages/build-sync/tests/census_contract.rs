#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

// Serialize stub writers with test-side spawns so a fork cannot inherit another writer.
// Release the lock after spawn has completed exec, before waiting for the child.
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn write_executable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut writer = fs::File::create(path)?;
    writer.write_all(bytes)?;
    writer.sync_all()?;
    drop(writer);
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn output_serialized(command: &mut Command) -> io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = {
        let _guard = STUB_PROCESS_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let started = Instant::now();
        loop {
            match command.spawn() {
                Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                    if started.elapsed() >= Duration::from_millis(500) {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                result => break result?,
            }
        }
    };
    child.wait_with_output()
}

struct Fixture {
    root: tempfile::TempDir,
    metadata: Value,
}

fn ledger(path: &Path, rows: &[Value]) {
    let body = rows
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("dependency_ledger += ['''\n{body}\n''']\n")).expect("ledger");
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
        fs::write(root.path().join("declared-paths.txt"), "").expect("evaluated paths");
        fs::create_dir(root.path().join("meson-info")).expect("Meson introspection");
        fs::write(root.path().join("meson-info/intro-tests.json"), "[]")
            .expect("Meson test environments");
        fs::write(root.path().join("meson-info/intro-installed.json"), "{}")
            .expect("installed outputs");
        fs::write(root.path().join("meson-info/intro-buildoptions.json"), "[]")
            .expect("build options");
        fs::create_dir(root.path().join("adr")).expect("records");
        fs::write(root.path().join("adr/036-tools-dependency-concept.md"), "|Present source|Destination and tier|\n|---|---|\n|`base`, `tool`|fixture packages|\n\n|Package|Tier and domain|Accountable owner|Consumers|\n|-------|---------------|-----------------|---------|\n|`base`|Fixture domain|BASE|tool|\n\n").expect("package destinations");
        fs::write(
            root.path()
                .join("adr/033-tool-executables-names-and-versions.md"),
            "|Present name|Successor|Installs to|\n|---|---|---|\n\n",
        )
        .expect("successor table");
        fs::create_dir(root.path().join("packages")).expect("packages");
        fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = [\"packages/base\", \"packages/tool\"]\n[workspace.package]\nedition = \"2024\"\n[workspace.dependencies]\nbase = { path = \"packages/base\" }\npetgraph = { version = \"=0.8.3\", features = [\"serde-1\"] }\n").expect("workspace");
        fs::write(root.path().join("Cargo.lock"), "version = 4\n[[package]]\nname = \"base\"\nversion = \"0.1.0\"\n[[package]]\nname = \"tool\"\nversion = \"0.1.0\"\ndependencies = [\"base\", \"petgraph\"]\n[[package]]\nname = \"petgraph\"\nversion = \"0.8.3\"\nsource = \"registry+fixture\"\nchecksum = \"reviewed\"\n").expect("lock");
        let mut packages = Vec::new();
        let mut readme = String::new();
        for (name, tier) in [("base", 0), ("tool", 2)] {
            let relative = format!("packages/{name}/Cargo.toml");
            let directory = root.path().join("packages").join(name);
            fs::create_dir(&directory).expect("member");
            let dependencies = if name == "tool" {
                "base.workspace = true\npetgraph.workspace = true\n"
            } else {
                ""
            };
            fs::write(directory.join("Cargo.toml"), format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n[package.metadata.superloop]\ntier = {tier}\nrelease-group = \"{name}\"\n[dependencies]\n{dependencies}")).expect("member manifest");
            ledger(
                &directory.join("meson.build"),
                &[json!({"kind":"package","name":name,
                "tier":tier,"release_group":name,"manifest":relative,"version_authority":relative})],
            );
            packages.push(json!({"id":name,"name":name,"version":"0.1.0","source":null,
                "manifest_path":root.path().join(&relative),"targets":[],"metadata":{"superloop":{"tier":tier,"release-group":name}}}));
            writeln!(readme, "|`{name}`|{tier}|`{name}`|").expect("table");
        }
        fs::write(root.path().join("packages/README.md"), readme).expect("README");
        packages.push(json!({"id":"petgraph","name":"petgraph","version":"0.8.3","source":"registry+fixture"}));
        ledger(
            &root.path().join("meson.build"),
            &[
                json!({"kind":"accountable-owner","package":"base","owner":"BASE"}),
                json!({"kind":"accountable-owner","package":"tool","owner":"TOOL"}),
                json!({"kind":"admission","name":"petgraph","owner":"ORCHESTRATORHOOK","reason":"state graphs"}),
                json!({"kind":"closure","name":"petgraph","version":"0.8.3","source":"registry+fixture","checksum":"reviewed","direct_roots":["petgraph"],"owners":["ORCHESTRATORHOOK"],"reason":"state graphs"}),
            ],
        );
        let ledger_path = root.path().join("meson.build");
        let mut source = fs::read_to_string(&ledger_path).expect("ledger");
        source.push_str("\nrust_version_roster = {\n}\nscript_version_roster = {\n}\npassthrough_roster = {\n}\n");
        fs::write(ledger_path, source).expect("rosters");
        let metadata = json!({"workspace_members":["base","tool"],"packages":packages,
        "resolve":{"nodes":[
            {"id":"base","deps":[],"features":[]},
            {"id":"tool","deps":[
                {"pkg":"base","dep_kinds":[{"kind":null,"target":null}]},
                {"pkg":"petgraph","dep_kinds":[{"kind":null,"target":null}]}
            ],"features":[]},
            {"id":"petgraph","deps":[],"features":["serde-1"]}
        ]}});
        let cargo = root.path().join("cargo-fixture");
        write_executable(&cargo, b"#!/bin/sh\n[ \"$*\" = 'metadata --locked --format-version 1' ] || exit 19\ncat metadata.json\n").expect("cargo fixture");
        Self { root, metadata }
    }

    fn run(&self) -> Value {
        self.run_at(self.root.path(), None)
    }

    fn run_at(&self, build: &Path, expected_error: Option<&str>) -> Value {
        fs::write(
            self.root.path().join("metadata.json"),
            self.metadata.to_string(),
        )
        .expect("metadata");
        let report = self.root.path().join("report.json");
        if report.exists() {
            fs::remove_file(&report).expect("remove prior report before the next invocation");
        }
        let mut configured = Vec::new();
        for relative in [
            "meson.build",
            "packages/base/meson.build",
            "packages/tool/meson.build",
        ] {
            let source =
                fs::read_to_string(self.root.path().join(relative)).expect("source ledger");
            for block in source.split("dependency_ledger += ['''\n").skip(1) {
                configured.push(
                    block
                        .split_once("\n''']")
                        .expect("ledger terminator")
                        .0
                        .to_owned(),
                );
            }
        }
        let ledger = build.join("dependency-ledger.jsonl");
        fs::write(&ledger, configured.join("\n")).expect("configured ledger");
        let output = output_serialized(
            Command::new(env!("CARGO_BIN_EXE_build-sync"))
                .arg("census")
                .arg("--root")
                .arg(self.root.path())
                .arg("--cargo")
                .arg(self.root.path().join("cargo-fixture"))
                .arg("--ledger")
                .arg(ledger)
                .arg("--report")
                .arg(&report),
        )
        .expect("built census");
        let bytes = fs::read(&report).unwrap_or_else(|error| {
            panic!(
                "read {}: {error}; status={}; stdout={}; stderr={}",
                report.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        });
        let report: Value = serde_json::from_slice(&bytes).expect("JSON");
        if let Some(expected) = expected_error {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                report["error"]
                    .as_str()
                    .expect("refusal")
                    .contains(expected),
                "{report}"
            );
            return report;
        }
        assert!(
            report.get("error").is_none(),
            "census did not finish: {report}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let expected_status = i32::from(
            !report["unaccounted"]
                .as_array()
                .expect("findings")
                .is_empty(),
        );
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        report
    }
}

/// The built command resolves package identities and accepts a fully accounted fixture graph.
/// ´test:integration:census-reports-resolved-graph´
#[test]
fn census_reports_resolved_graph() {
    let report = Fixture::new().run();
    assert_eq!(report["packages"].as_array().expect("packages").len(), 2);
    assert_eq!(report["tier_debt"], json!([]));
    assert_eq!(report["unexplained_lock"], json!([]));
    assert_eq!(report["unaccounted"].as_array().expect("findings").len(), 0);
    assert_eq!(report["packages"][0]["accountable_owner"], "BASE");
    assert_eq!(report["packages"][0]["consumers"], json!(["tool"]));
    assert_eq!(report["packages"][1]["accountable_owner"], "TOOL");
    assert_eq!(report["packages"][1]["consumers"], json!([]));
}

/// Consumers include every dependency kind but name each source only once.
/// ´test:integration:census-derives-consumers-from-all-edge-kinds´
#[test]
fn census_derives_consumers_from_all_edge_kinds() {
    let mut fixture = Fixture::new();
    fixture.metadata["resolve"]["nodes"][1]["deps"][0]["dep_kinds"] = json!([
        {"kind":null,"target":null}, {"kind":"dev","target":null},
        {"kind":"build","target":"cfg(unix)"}
    ]);
    let report = fixture.run();
    assert_eq!(report["unaccounted"], json!([]));
    assert_eq!(report["packages"][0]["consumers"], json!(["tool"]));
    assert_eq!(report["internal_edges"].as_array().expect("edges").len(), 3);
    fixture.metadata["resolve"]["nodes"][1]["deps"][0]["pkg"] = json!("petgraph");
    assert_eq!(fixture.run()["packages"][0]["consumers"], json!([]));
}

/// Missing, invalid, duplicate and stale accountability rows are findings.
/// ´test:integration:census-refuses-unaccounted-owners´
#[test]
fn census_refuses_unaccounted_owners() {
    for replacement in [json!(null), json!(""), json!("lowercase")] {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("meson.build");
        let source = fs::read_to_string(&path).expect("ledger");
        fs::write(
            path,
            source.replace("\"owner\":\"BASE\"", &format!("\"owner\":{replacement}")),
        )
        .expect("invalid owner");
        assert!(
            fixture.run()["unaccounted"]
                .to_string()
                .contains("missing or invalid accountable owner: base")
        );
    }
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let source = fs::read_to_string(&path).expect("ledger");
    fs::write(
        &path,
        source.replace("\"package\":\"base\"", "\"package\":\"absent\""),
    )
    .expect("stale owner");
    let report = fixture.run();
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("missing or invalid accountable owner: base")
    );
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("stale accountable owner: absent")
    );
    fs::write(path, format!("{source}\ndependency_ledger += ['''\n{{\"kind\":\"accountable-owner\",\"package\":\"base\",\"owner\":\"OTHER\"}}\n''']\n")).expect("duplicate owner");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("duplicate accountable owner: base")
    );
}

/// An omitted package must not hide an independent owner finding.
///
/// # Panics
/// Panics only if fixture setup or the findings assertions fail.
/// ´test:integration:census-retains-unaccounted-package-and-owner-findings´
#[test]
fn census_retains_unaccounted_package_and_owner_findings() {
    let fixture = Fixture::new();
    ledger(&fixture.root.path().join("packages/base/meson.build"), &[]);
    let path = fixture.root.path().join("meson.build");
    let source = fs::read_to_string(&path).expect("ledger");
    fs::write(
        path,
        source.replace("\"owner\":\"TOOL\"", "\"owner\":\"lowercase\""),
    )
    .expect("invalid independent owner");
    let report = fixture.run();
    let findings = report["unaccounted"].as_array().expect("measured findings");
    assert!(findings.contains(&json!("unaccounted package: base")));
    assert!(findings.contains(&json!("missing or invalid accountable owner: tool")));
}

/// A newly introduced sideways source edge refuses even when both packages carry tiers.
/// ´test:integration:census-refuses-unadmitted-tier-edge´
#[test]
fn census_refuses_unadmitted_tier_edge() {
    let mut fixture = Fixture::new();
    fixture.metadata["packages"][1]["metadata"]["superloop"]["tier"] = json!(0);
    let report = fixture.run();
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("unadmitted tier edge: tool -> base")
    );
}

/// A declaration cannot restore a tier exception after the lane merge.
/// ´test:integration:census-refuses-retired-tier-debt-declarations´
#[test]
fn census_refuses_retired_tier_debt_declarations() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    source.push_str("\ndependency_ledger += ['''\n{\"kind\":\"tier-debt\",\"source\":\"tool\",\"target\":\"base\",\"dependency_kind\":\"dev\",\"bite\":10}\n''']\n");
    fs::write(path, source).expect("debt declaration");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("tier debt declarations are retired")
    );
}

/// A changed lockfile checksum needs a reviewed closure update rather than reachability alone.
/// ´test:integration:census-refuses-unreviewed-lock-change´
#[test]
fn census_refuses_unreviewed_lock_change() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("Cargo.lock");
    let source = fs::read_to_string(&path)
        .expect("lock")
        .replace("reviewed", "changed");
    fs::write(path, source).expect("changed lock");
    assert!(
        fixture.run()["unexplained_lock"]
            .to_string()
            .contains("petgraph 0.8.3")
    );
}

/// Target-specific dependency features cannot bypass the workspace feature authority.
/// ´test:integration:census-refuses-target-local-features´
#[test]
fn census_refuses_target_local_features() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("packages/tool/Cargo.toml");
    let mut source = fs::read_to_string(&path).expect("manifest");
    source.push_str("\n[target.'cfg(unix)'.dev-dependencies]\npetgraph = { workspace = true, features = [\"rayon\"] }\n");
    fs::write(path, source).expect("target dependency");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("dev-dependencies.petgraph must inherit")
    );
}

/// A newly introduced process constructor cannot silently escape the declared call inventory.
/// ´test:integration:census-refuses-unregistered-process-constructor´
#[test]
fn census_refuses_unregistered_process_constructor() {
    let fixture = Fixture::new();
    let directory = fixture.root.path().join("packages/tool/src");
    fs::create_dir(&directory).expect("source directory");
    fs::write(
        directory.join("lib.rs"),
        "fn run() { std::process::Command::new(\"git\").status(); }\n",
    )
    .expect("source");
    let report = fixture.run();
    assert_eq!(report["calls"].as_array().expect("calls").len(), 1);
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("unaccounted executable call:")
    );
}

/// Quoted fixture programs are not parsed as Rust call sites in their surrounding source.
/// ´test:integration:census-keeps-quoted-programs-out-of-rust-call-inventory´
#[test]
fn census_keeps_quoted_programs_out_of_rust_call_inventory() {
    let fixture = Fixture::new();
    let directory = fixture.root.path().join("packages/tool/src");
    fs::create_dir(&directory).expect("source directory");
    fs::write(
        directory.join("lib.rs"),
        "const TEXT: &str = r#\"Command::new(\"git\")\"#;\n",
    )
    .expect("quoted source");
    assert_eq!(fixture.run()["calls"], json!([]));
}

/// New successor rows require a ledger disposition even before their bite lands.
/// ´test:integration:census-refuses-unaccounted-successor´
#[test]
fn census_refuses_unaccounted_successor() {
    let fixture = Fixture::new();
    fs::write(
        fixture
            .root
            .path()
            .join("adr/033-tool-executables-names-and-versions.md"),
        "|Present name|Successor|Installs to|\n|---|---|---|\n|extra|next|bin|\n\n",
    )
    .expect("successor");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unaccounted successor row:")
    );
}

/// The package destination table cannot omit a member measured by Cargo.
/// ´test:integration:census-refuses-missing-package-destination´
#[test]
fn census_refuses_missing_package_destination() {
    let fixture = Fixture::new();
    fs::write(
        fixture
            .root
            .path()
            .join("adr/036-tools-dependency-concept.md"),
        "|Present source|Destination and tier|\n|---|---|\n|`base`|fixture|\n\n|Package|Tier and domain|Accountable owner|Consumers|\n|-------|---------------|-----------------|---------|\n\n",
    )
    .expect("destination");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("package lacks a recorded destination: tool")
    );
}

/// A Cargo binary absent from the version roster has no publishable identity.
/// ´test:integration:census-refuses-unregistered-binary´
#[test]
fn census_refuses_unregistered_binary() {
    let mut fixture = Fixture::new();
    fixture.metadata["packages"][1]["targets"] = json!([{"name":"extra","kind":["bin"]}]);
    assert!(fixture.run()["unaccounted"].to_string().contains("extra"));
}

/// Unit templates are executable payloads even when their suffix is configuration input.
/// ´test:integration:census-refuses-unregistered-unit-template´
#[test]
fn census_refuses_unregistered_unit_template() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.path().join("packages/tool/worker.service.in"),
        "[Service]\nExecStart=@BINDIR@/tool\n",
    )
    .expect("unit template");
    let report = fixture.run();
    assert_eq!(report["payloads"][0]["form"], "unit-template");
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("unaccounted executable payload:")
    );
}

/// A misspelled ledger kind cannot silently bypass the relevant check.
/// ´test:integration:census-refuses-unknown-ledger-kind´
#[test]
fn census_refuses_unknown_ledger_kind() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("packages/tool/meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    source.push_str("\ndependency_ledger += ['''\n{\"kind\":\"cal\"}\n''']\n");
    fs::write(path, source).expect("unknown kind");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unknown dependency ledger kind: cal")
    );
}

/// Renaming the Command import must not hide a process edge from the census.
/// ´test:integration:census-finds-renamed-process-constructor´
#[test]
fn census_finds_renamed_process_constructor() {
    let fixture = Fixture::new();
    let directory = fixture.root.path().join("packages/tool/src");
    fs::create_dir(&directory).expect("source directory");
    fs::write(
        directory.join("lib.rs"),
        "use std::process::Command as Runner;\nfn run() { Runner::new(\"git\").status(); }\n",
    )
    .expect("aliased source");
    assert_eq!(fixture.run()["calls"].as_array().expect("calls").len(), 1);
}

/// A metadata launch refusal retains the actual production diagnostic at the requested path.
/// # Panics
/// Panics only if fixture setup fails or the built census loses its refusal report.
/// ´test:integration:census-retains-report-before-metadata-can-start´
#[test]
fn census_retains_report_before_metadata_can_start() {
    let fixture = Fixture::new();
    fixture.run();
    let report = fixture.root.path().join("report.json");
    fs::remove_file(&report).expect("remove successful report");
    let missing = fixture.root.path().join("missing-cargo");
    let output = output_serialized(
        Command::new(env!("CARGO_BIN_EXE_build-sync"))
            .arg("census")
            .arg("--root")
            .arg(fixture.root.path())
            .arg("--cargo")
            .arg(&missing)
            .arg("--ledger")
            .arg(fixture.root.path().join("dependency-ledger.jsonl"))
            .arg("--report")
            .arg(&report),
    )
    .expect("built census");
    assert_eq!(output.status.code(), Some(1));
    let retained: Value = serde_json::from_slice(&fs::read(&report).expect("retained refusal"))
        .expect("refusal JSON");
    assert_eq!(retained["schema"], 1);
    assert_eq!(retained["complete"], false);
    let reason = retained["error"].as_str().expect("refusal reason");
    assert!(reason.starts_with("cargo metadata:"), "{retained}");
    assert!(reason.contains("No such file or directory"), "{retained}");
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostic.contains("cargo metadata"), "{diagnostic}");
}

/// Direct native exec calls require a declared edge even without a Command builder.
/// ´test:integration:census-finds-native-exec´
#[test]
fn census_finds_native_exec() {
    let fixture = Fixture::new();
    let directory = fixture.root.path().join("packages/tool/src");
    fs::create_dir(&directory).expect("source directory");
    fs::write(
        directory.join("lib.rs"),
        "fn run() { unsafe { libc::execve(program, argv, env); } }\n",
    )
    .expect("native source");
    assert_eq!(fixture.run()["calls"][0]["form"], "native-process-exec");
}

/// A new native install destination must be represented in the dependency ledger.
/// ´test:integration:census-refuses-unaccounted-native-install´
#[test]
fn census_refuses_unaccounted_native_install() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.path().join("meson-info/intro-installed.json"),
        json!({fixture.root.path().join("tool").display().to_string():"/prefix/bin/tool"})
            .to_string(),
    )
    .expect("native output");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unaccounted installation: native:/prefix/bin/tool")
    );
}

/// Migration map outputs are measured even when the configured domain does not install them.
/// ´test:integration:census-refuses-unaccounted-map-install´
#[test]
fn census_refuses_unaccounted_map_install() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.path().join("maps")).expect("maps");
    fs::write(fixture.root.path().join("maps/bin.toml"),
        "root = \"~/.local/bin\"\n[[targets]]\nkind = \"build\"\noutput = \"tool\"\ndestination = \"tool\"\nmode = \"0755\"\n").expect("map");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unaccounted installation: map:~/.local/bin/tool")
    );
}

fn document_fixture(map: Option<&str>, destination: &str) -> Fixture {
    let fixture = Fixture::new();
    let root = fixture.root.path();
    fs::create_dir_all(root.join("docs/arch")).expect("architecture directory");
    fs::create_dir_all(root.join("docs/spec")).expect("specification directory");
    fs::write(
        root.join("docs/meson.build"),
        "# docs_prose = files('arch/comment.md')\nexample = '''docs_prose = files('arch/string.md')'''\ndocs_prose = files(\n  'arch/example.md', # actual document\n  'integration.md',\n)\ndocs_prose += files('spec/example.md')\n",
    )
    .expect("document declarations");
    fs::write(
        root.join("declared-paths.txt"),
        "docs/arch/example.md\ndocs/spec/example.md\ndocs/integration.md\ndocs/arch/diagram.svg\n",
    )
    .expect("evaluated document paths");
    let mut source = fs::read_to_string(root.join("meson.build")).expect("source ledger");
    let mut targets = Vec::new();
    for document in ["docs/arch/example.md", "docs/spec/example.md"] {
        fs::write(root.join(document), "# Example\n").expect("document");
        let target = json!({"kind":"copy","source":document,
            "destination":format!("{destination}{document}"),"mode":"0644"});
        if let Some(map) = map {
            let row = json!({"kind":"installation","route":"map","declaration":map,
                "destination":format!("~/.local/share/superloop-tools/{destination}{document}"),
                "target":target,"registry":null,"owner":"fixture"});
            writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']")
                .expect("installation ledger");
        }
        targets.push(target);
    }
    fs::write(root.join("meson.build"), source).expect("installation declarations");
    if let Some(map) = map {
        fs::create_dir(root.join("maps")).expect("maps");
        let value = json!({"root":"~/.local/share/superloop-tools","targets":targets});
        fs::write(root.join(map), toml::to_string(&value).expect("map TOML"))
            .expect("document map");
    }
    fixture
}

/// Missing share-map coverage refuses both architecture and specification documents.
///
/// # Panics
/// Panics only if fixture setup or census execution fails, or coverage is not enforced.
/// ´test:integration:census-refuses-uninstalled-docs-prose´
#[test]
fn census_refuses_uninstalled_docs_prose() {
    for (map, destination) in [
        (None, ""),
        (Some("maps/other.toml"), ""),
        (Some("maps/share-map.toml"), "elsewhere/"),
    ] {
        let fixture = document_fixture(map, destination);
        let report = fixture.run();
        let findings = report["unaccounted"].as_array().expect("findings");
        assert_eq!(findings.len(), 2, "{report}");
        for document in ["docs/arch/example.md", "docs/spec/example.md"] {
            assert!(findings.contains(&json!(format!(
                "docs-prose-uninstalled: {document} declared in declared-paths.txt has no installation in maps/share-map.toml"
            ))));
        }
    }
}

/// Matching share-map rows admit documents without expanding coverage to other prose.
///
/// # Panics
/// Panics only if fixture setup or census execution fails, or installed documents refuse.
/// ´test:integration:census-admits-installed-docs-prose´
#[test]
fn census_admits_installed_docs_prose() {
    let fixture = document_fixture(Some("maps/share-map.toml"), "");
    assert_eq!(fixture.run()["unaccounted"], json!([]));
}

/// Source inclusion cannot bypass dependency accounting by avoiding a Cargo edge.
/// ´test:integration:census-refuses-unaccounted-source-import´
#[test]
fn census_refuses_unaccounted_source_import() {
    let fixture = Fixture::new();
    for package in ["base", "tool"] {
        fs::create_dir(fixture.root.path().join(format!("packages/{package}/src")))
            .expect("sources");
    }
    fs::write(
        fixture.root.path().join("packages/base/src/lib.rs"),
        "pub fn shared() {}\n",
    )
    .expect("base source");
    fs::write(
        fixture.root.path().join("packages/tool/src/lib.rs"),
        "#[path = \"../../base/src/lib.rs\"]\nmod shared;\n",
    )
    .expect("source import");
    let report = fixture.run();
    assert_eq!(report["source_imports"][0]["target"], "base");
    assert!(
        report["unaccounted"]
            .to_string()
            .contains("unaccounted source import:")
    );
}

/// A shared-file contract must name a real reader and retain its source evidence.
/// ´test:integration:census-refuses-stale-data-contract´
#[test]
fn census_refuses_stale_data_contract() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("packages/tool/meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    let row = json!({"kind":"data","identity":"state","writer":"tool","readers":["missing"],
        "format_authority":"packages/README.md","format_contract":"fixture state","owner":"fixture",
        "sites":[{"path":"packages/README.md","anchor":"absent format marker"}]});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("declaration");
    fs::write(path, source).expect("ledger");
    let findings = fixture.run()["unaccounted"].to_string();
    assert!(findings.contains("unknown participant: missing"));
    assert!(findings.contains("stale source anchor"));
}

/// Shell release groups must agree with their one Meson version authority.
/// ´test:integration:census-refuses-shell-group-drift´
#[test]
fn census_refuses_shell_group_drift() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger").replace(
        "script_version_roster = {\n}",
        "script_version_roster = {\n  'bin/example': ['', '0.1.0', 'example'],\n}",
    );
    let row = json!({"kind":"program","identity":"bin/example","output":"versioned-bin-example",
        "package":"example","version_authority":"meson.build:script_version_roster","release_group":"wrong",
        "form":"shell","installation_class":"build","callers":[]});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("declaration");
    fs::write(path, source).expect("ledger");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("script version authority differs from roster")
    );
}

/// A reviewed payload still refuses a changed source, unresolved callee and stale call anchor.
/// ´test:integration:census-refuses-payload-call-drift´
#[test]
fn census_refuses_payload_call_drift() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.path().join("bin")).expect("payload directory");
    fs::write(fixture.root.path().join("bin/probe"), "#!/bin/sh\nexit 0\n").expect("payload");
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    let row = json!({"kind":"payload","path":"bin/probe","form":"script","sha256":"stale",
        "owner":"tool","interpreter":"/bin/sh","execution_host":"fixture",
        "version_authority":"packages/tool/Cargo.toml","contract":"fixture command",
        "calls":[{"callee":"external:missing","selector":"missing","lookup":"test-executable",
        "contract":"fixture child","anchor":"exec missing"}]});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("declaration");
    fs::write(path, source).expect("ledger");
    let findings = fixture.run()["unaccounted"].to_string();
    assert!(findings.contains("payload differs from its reviewed source: bin/probe"));
    assert!(findings.contains("payload call source anchor missing: bin/probe"));
    assert!(findings.contains("payload call has unregistered executable: bin/probe"));
}

/// Transported argv needs its own callee even when the outer SSH process is registered.
/// ´test:integration:census-refuses-stale-delegated-call´
#[test]
fn census_refuses_stale_delegated_call() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    let row = json!({"kind":"delegated-call","identity":"remote-probe","caller":"tool",
        "callee":"external:missing","selector":"remote probe","lookup":"public-command",
        "execution_host":"fixture node","contract":"remote version query",
        "path":"packages/README.md","anchor":"remote program --version"});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("declaration");
    fs::write(path, source).expect("ledger");
    let findings = fixture.run()["unaccounted"].to_string();
    assert!(findings.contains("delegated call has stale source anchor: remote-probe"));
    assert!(findings.contains("delegated call has unregistered executable: remote-probe"));
}

/// Meson calls inside a loop are inventoried without mistaking strings or comments for commands.
/// ´test:integration:census-measures-meson-executable-forms´
#[test]
fn census_measures_meson_executable_forms() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    source.push_str("\n# run_command('comment')\ntext = '''run_command('data')'''\nforeach name : ['one', 'two']\n  test(name, find_program('probe'), args: ['('])\nendforeach\nconfigure_file(input: 'a', output: 'b', copy: true)\n");
    fs::write(path, source).expect("build forms");
    let report = fixture.run();
    assert_eq!(
        report["meson_calls"].as_array().expect("Meson calls").len(),
        2
    );
    let findings = report["unaccounted"].to_string();
    assert!(findings.contains("unaccounted Meson executable form: meson.build:test#1"));
    assert!(findings.contains("unaccounted Meson executable form: meson.build:find_program#1"));
}

fn test_tool_rows(fixture: &Fixture, provider: &str, binding: &str) {
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    for row in [
        json!({"kind":"program","identity":"bin/tool","output":"packages/tool/tool","package":"tool","version_authority":"packages/tool/Cargo.toml","form":"rust","installation_class":"build","cargo_binary":"tool","callers":[]}),
        json!({"kind":"test-tool","consumer":"tool","binding":binding,"provider":provider,"callee":"bin/tool","suite":"cargo-test","contract":"fixture executable binding"}),
    ] {
        writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']")
            .expect("test-tool declaration");
    }
    fs::write(path, source).expect("test-tool ledger");
}

/// A test executable cannot silently change from the registered build output to an ambient program.
/// ´test:integration:census-checks-configured-test-environment´
#[test]
fn census_checks_configured_test_environment() {
    let fixture = Fixture::new();
    test_tool_rows(&fixture, "meson-environment", "FIXTURE_TOOL");
    let tests = fixture.root.path().join("meson-info/intro-tests.json");
    fs::write(
        &tests,
        json!([{"name":"cargo-test","env":{"FIXTURE_TOOL":"/ambient/tool"}}]).to_string(),
    )
    .expect("incorrect environment");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("test-tool environment differs: cargo-test FIXTURE_TOOL")
    );
    fs::write(tests, json!([{"name":"cargo-test","env":{"FIXTURE_TOOL":fixture.root.path().join("packages/tool/tool")}}]).to_string()).expect("declared environment");
    assert!(
        !fixture.run()["unaccounted"]
            .to_string()
            .contains("test-tool environment differs")
    );
}

/// Cargo fixture bindings must resolve to a binary target in the consuming package.
/// ´test:integration:census-refuses-foreign-cargo-test-tool´
#[test]
fn census_refuses_foreign_cargo_test_tool() {
    let fixture = Fixture::new();
    test_tool_rows(&fixture, "cargo-target", "CARGO_BIN_EXE_foreign");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("test-tool Cargo target differs: tool CARGO_BIN_EXE_foreign")
    );
}

/// A Cargo-provided binary call needs a registered test-tool row in addition to its call edge.
/// ´test:integration:census-refuses-unregistered-test-tool´
#[test]
fn census_refuses_unregistered_test_tool() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    let row = json!({"kind":"call","site":"packages/tool/src/lib.rs:fixture#1","caller":"tool","owner":"TOOL","selector":"fixture","callee":"bin/tool","lookup":"test-executable","binding":"CARGO_BIN_EXE_tool","contract":"fixture binary"});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("call declaration");
    fs::write(path, source).expect("call ledger");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unregistered test-tool: tool CARGO_BIN_EXE_tool -> bin/tool")
    );
}

/// A program supplied by the suite needs the same binding declaration as a Cargo target.
/// ´test:integration:census-refuses-unregistered-suite-program´
#[test]
fn census_refuses_unregistered_suite_program() {
    let fixture = Fixture::new();
    test_tool_rows(&fixture, "meson-environment", "FIXTURE_TOOL");
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    let row = json!({"kind":"call","site":"packages/tool/src/lib.rs:fixture#1","caller":"tool","owner":"TOOL","selector":"fixture","callee":"bin/tool","lookup":"test-executable","binding":"UNREGISTERED_TOOL","contract":"suite binary"});
    writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("call declaration");
    fs::write(path, source).expect("call ledger");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("unregistered test-tool: tool UNREGISTERED_TOOL -> bin/tool")
    );
}

/// A command passed through a Meson variable remains bound to its reviewed definition.
/// ´test:integration:census-refuses-changed-meson-command-variable´
#[test]
fn census_refuses_changed_meson_command_variable() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    source.push_str("\nfixture_tool = 'first'\ntest('probe', fixture_tool)\n");
    fs::write(&path, &source).expect("Meson call");
    let report = fixture.run();
    let measured = &report["meson_calls"][0];
    for row in [
        json!({"kind":"external-program","identity":"external:fixture","selector":"fixture_tool","contract":"fixture","callers":["meson:tool"]}),
        json!({"kind":"meson-call","site":measured["site"],"sha256":measured["sha256"],"scope_sha256":measured["scope_sha256"],"caller":"meson:tool","owner":"tool","callees":["external:fixture"],"lookup":"public-command","contract":"fixture command variable"}),
    ] {
        writeln!(source, "\ndependency_ledger += ['''\n{row}\n''']").expect("declaration");
    }
    fs::write(&path, &source).expect("reviewed scope");
    assert!(
        !fixture.run()["unaccounted"]
            .to_string()
            .contains("Meson executable variable scope differs")
    );
    fs::write(
        path,
        source.replace("fixture_tool = 'first'", "fixture_tool = 'second'"),
    )
    .expect("changed variable");
    let findings = fixture.run()["unaccounted"].to_string();
    assert!(findings.contains("Meson executable variable scope differs"));
    assert!(!findings.contains("Meson executable form differs"));
}

/// Recorded successor packages remain accounted after the original package is removed.
/// ´test:integration:census-accepts-recorded-successor-package´
#[test]
fn census_accepts_recorded_successor_package() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .path()
        .join("adr/036-tools-dependency-concept.md");
    fs::write(&path, "|Present source|Destination and tier|\n|---|---|\n|`base`, `former-tool`|Survives as tier 2 `tool`.|\n\n|Package|Tier and domain|Accountable owner|Consumers|\n|-------|---------------|-----------------|---------|\n\n").expect("successor destination");
    assert_eq!(fixture.run()["unaccounted"], json!([]));
    fs::write(path, "|Present source|Destination and tier|\n|---|---|\n|`base`, `former-tool`|No successor declared.|\n\n|Package|Tier and domain|Accountable owner|Consumers|\n|-------|---------------|-----------------|---------|\n\n").expect("missing destination");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("package lacks a recorded destination: tool")
    );
}

/// A build-only successor is complete without an install and refuses an accidental install.
/// ´test:integration:census-keeps-reporter-successor-build-only´
#[test]
fn census_keeps_reporter_successor_build_only() {
    let fixture = Fixture::new();
    let row = "|`former-tool`|`tool`|build tree only|";
    fs::write(
        fixture
            .root
            .path()
            .join("adr/033-tool-executables-names-and-versions.md"),
        format!("|Present name|Successor|Installs to|\n|---|---|---|\n{row}\n\n"),
    )
    .expect("build-only successor");
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    for declaration in [
        json!({"kind":"successor","record":"tab:toolnames:successors","row":row,"pending_bites":[],"build_programs":["build/tool"]}),
        json!({"kind":"program","identity":"build/tool","output":"packages/tool/tool","package":"tool","version_authority":"packages/tool/Cargo.toml","form":"rust","installation_class":"build","cargo_binary":"tool","callers":[]}),
    ] {
        writeln!(source, "\ndependency_ledger += ['''\n{declaration}\n''']").expect("declaration");
    }
    fs::write(&path, &source).expect("build-only ledger");
    let report = fixture.run();
    assert_eq!(report["pending_successors"], json!([]));
    assert!(!report["unaccounted"].to_string().contains("successor"));
    let install = json!({"kind":"installation","route":"native","source":"build:packages/tool/tool","destination":"/fixture/bin/tool","owner":"tool"});
    writeln!(source, "\ndependency_ledger += ['''\n{install}\n''']").expect("accidental install");
    fs::write(path, source).expect("installed ledger");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("successor build-only program is not declared")
    );
}

/// Generated bridge destinations require the executable owner and its generating source.
/// ´test:integration:census-binds-generated-bridges-to-their-owner´
#[test]
fn census_binds_generated_bridges_to_their_owner() {
    let fixture = Fixture::new();
    let row = "|`LOOP-gpg`|generated `LOOP-gpg`|private directory|";
    fs::write(
        fixture
            .root
            .path()
            .join("adr/033-tool-executables-names-and-versions.md"),
        format!("|Present name|Successor|Installs to|\n|---|---|---|\n{row}\n\n"),
    )
    .expect("record");
    let path = fixture.root.path().join("meson.build");
    let mut source = fs::read_to_string(&path).expect("ledger");
    for declaration in [
        json!({"kind":"successor","record":"tab:toolnames:successors","row":row,"pending_bites":[],"generated_programs":[{"program":"build/tool","source":"packages/tool/Cargo.toml","anchor":"[package]","destination":"private/LOOP-gpg"}]}),
        json!({"kind":"program","identity":"build/tool","output":"packages/tool/tool","package":"tool","version_authority":"packages/tool/Cargo.toml","form":"rust","installation_class":"build","cargo_binary":"tool","callers":[]}),
    ] {
        writeln!(source, "\ndependency_ledger += ['''\n{declaration}\n''']").expect("declaration");
    }
    fs::write(&path, &source).expect("ledger");
    assert!(
        !fixture.run()["unaccounted"]
            .to_string()
            .contains("successor")
    );
    fs::write(
        &path,
        source.replace(
            "\"anchor\":\"[package]\"",
            "\"anchor\":\"missing generator\"",
        ),
    )
    .expect("broken generator");
    assert!(
        fixture.run()["unaccounted"]
            .to_string()
            .contains("successor generated destination lacks its owner or source anchor")
    );
}

/// Evaluated paths cover Meson spellings without parsing the source expression.
///
/// # Panics
/// Panics only if fixture setup or the coverage assertions fail.
/// ´test:integration:census-documents-use-evaluated-paths´
#[test]
fn census_documents_use_evaluated_paths() {
    for declaration in [
        "docs_prose = files('arch/example.md') + files('spec/example.md')\n",
        "docs_prose = files('./arch/example.md', '''spec/example.md''')\n",
        "docs_prose = evaluated_elsewhere\n",
    ] {
        for map in [None, Some("maps/share-map.toml")] {
            let fixture = document_fixture(map, "");
            fs::write(fixture.root.path().join("docs/meson.build"), declaration)
                .expect("Meson expression");
            let report = fixture.run();
            let findings = report["unaccounted"].as_array().expect("findings");
            assert_eq!(
                findings.len(),
                if map.is_some() { 0 } else { 2 },
                "{report}"
            );
            if map.is_none() {
                assert!(findings.iter().all(|finding| {
                    finding
                        .as_str()
                        .expect("finding")
                        .starts_with("docs-prose-uninstalled:")
                }));
            }
        }
    }
}

/// An absent evaluated list refuses instead of skipping document coverage.
///
/// # Panics
/// Panics only if fixture setup or the refusal assertion fails.
/// ´test:integration:census-documents-refuse-missing-list´
#[test]
fn census_documents_refuse_missing_list() {
    let fixture = Fixture::new();
    let path = fixture.root.path().join("declared-paths.txt");
    fs::remove_file(&path).expect("remove evaluated list");
    let report = fixture.run_at(fixture.root.path(), Some("docs-prose-unreadable:"));
    assert!(
        report["error"]
            .as_str()
            .expect("refusal")
            .ends_with(&format!(" in {}", path.display()))
    );
}

/// A non-file or non-UTF-8 evaluated list has the same refusal name.
///
/// # Panics
/// Panics only if fixture setup or the refusal assertion fails.
/// ´test:integration:census-documents-refuse-unreadable-list´
#[test]
fn census_documents_refuse_unreadable_list() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("declared-paths.txt");
        if directory {
            fs::remove_file(&path).expect("remove evaluated list");
            fs::create_dir(&path).expect("non-file list");
        } else {
            fs::write(&path, [0xff]).expect("non-UTF-8 list");
        }
        let report = fixture.run_at(fixture.root.path(), Some("docs-prose-unreadable:"));
        assert!(
            report["error"]
                .as_str()
                .expect("refusal")
                .ends_with(&format!(" in {}", path.display()))
        );
    }
}

/// Invalid path records refuse before document selection can hide them.
///
/// # Panics
/// Panics only if fixture setup or the refusal assertion fails.
/// ´test:integration:census-documents-refuse-invalid-paths´
#[test]
fn census_documents_refuse_invalid_paths() {
    for path in [
        "/docs/arch/example.md",
        "../outside.md",
        "docs//arch/example.md",
        "./docs/arch/example.md",
        "docs\\arch\\example.md",
        "bad\0path",
        "\n",
    ] {
        let fixture = Fixture::new();
        fs::write(fixture.root.path().join("declared-paths.txt"), path).expect("invalid path");
        fixture.run_at(
            fixture.root.path(),
            Some("docs-prose-unreadable: line 1 is not a normalized relative path in "),
        );
    }
}

/// A list outside the configured ledger's parent cannot supply coverage.
///
/// # Panics
/// Panics only if fixture setup or the refusal assertion fails.
/// ´test:integration:census-documents-require-ledger-parent´
#[test]
fn census_documents_require_ledger_parent() {
    let fixture = document_fixture(Some("maps/share-map.toml"), "");
    let build = fixture.root.path().join("other-build");
    fs::create_dir(&build).expect("other build");
    let report = fixture.run_at(&build, Some("docs-prose-unreadable:"));
    assert!(
        report["error"]
            .as_str()
            .expect("refusal")
            .ends_with(&format!(
                " in {}",
                build.join("declared-paths.txt").display()
            ))
    );
}

/// A missing domains header refuses without publishing a measured graph.
///
/// # Panics
/// Panics only if fixture setup or refusal assertions fail.
/// ´test:integration:census-refuses-missing-domains-table´
#[test]
fn census_refuses_missing_domains_table() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .path()
        .join("adr/036-tools-dependency-concept.md");
    let record = fs::read_to_string(&path).expect("record");
    fs::write(
        path,
        record.replace(
            "|Package|Tier and domain|Accountable owner|Consumers|\n",
            "",
        ),
    )
    .expect("missing domains header");
    let error = "record 036 domains table missing";
    let report = fixture.run_at(fixture.root.path(), Some(error));
    assert_eq!(report, json!({"schema":1,"complete":false,"error":error}));
}

/// A five-field domains row refuses without publishing a measured graph.
///
/// # Panics
/// Panics only if fixture setup or refusal assertions fail.
/// ´test:integration:census-refuses-malformed-domains-table-row´
#[test]
fn census_refuses_malformed_domains_table_row() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .path()
        .join("adr/036-tools-dependency-concept.md");
    let record = fs::read_to_string(&path).expect("record");
    fs::write(
        path,
        record.replace(
            "|`base`|Fixture domain|BASE|tool|",
            "|`base`|Fixture domain|BASE|tool|extra|",
        ),
    )
    .expect("five-field domains row");
    let error = "record 036 domains table row malformed";
    let report = fixture.run_at(fixture.root.path(), Some(error));
    assert_eq!(report, json!({"schema":1,"complete":false,"error":error}));
}

/// A stale domains package refuses without publishing a measured graph.
///
/// # Panics
/// Panics only if fixture setup or refusal assertions fail.
/// ´test:integration:census-refuses-domains-package-outside-roster´
#[test]
fn census_refuses_domains_package_outside_roster() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .path()
        .join("adr/036-tools-dependency-concept.md");
    let record = fs::read_to_string(&path).expect("record");
    fs::write(
        path,
        record.replace(
            "|`base`|Fixture domain|BASE|tool|",
            "|`base`|Fixture domain|BASE|tool|\n|`absent`|Stale domain|ABSENT|tool|",
        ),
    )
    .expect("stale domains package");
    let error = "record 036 domains table names a package the roster lacks: absent";
    let report = fixture.run_at(fixture.root.path(), Some(error));
    assert_eq!(report, json!({"schema":1,"complete":false,"error":error}));
}

/// Domain owners cannot drift between the ledger and record 036.
///
/// # Panics
/// Panics only if fixture setup or the disagreement assertion fails.
/// ´test:integration:census-refuses-record-owner-disagreement´
#[test]
fn census_refuses_record_owner_disagreement() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .path()
        .join("adr/036-tools-dependency-concept.md");
    let record = fs::read_to_string(&path).expect("record");
    fs::write(path, record.replace("|BASE|", "|OTHER|")).expect("changed record owner");
    assert_eq!(
        fixture.run()["unaccounted"],
        json!(["accountable owner disagrees with record 036: base"])
    );
}

/// The domains table does not require every workspace package to be a domain.
///
/// # Panics
/// Panics only if fixture setup or admission assertions fail.
/// ´test:integration:census-admits-owner-outside-domains-table´
#[test]
fn census_admits_owner_outside_domains_table() {
    let fixture = Fixture::new();
    let report = fixture.run();
    assert_eq!(report["unaccounted"], json!([]));
    let tool = report["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "tool")
        .expect("unlisted package");
    assert_eq!(tool["accountable_owner"], "TOOL");
}
