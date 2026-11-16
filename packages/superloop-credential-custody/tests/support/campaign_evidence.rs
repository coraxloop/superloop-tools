//! Synthetic protected producer evidence for the public observation boundary.
//! Actual producer/store correspondence is tested by the launch campaign tests.
use super::{Fixture, hash, mode};
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt as _;
use std::{fs, path::Path};

fn protected(path: &Path, value: &Value, permissions: u32) {
    if path.exists() {
        mode(path, 0o600);
    }
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    mode(path, permissions);
}
fn directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    mode(path, 0o700);
}
fn object(path: &Path) -> Value {
    let m = fs::metadata(path).unwrap();
    json!({"device":m.dev(),"inode":m.ino()})
}
fn canonical(domain: &str, value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain.as_bytes());
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(&bytes);
    hash(&framed)
}
fn properties(role: &str) -> Value {
    json!({"capability_bounding_set":match role {"calibration-run"=>vec!["SYS_PTRACE","KILL"],"descriptors"=>vec!["SYS_PTRACE"],_=>vec![]},
        "ambient_capabilities":[],"no_new_privileges":true,"protect_system":"strict",
        "user_namespace":"host","pid_namespace":"host","manager_access":role=="calibration-run",
        "dynamic_user":role=="fixture","private_diagnostics":true,
        "writable":match role {"calibration-run"=>vec!["runtime","sealed","evidence"],"completion"|"descriptors"=>vec!["evidence"],"barrier-release"=>vec!["runtime","evidence"],_=>vec![]}})
}
impl Fixture {
    fn rewrite_producer(&mut self, edit: impl FnOnce(&mut Value, &mut Value)) {
        let root = self.dir.path().join("producer");
        let path = root.join("policy.json");
        let matrix_path = root.join("evidence/campaign.json");
        let mut policy: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut matrix: Value = serde_json::from_slice(&fs::read(&matrix_path).unwrap()).unwrap();
        edit(&mut policy, &mut matrix);
        for case in policy["cases"].as_array_mut().unwrap() {
            let public = json!({"schema":1,"command":"fixture-emit","case":case["id"],"behavior":"normal","timeout_ms":60000,
                "streams":case["streams"].as_array().unwrap().iter().map(|s|json!({"name":s["name"],"length":s["length"],"pattern":s["pattern"]})).collect::<Vec<_>>()});
            let file = Path::new(case["public_case"].as_str().unwrap()).to_path_buf();
            protected(&file, &public, 0o444);
            case["expected_case_sha256"] = json!(hash(&fs::read(file).unwrap()));
        }
        protected(&path, &policy, 0o400);
        let digest = hash(&fs::read(path).unwrap());
        matrix["policy_sha256"] = json!(digest);
        for (row, case) in matrix["rows"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(policy["cases"].as_array().unwrap())
        {
            row["completed"]["policy_sha256"] = json!(digest);
            row["completed"]["case_sha256"] = case["expected_case_sha256"].clone();
        }
        protected(&matrix_path, &matrix, 0o400);
        self.record["campaign"]["matrix_sha256"] = json!(hash(&fs::read(matrix_path).unwrap()));
    }
    pub(super) fn campaign(&mut self) {
        let root = self.dir.path().join("producer");
        for part in ["", "runtime", "sealed", "evidence"] {
            directory(&root.join(part));
        }
        let mut artifacts = Vec::new();
        for role in [
            "launcher",
            "fixture",
            "sealer",
            "parser",
            "interpreter",
            "library",
        ] {
            let path = if matches!(role, "launcher" | "fixture") {
                let path = root.join(role);
                if path.exists() {
                    mode(&path, 0o600);
                }
                fs::write(&path, role).unwrap();
                mode(&path, 0o444);
                path
            } else {
                let path = Path::new(
                    self.record["identity"]["files"][role]["path"]
                        .as_str()
                        .unwrap(),
                );
                if role == "interpreter" {
                    fs::canonicalize(path).unwrap()
                } else {
                    path.to_path_buf()
                }
            };
            artifacts.push(json!({"id":role,"role":role,"path":path,"expected_sha256":hash(&fs::read(&path).unwrap())}));
        }
        artifacts.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let measured = Value::Array(
            artifacts
                .iter()
                .map(|a| json!([a["id"], a["role"], a["expected_sha256"]]))
                .collect(),
        );
        let mut cases = Vec::new();
        for length in 3..=5 {
            for pair in 0..2 {
                let id = format!("pair-{length}-{pair}");
                let streams: Vec<_> = ["alpha", "beta"]
                    .iter()
                    .enumerate()
                    .map(|(slot, name)| {
                        json!({"name":name,"output":format!("{name}.sealed"),"length":length,
                        "pattern":if slot==pair {"ascending"} else {"descending"}})
                    })
                    .collect();
                let public = json!({"schema":1,"command":"fixture-emit","case":id,"behavior":"normal","timeout_ms":60000,
                    "streams":streams.iter().map(|s|json!({"name":s["name"],"length":s["length"],"pattern":s["pattern"]})).collect::<Vec<_>>()});
                let path = root.join(format!("{id}.json"));
                protected(&path, &public, 0o444);
                cases.push(json!({"id":id,"generator_unit":format!("synthetic-{id}.service"),"public_case":path,
                    "expected_case_sha256":hash(&fs::read(path).unwrap()),"streams":streams}));
            }
        }
        let roles: Vec<_> = [
            "calibration-run",
            "completion",
            "descriptors",
            "barrier-release",
            "fixture",
        ]
        .iter()
        .map(|role| json!({"role":role,"properties":properties(role)}))
        .collect();
        let policy = json!({"schema":2,"command":"launch-policy","sealer_construction":"landlock6-seccomp-v1","campaign":"campaign",
            "roots":{"runtime":root.join("runtime"),"sealed":root.join("sealed"),"evidence":root.join("evidence")},
            "manager_sockets":[root.join("bus.sock"),root.join("manager.sock")],"host_key":root.join("synthetic-key"),"slice":"synthetic.slice",
            "limits":{"case_ms":60000,"campaign_ms":3_600_000,"poll_ms":10,"sealed_bytes":1_048_576,"total_sealed_bytes":134_217_728,
                "diagnostic_bytes":1024,"artifact_bytes":67_108_864,"observed_fds":16,"mapped_files":8,"event_queue":16},
            "artifacts":artifacts,"roles":roles,"cases":cases});
        protected(&root.join("policy.json"), &policy, 0o400);
        let policy_hash = hash(&fs::read(root.join("policy.json")).unwrap());
        let rows = self.campaign_rows(&policy, &policy_hash);
        let matrix = json!({"schema":2,"command":"calibration-run","campaign":"campaign","policy_sha256":policy_hash,
            "code_sha256":canonical("custody-artifacts-v1",&measured),"rows":rows});
        protected(&root.join("evidence/campaign.json"), &matrix, 0o400);
        self.record["campaign"] = json!({"policy":root.join("policy.json"),"matrix_sha256":hash(&fs::read(root.join("evidence/campaign.json")).unwrap())});
    }
    fn campaign_rows(&self, policy: &Value, policy_hash: &str) -> Vec<Value> {
        let root = self.dir.path().join("producer");
        policy["cases"].as_array().unwrap().iter().enumerate().map(|(index,case)| {
            let id=case["id"].as_str().unwrap();
            directory(&root.join("sealed").join(id));directory(&root.join("evidence").join(id));
            let mut outputs=Vec::new();let mut lengths=Vec::new();
            for stream in case["streams"].as_array().unwrap() {
                let name=stream["name"].as_str().unwrap();let length=stream["length"].as_u64().unwrap();
                let content=if stream["pattern"]=="ascending" {"a"} else {"b"};
                let bytes=fs::read(self.dir.path().join("sealed").join(name).join(format!("{length}-{content}.sealed"))).unwrap();
                let path=root.join("sealed").join(id).join(stream["output"].as_str().unwrap());
                if path.exists(){mode(&path,0o600);}fs::write(&path,&bytes).unwrap();mode(&path,0o400);
                lengths.push(bytes.len());outputs.push(json!({"name":stream["output"],"object":object(&path),"sha256":hash(&bytes)}));
            }
            let receipt=root.join("evidence").join(id).join("completion.json");
            protected(&receipt,&json!({"synthetic_completed_case":id}),0o400);
            json!({"index":index,"completed":{"case":id,"policy_sha256":policy_hash,"case_sha256":case["expected_case_sha256"],
                "invocation":{"id":format!("invocation-{index}"),"unit":case["generator_unit"],"pid":123,"birth":456,
                    "uid":nix::unistd::geteuid().as_raw(),"image":object(&root.join("fixture"))},
                "completion_sha256":hash(&fs::read(receipt).unwrap()),"sealed_bytes":lengths,"outputs":outputs,
                "configuration":{"raw_sha256":hash(b"synthetic loaded properties"),"typed_sha256":hash(b"synthetic typed properties")},
                "manager_configuration_sha256":hash(b"synthetic manager properties")}})
        }).collect()
    }
}

/// ´test:integration:observation-rejects-legacy-assertions´
#[test]
fn observation_rejects_legacy_assertions() {
    for key in ["config_digest", "code_digest"] {
        let mut f = Fixture::new();
        f.record[key] = json!("a".repeat(64));
        super::refused(&f.observe(), "record-shape");
    }
    let mut f = Fixture::new();
    f.record["samples"][0]["completion"] = json!({"success":true});
    super::refused(&f.observe(), "record-shape");
    let mut f = Fixture::new();
    f.record["schema"] = json!(2);
    super::refused(&f.observe(), "record-schema");
    let f = Fixture::new();
    let report = super::pass(&f.observe());
    assert_eq!(report["schema"], 3);
    let path = f.dir.path().join("evidence/calibration");
    let mut old: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    old["schema"] = json!(1);
    protected(&path, &old, 0o400);
    super::refused(&f.check(), "calibration-identity");
    let mut f = Fixture::new();
    f.record["campaign"]["unknown"] = json!(true);
    super::refused(&f.observe(), "record-shape");
    let mut f = Fixture::new();
    f.record["campaign"]["matrix_sha256"] = json!("");
    super::refused(&f.observe(), "record-identity");
    let f = Fixture::new();
    super::pass(&f.observe());
    let path = f.dir.path().join("evidence/calibration");
    let mut old: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    old["evidence"]["campaign"]["unknown"] = json!(true);
    protected(&path, &old, 0o400);
    super::refused(&f.check(), "calibration-shape");
    let _removed = old["evidence"]["campaign"]
        .as_object_mut()
        .unwrap()
        .remove("unknown");
    old["evidence"]["config_digest"] = json!("a".repeat(64));
    protected(&path, &old, 0o400);
    super::refused(&f.check(), "calibration-shape");
}

/// ´test:integration:observation-admission-precedes-probes´
#[test]
fn observation_admission_precedes_probes() {
    let mut f = Fixture::new();
    let marker = f.dir.path().join("probe-ran");
    f.record["campaign"]["matrix_sha256"] = json!("0".repeat(64));
    f.record["probes"][0]["argv"] = json!(["/usr/bin/touch", marker]);
    super::refused(&f.observe(), "campaign-handoff-digest");
    assert!(!marker.exists());
}

/// ´test:integration:observation-binds-every-campaign-output´
#[test]
fn observation_binds_every_campaign_output() {
    for (pointer, value, class) in [
        (
            "/campaign/matrix_sha256",
            json!("0".repeat(64)),
            "campaign-handoff-digest",
        ),
        ("/case", json!("other"), "observation-campaign"),
        ("/samples/0/case", json!("missing"), "observation-case"),
        ("/samples/0/case", json!("pair-4-0"), "observation-input"),
        ("/samples/0/case", json!("pair-3-1"), "observation-input"),
        (
            "/identity/files/library/sha256",
            json!("0".repeat(64)),
            "observation-artifact",
        ),
    ] {
        let mut f = Fixture::new();
        *f.record.pointer_mut(pointer).unwrap() = value;
        // Keep the outer case selector consistent so the new core is reached.
        f.save();
        if pointer == "/case" {
            let out = super::binary()
                .args(["length-observe", "--parameters"])
                .arg(f.dir.path().join("parameters.json"))
                .args(["--case", "other", "--receipt", "calibration"])
                .output()
                .unwrap();
            super::refused(&out, class);
        } else {
            super::refused(&f.observe(), class);
        }
    }
    let mut f = Fixture::new();
    f.record["sealed_root"] = json!(f.dir.path().join("producer/sealed"));
    super::refused(&f.observe(), "observation-analysis-root");
    let mut f = Fixture::new();
    let path = f.dir.path().join("other-library");
    fs::copy(f.dir.path().join("library"), &path).unwrap();
    f.record["identity"]["files"]["library"]["path"] = json!(path);
    super::refused(&f.observe(), "observation-artifact");
    let mut f = Fixture::new();
    f.rewrite_producer(|policy, matrix| {
        let _case = policy["cases"].as_array_mut().unwrap().pop();
        let _row = matrix["rows"].as_array_mut().unwrap().pop();
    });
    super::refused(&f.observe(), "observation-roster");
    let mut f = Fixture::new();
    f.rewrite_producer(|policy, _| {
        policy["cases"][0]["streams"][0]["name"] = json!("gamma");
    });
    super::refused(&f.observe(), "observation-stream");
}

/// ´test:integration:calibration-retains-measured-binding-and-parameter-identity´
#[test]
fn calibration_retains_measured_binding_and_parameter_identity() {
    let mut f = Fixture::new();
    let report = super::pass(&f.observe());
    assert_eq!(
        report["evidence"]["campaign"]["matrix_sha256"],
        f.record["campaign"]["matrix_sha256"]
    );
    let matrix: Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("producer/evidence/campaign.json")).unwrap(),
    )
    .unwrap();
    let configurations = Value::Array(
        matrix["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                json!([
                    row["completed"]["case"],
                    row["completed"]["configuration"],
                    row["completed"]["manager_configuration_sha256"]
                ])
            })
            .collect(),
    );
    assert_eq!(
        report["evidence"]["campaign"]["configuration_sha256"],
        canonical("custody-campaign-configuration-v2", &configurations)
    );
    assert_eq!(
        report["evidence"]["campaign"]["code_sha256"],
        matrix["code_sha256"]
    );
    assert_eq!(
        report["evidence"]["campaign"]["policy_sha256"],
        matrix["policy_sha256"]
    );
    assert!(report["evidence"].get("config_digest").is_none());
    assert!(report["evidence"].get("code_digest").is_none());
    f.record["probes"][0]["argv"] = json!(["/usr/bin/printf", "%s\n", "synthetic-v1"]);
    super::refused(&f.check(), "calibration-identity");
    let f = Fixture::new();
    super::pass(&f.observe());
    let path = f.dir.path().join("producer/sealed/pair-3-0/alpha.sealed");
    mode(&path, 0o600);
    fs::write(&path, b"QkJC\n").unwrap();
    mode(&path, 0o400);
    super::refused(&f.check(), "campaign-handoff-content");
}

/// ´test:integration:observation-rechecks-campaign-after-parser´
#[test]
fn observation_rechecks_campaign_after_parser() {
    let payload = format!(
        "{}\np = root.parent / 'producer' / 'evidence' / 'campaign.json'\nb = p.read_bytes()\np.chmod(0o600)\np.write_bytes(b + b' ')\np.chmod(0o400)\n",
        super::PAYLOAD
    );
    let f = Fixture::payload(&payload);
    super::refused(&f.observe(), "campaign-handoff-digest");
    assert!(!f.dir.path().join("evidence/calibration").exists());
    let payload = format!(
        "{}\np = root / 'alpha' / '3-a.sealed'\np.chmod(0o600)\np.write_bytes(b'QkJC\\n')\np.chmod(0o400)\n",
        super::PAYLOAD
    );
    let f = Fixture::payload(&payload);
    super::refused(&f.observe(), "sealed-completion-identity");
    assert!(!f.dir.path().join("evidence/calibration").exists());
}

/// ´test:integration:calibration-measures-owner-and-refuses-earlier-form´
#[test]
fn calibration_measures_owner_and_refuses_earlier_form() {
    let f = Fixture::new();
    let report = super::pass(&f.observe());
    assert_eq!(report["schema"], 3);
    assert_eq!(
        report["evidence"]["campaign"]["admitted_owner_uid"],
        nix::unistd::geteuid().as_raw()
    );
    let path = f.dir.path().join("evidence/calibration");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut changed = original.clone();
    changed["schema"] = json!(2);
    protected(&path, &changed, 0o400);
    super::refused(&f.check(), "calibration-identity");
    let mut changed = original.clone();
    changed["evidence"]["campaign"]["admitted_owner_uid"] =
        json!(nix::unistd::geteuid().as_raw().wrapping_add(1));
    protected(&path, &changed, 0o400);
    super::refused(&f.check(), "calibration-identity");
    let mut changed = original;
    let _removed = changed["evidence"]["campaign"]
        .as_object_mut()
        .unwrap()
        .remove("admitted_owner_uid");
    protected(&path, &changed, 0o400);
    super::refused(&f.check(), "calibration-shape");
}

/// ´test:integration:observation-receipt-root-is-disjoint´
#[test]
fn observation_receipt_root_is_disjoint() {
    for path in [
        "producer/evidence",
        "producer/sealed",
        "producer/runtime",
        "producer/evidence/analysis",
        "producer",
    ] {
        let mut f = Fixture::new();
        directory(&f.dir.path().join(path));
        f.record["evidence_root"] = json!(f.dir.path().join(path));
        super::refused(&f.observe(), "observation-evidence-root");
        assert!(!f.dir.path().join(path).join("calibration").exists());
    }
}

/// ´test:integration:observation-complete-subset-is-not-whole-campaign´
#[test]
fn observation_complete_subset_is_not_whole_campaign() {
    let mut f = Fixture::payload(&super::PAYLOAD.replace("(3, 4, 5)", "(3, 4)"));
    f.record["lengths"] = json!([3, 4]);
    f.record["samples"]
        .as_array_mut()
        .unwrap()
        .retain(|s| s["input_length"] != 5);
    for name in ["alpha", "beta"] {
        for content in ["a", "b"] {
            fs::remove_file(
                f.dir
                    .path()
                    .join(format!("sealed/{name}/5-{content}.sealed")),
            )
            .unwrap();
        }
    }
    super::refused(&f.observe(), "observation-roster");
}

/// ´test:integration:observation-swapped-pattern-assignment-is-not-input´
#[test]
fn observation_swapped_pattern_assignment_is_not_input() {
    let mut f = Fixture::new();
    f.record["samples"][0]["case"] = json!("pair-3-1");
    f.record["samples"][1]["case"] = json!("pair-3-0");
    let a = f.dir.path().join("sealed/alpha/3-a.sealed");
    let b = f.dir.path().join("sealed/alpha/3-b.sealed");
    let bytes_a = fs::read(&a).unwrap();
    let bytes_b = fs::read(&b).unwrap();
    mode(&a, 0o600);
    mode(&b, 0o600);
    fs::write(&a, bytes_b).unwrap();
    fs::write(&b, bytes_a).unwrap();
    mode(&a, 0o400);
    mode(&b, 0o400);
    super::refused(&f.observe(), "observation-input");
}
