//! Opt-in launch declarations; no workspace placement or execution.
use super::{LaneError, Plan, Settings};
use execute_command::workspace::{Grant, GrantSnapshot};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

const MAX_DECLARATION: usize = 65_536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    grant: Grant,
    baseline_environment_is_public: bool,
}

fn refusal(detail: &str) -> LaneError {
    LaneError::input("workspace-declaration", detail)
}

/// Parse public owner input without echoing environment values in a refusal.
pub(super) fn declaration(text: &str) -> Result<GrantSnapshot, LaneError> {
    if text.len() > MAX_DECLARATION {
        return Err(refusal("declaration exceeds 65536 bytes"));
    }
    let declared: Declaration = serde_json::from_str(text).map_err(|_| {
        refusal("declaration requires exactly grant and baseline_environment_is_public")
    })?;
    if !declared.baseline_environment_is_public {
        return Err(refusal(
            "baseline environment must contain no secrets and is published to workers, previews, records and judgement",
        ));
    }
    let grant = declared.grant;
    grant
        .validate()
        .map_err(|_| refusal("grant fields differ"))?;
    let mut names = BTreeSet::new();
    for (name, value) in &grant.baseline_env {
        if !names.insert(name) {
            return Err(refusal("baseline environment names must be unique"));
        }
        if secret(name, value) {
            return Err(refusal(
                "baseline environment contains a recognizable credential name or value; supply only public build configuration",
            ));
        }
    }
    let digest = grant.digest().map_err(|_| refusal("grant digest failed"))?;
    Ok(GrantSnapshot { grant, digest })
}

fn secret(name: &str, value: &str) -> bool {
    let name = name.to_ascii_uppercase();
    let lower = value.to_ascii_lowercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "API_KEY",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "AUTHORIZATION",
        "AUTH",
        "COOKIE",
    ]
    .iter()
    .any(|part| name.contains(part))
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.starts_with("bearer ")
        || ["sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "akia"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        || lower.split_once("://").is_some_and(|(_, rest)| {
            rest.split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
}

/// Add only an explicitly declared, context-bound snapshot to a fresh plan.
pub(super) fn bind(
    plan: &mut Plan,
    settings: &Settings,
    declaration_text: Option<&str>,
    expected: Option<&str>,
    preview: bool,
) -> Result<(), LaneError> {
    let Some(text) = declaration_text else {
        return Ok(());
    };
    let snapshot = declaration(text)?;
    if plan.document["loop"] != snapshot.grant.loop_name
        || plan.document["run"] != snapshot.grant.run
    {
        return Err(refusal("grant loop or run differs from launch"));
    }
    let table: toml::Table =
        toml::from_str(&settings.source).map_err(|_| refusal("workers settings cannot be read"))?;
    let policy = table
        .get("workspace_policy")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            refusal(
                "workers.toml workspace_policy must publish both policy digests before declaration",
            )
        })?;
    for (key, digest) in [
        ("quick_policy_digest", &snapshot.grant.quick_policy_digest),
        ("blacklist_digest", &snapshot.grant.blacklist_digest),
    ] {
        if policy.get(key).and_then(toml::Value::as_str) != Some(digest.as_str()) {
            return Err(refusal(
                "grant policy digests differ from loop configuration",
            ));
        }
    }
    if !preview && expected != Some(snapshot.digest.as_str()) {
        return Err(LaneError::input(
            "workspace-digest",
            "apply requires the matching compute_workspace.digest from launch --dry-run; repeat preview after any declaration change",
        ));
    }
    plan.document["compute_workspace"] = json!(snapshot);
    Ok(())
}

/// A protected prior grant is immutable, including during preparation recovery.
pub(super) fn retain_or_declare(
    plan: &mut Plan,
    settings: &Settings,
    declaration_text: Option<&str>,
    expected: Option<&str>,
    preview: bool,
    prior: Option<&serde_json::Value>,
) -> Result<(), LaneError> {
    if let Some(prior) = prior {
        if declaration_text.is_some() {
            return Err(refusal(
                "workspace declaration requires a new run; resume retains the recorded grant",
            ));
        }
        plan.retain_workspace(&prior["plan"])?;
    }
    bind(plan, settings, declaration_text, expected, preview)
}

/// A visible preparing reservation must already name a reserved mail birth.
pub(super) fn reserve_before_publish<T>(
    reserve: impl FnOnce() -> Result<(), LaneError>,
    publish: impl FnOnce() -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    reserve()?;
    publish()
}

#[cfg(test)]
mod tests {
    use super::super::{LaunchRequest, initial_reservation, publish_reservation, read_reservation};
    use super::*;
    use std::path::Path;

    fn input() -> String {
        json!({"grant":crate::plan::fixture_workspace_snapshot()["grant"],"baseline_environment_is_public":true}).to_string()
    }
    fn settings() -> Settings {
        let mut settings = crate::tests::fixture_settings(Path::new("/fixture/entry"));
        settings.source = format!(
            "workspace_policy = {{ quick_policy_digest = {:?}, blacklist_digest = {:?} }}\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        settings
    }
    fn plan() -> Plan {
        Plan {
            home: "/fixture/home".into(),
            driver_dir: "/fixture/run".into(),
            letter: "/fixture/letter".into(),
            document: json!({"loop":"alpha","run":"R"}),
        }
    }
    fn record(plan: &Plan) -> serde_json::Value {
        initial_reservation(
            plan,
            "alpha",
            "R",
            3000,
            &json!({}),
            &[],
            Path::new("/fixture/letter"),
            None,
            &[],
            crate::door::Scope::Work,
        )
    }

    /// ´test:unit:workspace-declaration-binds-preview-before-publication´
    #[test]
    fn workspace_declaration_binds_preview_before_publication() {
        let root = tempfile::tempdir().expect("private fixture");
        let path = root.path().join(".reservation-R.json");
        let declaration = input();
        let mut preview = plan();
        bind(&mut preview, &settings(), Some(&declaration), None, true).expect("preview");
        assert!(!path.exists(), "preview publishes no reservation");
        assert_eq!(
            preview.document["compute_workspace"],
            crate::plan::fixture_workspace_snapshot(),
            "preview shows the complete reviewed declaration"
        );
        let digest = preview.document["compute_workspace"]["digest"]
            .as_str()
            .unwrap();
        let mut apply = plan();
        assert_eq!(
            bind(&mut apply, &settings(), Some(&declaration), None, false)
                .unwrap_err()
                .kind,
            "workspace-digest"
        );
        assert!(apply.document.get("compute_workspace").is_none());
        let changed = declaration.replace("/work/R", "/work/other");
        assert_eq!(
            bind(&mut apply, &settings(), Some(&changed), Some(digest), false)
                .unwrap_err()
                .kind,
            "workspace-digest"
        );
        bind(
            &mut apply,
            &settings(),
            Some(&declaration),
            Some(digest),
            false,
        )
        .expect("matching act");
        assert_eq!(apply.document, preview.document);
        publish_reservation(&path, &record(&apply)).expect("publish before home creation");
        let saved = read_reservation(&path).unwrap().unwrap();
        assert_eq!(
            saved["plan"]["compute_workspace"],
            preview.document["compute_workspace"]
        );
        assert!(
            crate::plan::workspace_snapshot(&saved["plan"])
                .unwrap()
                .is_some()
        );
    }

    /// ´test:unit:workspace-undeclared-launch-keeps-written-bytes´
    #[test]
    fn workspace_undeclared_launch_keeps_written_bytes() {
        let root = tempfile::tempdir().expect("fixture");
        // Captured once from the W1b c6fcb05a publisher; no candidate producer defines these bytes.
        let baseline_plan = br#"{"loop":"alpha","run":"R"}"#;
        let baseline_record = br#"{"checkout_attempts":[],"checkout_next_index":1,"checkouts":[],"checkouts_omitted":0,"collection":null,"declared_sources":[],"door_scope":"work","harvest_agreement":null,"helper_spawn_state":"not-started","imports":[],"letter_source":"/fixture/letter","loop":"alpha","model_selection":{},"observer_state":"not-started","phase":"preparing","plan":{"loop":"alpha","run":"R"},"probe_starts":[],"reservation_census":{"skipped_count":0,"skipped_names":[]},"rotation_source_sha256":null,"run":"R","schema":1,"worker_uid":3000}"#;
        let mut after = plan();
        for preview in [true, false] {
            bind(&mut after, &settings(), None, None, preview).expect("absent opt-in");
            assert_eq!(after.json().unwrap().as_bytes(), baseline_plan);
            let path = root.path().join("after.json");
            publish_reservation(&path, &record(&after)).unwrap();
            assert_eq!(std::fs::read(path).unwrap(), baseline_record);
            assert!(after.document.get("compute_workspace").is_none());
        }
    }

    /// ´test:unit:workspace-declaration-refuses-secrets-duplicates-and-context´
    #[test]
    fn workspace_declaration_refuses_secrets_duplicates_and_context() {
        declaration(&input()).expect("public PATH control");
        for (name, value) in [
            ("PATH", "/other"),
            ("API_KEY", "fixture-public-marker"),
            ("BUILD", "Bearer fixture-public-marker"),
            ("BUILD", "https://fixture:public@example.invalid/"),
        ] {
            let mut bad: serde_json::Value = serde_json::from_str(&input()).unwrap();
            bad["grant"]["baseline_env"]
                .as_array_mut()
                .unwrap()
                .push(json!([name, value]));
            let error = declaration(&bad.to_string()).unwrap_err();
            assert_eq!(error.kind, "workspace-declaration");
            assert!(
                !error.detail.contains(value),
                "refusal does not echo suspect values"
            );
        }
        let mut bad: serde_json::Value = serde_json::from_str(&input()).unwrap();
        bad["baseline_environment_is_public"] = json!(false);
        assert!(declaration(&bad.to_string()).is_err());
        for text in [
            input().replace("\"R\"", "\"S\""),
            input().replace(&"a".repeat(64), &"c".repeat(64)),
        ] {
            let mut candidate = plan();
            assert_eq!(
                bind(&mut candidate, &settings(), Some(&text), None, true)
                    .unwrap_err()
                    .kind,
                "workspace-declaration"
            );
            assert!(candidate.document.get("compute_workspace").is_none());
        }
        let duplicate = input().replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
        assert!(declaration(&duplicate).is_err());
    }

    /// ´test:unit:workspace-preparation-retry-retains-immutable-grant´
    #[test]
    fn workspace_preparation_retry_retains_immutable_grant() {
        let prior = json!({"plan":{"loop":"alpha","run":"R","compute_workspace":crate::plan::fixture_workspace_snapshot()}});
        let mut rebuilt = plan();
        retain_or_declare(&mut rebuilt, &settings(), None, None, false, Some(&prior))
            .expect("retry retains binding");
        assert_eq!(
            rebuilt.document["compute_workspace"],
            prior["plan"]["compute_workspace"]
        );
        assert_eq!(
            retain_or_declare(
                &mut rebuilt,
                &settings(),
                Some(&input()),
                None,
                true,
                Some(&prior)
            )
            .unwrap_err()
            .kind,
            "workspace-declaration"
        );
        assert_eq!(
            rebuilt.document["compute_workspace"],
            prior["plan"]["compute_workspace"]
        );
    }

    /// ´test:unit:workspace-launch-cli-carries-private-declaration-and-digest´
    #[test]
    fn workspace_launch_cli_carries_private_declaration_and_digest() {
        let declaration = input();
        let digest = super::declaration(&declaration).unwrap().digest;
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--letter".into(),
            "/fixture/letter".into(),
            "--compute-workspace".into(),
            declaration.clone(),
            "--expect-digest".into(),
            digest.clone(),
        ];
        let mut request = LaunchRequest::parse(&words).expect("declared act");
        let selection =
            super::super::LaunchModel::select(b"fixture", Some("gpt-6-sol"), Some("high")).unwrap();
        let argv = super::super::private_argv(
            "/fixture/lane",
            "/fixture/podman",
            Path::new("/fixture/home"),
            &request,
            3000,
            &selection,
            crate::settings::BoxBackend::Codex,
        )
        .unwrap();
        assert!(argv.windows(4).any(|w| w
            == [
                "--compute-workspace",
                &declaration,
                "--workspace-digest",
                &digest
            ]));
        request.dry_run = true;
        request.expect_digest = None;
        let preview = super::super::private_argv(
            "/fixture/lane",
            "/fixture/podman",
            Path::new("/fixture/home"),
            &request,
            3000,
            &selection,
            crate::settings::BoxBackend::Codex,
        )
        .expect("preview uses the computed grant digest");
        assert!(
            preview.windows(4).any(|w| w
                == [
                    "--compute-workspace",
                    &declaration,
                    "--workspace-digest",
                    &digest
                ]),
            "displayed private preview repeats the reviewed digest"
        );
        request.dry_run = false;
        assert_eq!(
            super::super::private_argv(
                "/fixture/lane",
                "/fixture/podman",
                Path::new("/fixture/home"),
                &request,
                3000,
                &selection,
                crate::settings::BoxBackend::Codex
            )
            .unwrap_err()
            .kind,
            "workspace-digest"
        );
        words[2] = "--round".into();
        words[3] = "work".into();
        assert_eq!(
            LaunchRequest::parse(&words).unwrap_err().kind,
            "round-selection"
        );
    }
    /// ´test:unit:workspace-private-make-uses-birth-publication-boundary´
    #[test]
    fn workspace_private_make_uses_birth_publication_boundary() {
        // Structural companion to the binding-level transaction fixture below.
        // Pin the production call, not a claim about receipt-layer recovery.
        let source = include_str!("../launch.rs");
        let body = source.split_once("fn private_make(").unwrap().1;
        let before_home = body.split_once("let mut result =").unwrap().0;
        let (_, call) = before_home
            .split_once("let retired = workspace::reserve_before_publish(")
            .expect("private_make must use the birth-before-publication helper");
        let compact: String = call.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert!(
            compact.starts_with("||{custody.create_birth(owner_home,loop_name,&birth,\"reserve\")"),
            "the first closure reserves the production birth"
        );
        assert!(
            compact.contains("},||{ifletSome(record)=prior{replace_preparation_with("),
            "replacement publication belongs to the second closure"
        );
        assert!(
            compact
                .ends_with("}else{publish_reservation(&reservation,&next)?;Ok(Vec::new())}},)?;"),
            "fresh publication belongs to the second closure"
        );
    }

    /// ´test:unit:workspace-publication-cut-keeps-retirable-mail-birth´
    #[test]
    fn workspace_publication_cut_keeps_retirable_mail_birth() {
        use loop_home::mail::{birth, configuration_store::ConfigurationStore};
        use std::os::unix::fs::PermissionsExt as _;
        for after_reservation in [false, true] {
            let root = tempfile::tempdir().expect("fixture");
            let private = root.path().join("private");
            std::fs::create_dir(&private).unwrap();
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
            let service = nix::unistd::Uid::effective().as_raw() + 1;
            let identity = birth::Identity::for_reservation(3000, "superloop-lane:R".into());
            let path = root.path().join(".reservation-R.json");
            let mut plan = plan();
            plan.document["compute_workspace"] = crate::tests::published_workspace();
            let mut record = record(&plan);
            record["mail_birth"] = json!(identity);
            let result: Result<(), LaneError> = reserve_before_publish(
                || {
                    let mut store = ConfigurationStore::open(&private, service).unwrap();
                    birth::reserve(&mut store, &identity).unwrap();
                    Ok(())
                },
                || {
                    if after_reservation {
                        publish_reservation(&path, &record)?;
                    }
                    Err(LaneError::input("fixture-cut", "publication interrupted"))
                },
            );
            assert_eq!(result.unwrap_err().kind, "fixture-cut");
            assert_eq!(path.exists(), after_reservation);
            if after_reservation {
                assert_eq!(
                    read_reservation(&path).unwrap().unwrap()["mail_birth"],
                    json!(identity)
                );
            }
            let mut store = ConfigurationStore::open(&private, service).unwrap();
            birth::retire(&mut store, &identity).expect("cut publication remains retirable");
            birth::verify_retired(&store, &identity).expect("terminal binding retained");
        }
    }

    /// ´test:unit:workspace-declaration-refuses-duplicate-resources´
    #[test]
    fn workspace_declaration_refuses_duplicate_resources() {
        let text = input();
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["grant"]["resources"] = json!({"target":"/work/R/target"});
        let text = value.to_string();
        assert!(declaration(&text).is_ok());
        let duplicate = text.replace(
            "\"resources\":{",
            "\"resources\":{\"target\":\"/elsewhere\",",
        );
        assert_ne!(duplicate, text);
        assert_eq!(
            declaration(&duplicate).unwrap_err().kind,
            "workspace-declaration"
        );
    }
}
