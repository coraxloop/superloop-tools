use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::hook::{
    EscalationSink, HOOK_CEILING_MS, HookResponseBoundary, HookTiming, Mode, ModelStage,
    NestingGuard, PermissionDecision, ReductionError, hook_ceiling_ms, scope_floor,
    verify_nesting_guard_for_test,
};
use crate::journal::RoutedJournal;
use crate::request::Scope;
use crate::role::{
    CallerRole, Registry, RegistryError, SubordinateMapping, load_registry_from_path_with_uids,
    load_registry_with_estate_uid, open_public_root, parse_registry, read_registry_entry,
    resolve_role,
};
use crate::rubric::{refused_worker_rubric_roots, rubric_root_spans, rubric_roots};
use crate::{
    DecodeResult, FastLane, MAX_REASON_BYTES, ModelError, adapt_hook, decode_request,
    nested_hook_response, reduced_action,
};

static NEXT_ESTATE_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn parsed_worker_registry(entries: &[(&str, String)]) -> Registry {
    let mut listing = Vec::new();
    let mut texts = BTreeMap::new();
    for (name, entry) in entries {
        listing.extend_from_slice(name.as_bytes());
        listing.push(b'\n');
        let entry = if entry.contains("LOOP_WORKER_UIDS=")
            && !entry.contains("LOOP_ALLOCATIONS_SHA256=")
        {
            format!(
                "{entry}LOOP_ALLOCATIONS_SHA256={}\nLOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z\n",
                "a".repeat(64)
            )
        } else {
            entry.clone()
        };
        texts.insert((*name).to_owned(), entry.into_bytes());
    }
    parse_registry(&listing, &texts)
}

fn worker_identity_registry(one_block: &str, two_block: &str) -> Registry {
    parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD=/launch/one\nLOOP_UID=41001\nLOOP_WORKER_UIDS={one_block}\n"
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_SID=two-sid\nLOOP_CWD=/launch/two\nLOOP_UID=41002\nLOOP_WORKER_UIDS={two_block}\n"
            ),
        ),
    ])
}

/// ´test:crate:worker-uid-selects-loop-before-cwd-and-session´
#[test]
fn worker_uid_selects_loop_before_cwd_and_session() {
    let registry = worker_identity_registry("40000:4", "42000:4");
    for (session, cwd) in [
        ("one-sid", "/unregistered"),
        ("two-sid", "/launch/two"),
        ("", "/unregistered"),
    ] {
        let role = resolve_role(Some(&registry), 40002, session, cwd, None, false);
        assert!(matches!(role, CallerRole::OrchestratorSubagent(_)));
        assert_eq!(role.loop_name(), Some("one"));
        assert!(!role.stale_session());
        assert!(
            matches!(role, CallerRole::OrchestratorSubagent(ref loop_match) if loop_match.worker())
        );
    }
}

/// ´test:crate:uid-outside-blocks-falls-through-to-launch-directory´
#[test]
fn uid_outside_blocks_falls_through_to_launch_directory() {
    let registry = worker_identity_registry("40000:4", "42000:4");
    let role = resolve_role(Some(&registry), 42, "one-sid", "/launch/one", None, false);
    assert!(matches!(role, CallerRole::Orchestrator(_)));
    assert_eq!(role.loop_name(), Some("one"));
    assert!(matches!(role, CallerRole::Orchestrator(ref loop_match) if !loop_match.worker()));
}

/// The fixture keeps the measured record shapes with a fixture home and synthetic session and agent identifiers, because every fact the test asserts is structural.
/// ´test:crate:measured-subagent-hook-input-shares-main-session-identity´
#[test]
fn measured_subagent_hook_input_shares_main_session_identity() {
    let measured: Value =
        serde_json::from_str(include_str!("fixtures/subagent-hook-input-2026-09-23.json"))
            .expect("dated hook input fixture");
    assert_eq!(measured["measured_at"], "2026-09-23T05:00:08Z");
    let main = &measured["main_session_bash"];
    let subagent = &measured["subagent_bash"];
    assert_eq!(main["session_id"], subagent["session_id"]);
    assert_eq!(main["transcript_path"], subagent["transcript_path"]);
    for record in [main, subagent] {
        let path = record["transcript_path"].as_str().expect("transcript path");
        assert!(!path.split('/').any(|component| component == "subagents"));
    }
    for field in ["agent_id", "agent_type"] {
        assert!(main[field].is_null(), "main session has no {field}");
        assert!(
            subagent[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "subagent has non-null {field}"
        );
    }
}

/// ´test:crate:subagent-carries-main-session-identifier-and-requires-match´
#[test]
fn subagent_carries_main_session_identifier_and_requires_match() {
    let measured: Value =
        serde_json::from_str(include_str!("fixtures/subagent-hook-input-2026-09-23.json"))
            .expect("dated hook input fixture");
    let subagent = &measured["subagent_bash"];
    let sid = measured["main_session_bash"]["session_id"]
        .as_str()
        .expect("main session identifier");
    let cwd = subagent["cwd"].as_str().expect("subagent launch directory");
    let transcript = subagent["transcript_path"]
        .as_str()
        .expect("main transcript path");
    let registry = parsed_worker_registry(&[(
        "measured.env",
        format!("LOOP_NAME=measured\nLOOP_SID={sid}\nLOOP_CWD={cwd}\n"),
    )]);
    let agent_id_truthy = subagent["agent_id"]
        .as_str()
        .is_some_and(|value| !value.is_empty());
    let role = resolve_role(
        Some(&registry),
        42,
        subagent["session_id"]
            .as_str()
            .expect("subagent identifier"),
        cwd,
        Some(transcript),
        agent_id_truthy,
    );
    assert!(matches!(role, CallerRole::OrchestratorSubagent(_)));
    assert_eq!(role.loop_name(), Some("measured"));
    assert!(!role.stale_session());
    assert!(!transcript.contains("/subagents/"));
    assert!(agent_id_truthy);

    let rotated = resolve_role(
        Some(&registry),
        42,
        "rotated-unmatched",
        cwd,
        Some(transcript),
        agent_id_truthy,
    );
    assert!(matches!(rotated, CallerRole::Unknown));
    assert!(!rotated.stale_session());
}

/// ´test:crate:missing-session-id-fails-structure-and-hook-configuration´
#[test]
fn missing_session_id_fails_structure_and_hook_configuration() {
    let registry = parsed_worker_registry(&[(
        "one.env",
        "LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_STATE_ROOT=/journals/one\n".to_owned(),
    )]);
    assert!(
        matches!(registry.validate_deployment_structure(None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail == "LOOP_SID is required by a deployable registration")
    );
    let role = resolve_role(
        Some(&registry),
        42,
        "main-session",
        "/launch/one",
        None,
        false,
    );
    assert!(matches!(role, CallerRole::Orchestrator(_)));
    let mut sink = RoutedJournal::from_environment();
    assert!(!sink.configure(Some(&registry), &role));
    assert!(
        sink.configuration_error()
            .is_some_and(|detail| detail.contains("LOOP_SID"))
    );
}

/// ´test:crate:worker-run-root-derives-from-registered-home´
#[test]
fn worker_run_root_derives_from_registered_home() {
    let registry = parsed_worker_registry(&[
        (
            "one.env",
            "LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_HOME=/loop-home\n".to_owned(),
        ),
        (
            "two.env",
            "LOOP_NAME=two\nLOOP_CWD=/launch/two\n".to_owned(),
        ),
    ]);
    let entries = registry.entries();
    assert_eq!(
        entries[0].worker_run_root(40002),
        Some(PathBuf::from("/loop-home/runs/40002"))
    );
    assert_eq!(entries[1].worker_run_root(40002), None);
}

/// ´test:crate:worker-domain-rubric-requires-registered-home´
#[test]
fn worker_domain_rubric_requires_registered_home() {
    for home in [Some("/loop-home"), None] {
        let home_line = home.map_or(String::new(), |path| format!("LOOP_HOME={path}\n"));
        let registry = parsed_worker_registry(&[(
            "one.env",
            format!("LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_WORKER_UIDS=40000:4\n{home_line}"),
        )]);
        let role = resolve_role(Some(&registry), 40002, "", "/elsewhere", None, false);
        assert_eq!(
            role.domain_rubric_path(),
            home.map(|path| Path::new(path).join("shared/permissions/domain.md"))
        );
    }
}

/// ´test:crate:orchestrator-domain-rubric-uses-estate-or-convention´
#[test]
fn orchestrator_domain_rubric_uses_estate_or_convention() {
    for registered in [true, false] {
        let rubric_line = if registered {
            "LOOP_ORCHESTRATOR_RUBRIC=/estate/loops/one/orchestrator.md\n"
        } else {
            ""
        };
        let registry = parsed_worker_registry(&[(
            "one.env",
            format!("LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD=/launch/one\n{rubric_line}"),
        )]);
        let role = resolve_role(Some(&registry), 42, "one-sid", "/launch/one", None, false);
        let expected = if registered {
            "/estate/loops/one/orchestrator.md"
        } else {
            "/launch/one/local/permissions/domain.md"
        };
        assert_eq!(
            role.domain_rubric_path().as_deref(),
            Some(Path::new(expected))
        );
    }
}

/// ´test:crate:orchestrator-rubric-layout-requires-owner-directory´
#[test]
fn orchestrator_rubric_layout_requires_owner_directory() {
    for (rubric, owner, valid) in [
        (
            "/estate/rubrics/one.md",
            Some("/estate/rubrics/owner.md"),
            true,
        ),
        ("/elsewhere/one.md", Some("/estate/rubrics/owner.md"), false),
        ("/estate/rubrics/one.md", Some("/owner.md"), false),
        ("/estate/rubrics/one.md", None, false),
    ] {
        let registry = parsed_worker_registry(&[(
            "one.env",
            format!("LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_ORCHESTRATOR_RUBRIC={rubric}\n"),
        )]);
        let result = registry.validate_rubric_layout(owner.map(Path::new));
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(RegistryError::DeploymentEntry { entry, .. }) if entry == "one")
            );
        }
    }
}

/// ´test:crate:orchestrator-rubric-parser-rejects-relative-and-dot-components´
#[test]
fn orchestrator_rubric_parser_rejects_relative_and_dot_components() {
    for rubric in [
        "relative/rubric.md",
        "/estate/../rubric.md",
        "/estate/./rubric.md",
    ] {
        let registry = parsed_worker_registry(&[(
            "one.env",
            format!("LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_ORCHESTRATOR_RUBRIC={rubric}\n"),
        )]);
        assert!(registry.entries().is_empty(), "{rubric}");
    }
}

/// ´test:crate:rubric-roots-follow-the-runtime-quoted-path-grammar´
#[test]
fn rubric_roots_follow_the_runtime_quoted_path_grammar() {
    let text = "unquoted /ignored/ `relative/` `/` `/alpha/` `/beta/*/` `/bad/../path/` `/bad/./path/` `/no-slash` `/many/**/` `/omega/`";
    assert_eq!(rubric_roots(text), ["/alpha/", "/beta/*/", "/omega/"]);
}

/// ´test:crate:rubric-root-spans-apply-the-quoted-path-grammar-once´
#[test]
fn rubric_root_spans_apply_the_quoted_path_grammar_once() {
    let text = "unquoted /ignored/ `/alpha/` and `/beta/*/`";
    assert_eq!(
        rubric_root_spans(text).collect::<Vec<_>>(),
        ["/alpha/", "/beta/*/"]
    );
    for text in [
        "`/`",
        "`alpha/`",
        "`/alpha`",
        "`/a/../b/`",
        "`/a/./b/`",
        "`/a**/`",
    ] {
        assert_eq!(rubric_root_spans(text).next(), None, "{text}");
    }
}

/// ´test:crate:worker-rubric-containment-covers-literal-wildcards-and-empty-rubrics´
#[test]
fn worker_rubric_containment_covers_literal_wildcards_and_empty_rubrics() {
    let orchestrator = "`/domain/` and `/jobs/*/`";
    assert_eq!(
        refused_worker_rubric_roots(orchestrator, "`/domain/sub/` and `/jobs/*/task/`"),
        Vec::<String>::new()
    );
    assert_eq!(
        refused_worker_rubric_roots(orchestrator, "no quoted roots"),
        Vec::<String>::new()
    );
    assert_eq!(
        refused_worker_rubric_roots(orchestrator, "`/outside/` and `/jobs/other*/task/`"),
        ["/outside/", "/jobs/other*/task/"]
    );
}

/// ´test:crate:public-root-refuses-symlink-and-foreign-owner´
#[test]
fn public_root_refuses_symlink_and_foreign_owner() {
    let fixture = EstateFixture::new();
    let root = fixture.0.join("runs/40002");
    fs::create_dir_all(&root).expect("public run root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("public root mode");
    let actual = fs::metadata(&root).expect("root metadata").uid();
    assert!(matches!(
        open_public_root(&root, actual.wrapping_add(1)),
        Err(RegistryError::DirectoryOwner { .. })
    ));
    let link = fixture.0.join("linked-runs");
    symlink(fixture.0.join("runs"), &link).expect("symlinked component");
    assert!(matches!(
        open_public_root(&link.join("40002"), actual),
        Err(RegistryError::StateRoot("root contains a symlink"))
    ));
}

/// ´test:crate:uid-in-two-worker-blocks-resolves-unknown´
#[test]
fn uid_in_two_worker_blocks_resolves_unknown() {
    let registry = worker_identity_registry("40000:4", "40002:4");
    assert!(matches!(
        resolve_role(
            Some(&registry),
            40002,
            "one-sid",
            "/launch/one",
            None,
            false
        ),
        CallerRole::Unknown
    ));
}

/// ´test:crate:worker-block-parser-drops-malformed-entry-whole´
#[test]
fn worker_block_parser_drops_malformed_entry_whole() {
    for block in [
        "40000",
        "40000:",
        ":4",
        "40000:0",
        "0:1",
        "0:4",
        "+40000:4",
        "40000:4:1",
    ] {
        let registry = parsed_worker_registry(&[(
            "one.env",
            format!("LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_WORKER_UIDS={block}\n"),
        )]);
        assert!(registry.entries().is_empty(), "invalid block {block}");
    }
    let registry = worker_identity_registry("40000:4", "42000:4");
    assert!(registry.entries().first().is_some_and(|entry| {
        entry
            .worker_uids()
            .is_some_and(|block| block.contains(40003) && !block.contains(40004))
    }));
}

fn deployable_worker_registry(
    fixture: &EstateFixture,
    one_extra: &str,
    two_extra: &str,
) -> Registry {
    let mut entries = Vec::new();
    for (name, uid, extra) in [("one", 41001, one_extra), ("two", 41002, two_extra)] {
        let checkout = fixture.0.join(name);
        let root = checkout.join("local/state");
        fs::create_dir_all(&root).expect("state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private state root");
        entries.push((format!("{name}.env"), format!("LOOP_NAME={name}\nLOOP_SID={name}-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\nLOOP_UID={uid}\n{extra}", checkout.display(), root.display())));
    }
    parsed_worker_registry(
        &entries
            .iter()
            .map(|(name, text)| (name.as_str(), text.clone()))
            .collect::<Vec<_>>(),
    )
}

/// ´test:crate:deployment-refuses-worker-block-principal-collisions´
#[test]
fn deployment_refuses_worker_block_principal_collisions() {
    let fixture = EstateFixture::new();
    for (one, two, uid, rule) in [
        (
            "LOOP_WORKER_UIDS=40000:4\n",
            "LOOP_WORKER_UIDS=40002:4\n",
            5000,
            "overlaps",
        ),
        ("LOOP_WORKER_UIDS=41002:4\n", "", 5000, "LOOP_UID"),
        ("LOOP_WORKER_UIDS=5000:4\n", "", 5000, "deployment uid"),
    ] {
        let registry = deployable_worker_registry(&fixture, one, two);
        assert!(
            matches!(registry.validate_deployment_as(uid), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains(rule))
        );
    }
}

/// ´test:crate:registered-root-outside-checkouts-validates´
#[test]
fn registered_root_outside_checkouts_validates() {
    let fixture = EstateFixture::new();
    let root = fixture.0.join("journals/one");
    fs::create_dir_all(&root).expect("journal root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let registry = parsed_worker_registry(&[(
        "one.env",
        format!(
            "LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            fixture.0.join("launch/one").display(),
            root.display()
        ),
    )]);
    registry
        .validate_deployment()
        .expect("registered absolute root is valid");
}

/// ´test:crate:registered-root-inside-any-loop-home-rejects´
#[test]
fn registered_root_inside_any_loop_home_rejects() {
    let fixture = EstateFixture::new();
    let peer_home = fixture.0.join("homes/two");
    let root = peer_home.join("runs/state");
    let other_root = fixture.0.join("journals/two");
    for path in [&root, &other_root] {
        fs::create_dir_all(path).expect("journal root");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private root");
    }
    let registry = parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/one").display(),
                root.display()
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_SID=two-sid\nLOOP_CWD={}\nLOOP_HOME={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/two").display(),
                peer_home.display(),
                other_root.display()
            ),
        ),
    ]);
    assert!(
        matches!(registry.validate_deployment(), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("LOOP_HOME"))
    );
    let equal = parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/one").display(),
                peer_home.display()
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_CWD={}\nLOOP_HOME={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/two").display(),
                peer_home.display(),
                other_root.display()
            ),
        ),
    ]);
    assert!(
        matches!(equal.validate_root_layout(&[], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("LOOP_HOME"))
    );
}

/// ´test:crate:registered-root-containing-authorization-sources-rejects´
#[test]
fn registered_root_containing_authorization_sources_rejects() {
    let fixture = EstateFixture::new();
    let root = fixture.0.join("journals/one");
    let checkout = fixture.0.join("launch/one");
    let registry = parsed_worker_registry(&[(
        "one.env",
        format!(
            "LOOP_NAME=one\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            checkout.display(),
            root.display()
        ),
    )]);
    for source in [root.join("registry"), root.join("owner.md")] {
        assert!(
            matches!(registry.validate_root_layout(&[&source], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("authorization source"))
        );
    }

    let peer_checkout = root.join("peer-checkout");
    let peer_root = fixture.0.join("journals/two");
    let peers = parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                checkout.display(),
                root.display()
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                peer_checkout.display(),
                peer_root.display()
            ),
        ),
    ]);
    assert!(
        matches!(peers.validate_root_layout(&[], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("registered rubric of two"))
    );
}

fn layout_registry(
    one_cwd: &str,
    one_home: &str,
    two_cwd: &str,
    two_home: &str,
    two_rubric: Option<&str>,
) -> Registry {
    let rubric = two_rubric.map_or(String::new(), |path| {
        format!("LOOP_ORCHESTRATOR_RUBRIC={path}\n")
    });
    parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD={one_cwd}\nLOOP_HOME={one_home}\nLOOP_STATE_ROOT=/journals/one\n"
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_SID=two-sid\nLOOP_CWD={two_cwd}\nLOOP_HOME={two_home}\nLOOP_STATE_ROOT=/journals/two\n{rubric}"
            ),
        ),
    ])
}

/// ´test:crate:authorization-source-inside-registered-home-rejects´
#[test]
fn authorization_source_inside_registered_home_rejects() {
    let registry = layout_registry(
        "/launch/one",
        "/homes/one",
        "/launch/two",
        "/homes/two",
        None,
    );
    let source = Path::new("/homes/two/rubric.md");
    assert!(
        matches!(registry.validate_root_layout(&[source], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "two" && detail.contains("authorization source") && detail.contains("LOOP_HOME"))
    );
    let registered = layout_registry(
        "/launch/one",
        "/homes/one",
        "/launch/two",
        "/homes/two",
        Some("/homes/one/orchestrator.md"),
    );
    assert!(
        matches!(registered.validate_root_layout(&[], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("authorization source") && detail.contains("LOOP_HOME"))
    );
}

/// ´test:crate:state-root-containing-peer-orchestrator-rubric-rejects´
#[test]
fn state_root_containing_peer_orchestrator_rubric_rejects() {
    let registry = layout_registry(
        "/launch/one",
        "/homes/one",
        "/launch/two",
        "/homes/two",
        Some("/journals/one/peer.md"),
    );
    assert!(
        matches!(registry.validate_root_layout(&[], None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("registered rubric of two"))
    );
}

/// ´test:crate:launch-directory-equal-or-beneath-any-home-rejects´
#[test]
fn launch_directory_equal_or_beneath_any_home_rejects() {
    for cwd in ["/homes/one", "/homes/one/launch", "/homes/two/launch"] {
        let registry = layout_registry(cwd, "/homes/one", "/launch/two", "/homes/two", None);
        assert!(
            matches!(registry.validate_deployment_structure(None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("LOOP_CWD") && detail.contains("LOOP_HOME")),
            "{cwd}"
        );
    }
}

/// ´test:crate:registered-launch-directories-equal-or-nested-reject´
#[test]
fn registered_launch_directories_equal_or_nested_reject() {
    for cwd in ["/launch/one", "/launch/one/two"] {
        let registry = layout_registry("/launch/one", "/homes/one", cwd, "/homes/two", None);
        assert!(
            matches!(registry.validate_deployment_structure(None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "two" && detail.contains("LOOP_CWD")),
            "{cwd}"
        );
    }
}

/// ´test:crate:nested-registered-homes-reject´
#[test]
fn nested_registered_homes_reject() {
    let registry = layout_registry(
        "/launch/one",
        "/homes/one",
        "/launch/two",
        "/homes/one/two",
        None,
    );
    assert!(
        matches!(registry.validate_deployment_structure(None), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "two" && detail.contains("LOOP_HOME"))
    );
}

/// ´test:crate:estate-tree-inside-registered-home-rejects´
#[test]
fn estate_tree_inside_registered_home_rejects() {
    let registry = layout_registry(
        "/launch/one",
        "/homes/one",
        "/launch/two",
        "/homes/two",
        None,
    );
    let registry_directory = Path::new("/homes/one/estate/registry");
    assert!(
        matches!(registry.validate_root_layout(&[registry_directory], Some(registry_directory)), Err(RegistryError::DeploymentEntry { entry, detail }) if entry == "one" && detail.contains("estate tree"))
    );
}

/// ´test:crate:overlapping-registered-roots-still-reject´
#[test]
fn overlapping_registered_roots_still_reject() {
    let fixture = EstateFixture::new();
    let outer = fixture.0.join("journals/one");
    let inner = outer.join("two");
    fs::create_dir_all(&inner).expect("nested roots");
    for path in [&outer, &inner] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private root");
    }
    let registry = parsed_worker_registry(&[
        (
            "one.env",
            format!(
                "LOOP_NAME=one\nLOOP_SID=one-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/one").display(),
                outer.display()
            ),
        ),
        (
            "two.env",
            format!(
                "LOOP_NAME=two\nLOOP_SID=two-sid\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
                fixture.0.join("launch/two").display(),
                inner.display()
            ),
        ),
    ]);
    assert!(
        matches!(registry.validate_deployment(), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("overlapping state roots"))
    );
}

fn fixture_mapping(uid_count: u32, gid_count: u32) -> SubordinateMapping {
    SubordinateMapping::parse(
        2000,
        b"deployer:x:2000:2000::/home/deployer:/bin/sh\n",
        format!("deployer:100000:{uid_count}\n").as_bytes(),
        format!("2000:200000:{gid_count}\n").as_bytes(),
    )
    .expect("fixture mapping")
}

/// ´test:crate:subordinate-mapping-bounds-worker-blocks-and-loop-uids´
#[test]
fn subordinate_mapping_bounds_worker_blocks_and_loop_uids() {
    let block = worker_identity_registry("40000:10", "42000:4");
    assert!(
        matches!(block.validate_subordinate_mapping(&fixture_mapping(40005, 50000)), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("subuid"))
    );
    assert!(
        matches!(block.validate_subordinate_mapping(&fixture_mapping(50000, 40005)), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("subgid"))
    );
    let uid = parsed_worker_registry(&[(
        "one.env",
        "LOOP_NAME=one\nLOOP_CWD=/launch/one\nLOOP_UID=50001\n".to_owned(),
    )]);
    assert!(
        matches!(uid.validate_subordinate_mapping(&fixture_mapping(50000, 60000)), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("subuid"))
    );
    assert!(
        matches!(uid.validate_subordinate_mapping(&fixture_mapping(60000, 50000)), Err(RegistryError::DeploymentEntry { detail, .. }) if detail.contains("subgid"))
    );
    assert!(
        block
            .validate_subordinate_mapping(&fixture_mapping(50000, 50000))
            .is_ok()
    );
}

/// ´test:crate:subordinate-mapping-requires-account-and-well-formed-matching-lines´
#[test]
fn subordinate_mapping_requires_account_and_well_formed_matching_lines() {
    assert!(matches!(
        SubordinateMapping::parse(
            2000,
            b"other:x:41001:41001::/home/other:/bin/sh\n",
            b"deployer:100000:50000\n",
            b"deployer:200000:50000\n"
        ),
        Err(RegistryError::SubordinateMapping {
            file: "/etc/passwd",
            ..
        })
    ));
    assert!(matches!(
        SubordinateMapping::parse(
            2000,
            b"deployer:x:2000:2000::/home/deployer:/bin/sh\n",
            b"deployer:bad:50000\n",
            b"deployer:200000:50000\n"
        ),
        Err(RegistryError::SubordinateMapping {
            file: "/etc/subuid",
            ..
        })
    ));
    assert!(matches!(
        SubordinateMapping::parse(
            2000,
            b"deployer:x:2000:2000::/home/deployer:/bin/sh\n",
            b"other:100000:50000\n",
            b"deployer:200000:50000\n"
        ),
        Err(RegistryError::SubordinateMapping {
            file: "/etc/subuid",
            ..
        })
    ));
    let combined = SubordinateMapping::parse(
        2000,
        b"deployer:x:2000:2000::/home/deployer:/bin/sh\n",
        b"deployer:100000:25000\n2000:125000:25000\n",
        b"deployer:200000:25000\n2000:225000:25000\n",
    )
    .expect("matching name and numeric uid ranges are summed");
    assert!(
        worker_identity_registry("40000:4", "42000:4")
            .validate_subordinate_mapping(&combined)
            .is_ok()
    );
}

struct EstateFixture(PathBuf);

impl EstateFixture {
    fn new() -> Self {
        let sequence = NEXT_ESTATE_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let home = std::env::var_os("HOME").expect("estate fixture needs a home directory");
        let path = PathBuf::from(home).join(format!(
            "permission-triage-estate-{}-{sequence}",
            std::process::id()
        ));
        for ancestor in path.ancestors().skip(1) {
            let mode = fs::metadata(ancestor)
                .unwrap_or_else(|error| panic!("fixture ancestor {}: {error}", ancestor.display()))
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o022,
                0,
                "fixture ancestor {} is group- or other-writable",
                ancestor.display()
            );
        }
        fs::create_dir(&path).expect("unique estate fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("traversable fixture parent");
        Self(path)
    }

    fn registry(&self, uid: u32) -> PathBuf {
        let registry = self.0.join("registry");
        fs::create_dir(&registry).expect("estate registry directory");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o755))
            .expect("estate directory mode");
        Self::write_entry(&registry, "estate.env", uid);
        registry
    }

    fn write_entry(registry: &Path, name: &str, uid: u32) {
        let entry = registry.join(name);
        fs::write(
            &entry,
            format!("LOOP_NAME={name}\nLOOP_CWD=/workspace/{name}\nLOOP_UID={uid}\n"),
        )
        .expect("estate entry");
        fs::set_permissions(entry, fs::Permissions::from_mode(0o644)).expect("estate entry mode");
    }
}

impl Drop for EstateFixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

/// ´test:crate:estate-registry-loads-independent-of-three-reader-uids´
#[test]
fn estate_registry_loads_independent_of_three_reader_uids() {
    let fixture = EstateFixture::new();
    let owner = fs::metadata(&fixture.0).expect("fixture owner").uid();
    let registry = fixture.registry(owner);
    for effective in [
        owner.wrapping_add(1),
        owner.wrapping_add(2),
        owner.wrapping_add(3),
    ] {
        assert_ne!(effective, owner);
        assert_eq!(
            load_registry_from_path_with_uids(&registry, effective, Some(owner))
                .expect("estate registry accepts a different reader")
                .entries()
                .len(),
            1
        );
    }
}

/// ´test:crate:estate-registry-refuses-owner-mode-and-entry-mismatches´
#[test]
fn estate_registry_refuses_owner_mode_and_entry_mismatches() {
    let fixture = EstateFixture::new();
    let owner = fs::metadata(&fixture.0).expect("fixture owner").uid();
    let foreign = owner.wrapping_add(1);
    let registry = fixture.registry(owner);
    let entry = registry.join("estate.env");

    assert!(matches!(
        load_registry_from_path_with_uids(&registry, foreign, Some(foreign)),
        Err(RegistryError::EstateOwnerMismatch { .. })
    ));
    assert!(matches!(
        read_registry_entry(&entry, entry.clone(), 0o644, foreign, true),
        Err(RegistryError::EstateOwnerMismatch { .. })
    ));
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner, None),
        Err(RegistryError::UndeclaredEstateUid(_))
    ));

    fs::set_permissions(&registry, fs::Permissions::from_mode(0o775))
        .expect("group-writable estate directory");
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, foreign, Some(owner)),
        Err(RegistryError::WritableComponent(path)) if path == registry
    ));
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o755))
        .expect("restore estate directory");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o646))
        .expect("world-writable estate entry");
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, foreign, Some(owner)),
        Err(RegistryError::WritableComponent(path)) if path == entry
    ));
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o600))
        .expect("private-mode estate entry");
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, foreign, Some(owner)),
        Err(RegistryError::EstateEntryShape(path)) if path == entry
    ));
}

/// ´test:crate:estate-registry-refuses-writable-and-symlinked-ancestors´
#[test]
fn estate_registry_refuses_writable_and_symlinked_ancestors() {
    let fixture = EstateFixture::new();
    let owner = fs::metadata(&fixture.0).expect("fixture owner").uid();
    let real = fixture.0.join("real");
    fs::create_dir(&real).expect("real ancestor");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("safe ancestor");
    let registry = real.join("registry");
    fs::create_dir(&registry).expect("registry under ancestor");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o755)).expect("estate directory");
    EstateFixture::write_entry(&registry, "estate.env", owner);
    fs::set_permissions(&real, fs::Permissions::from_mode(0o775)).expect("group-writable ancestor");
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner.wrapping_add(1), Some(owner)),
        Err(RegistryError::WritableComponent(path)) if path == real
    ));
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("restore ancestor");
    let link = fixture.0.join("linked");
    symlink(&real, &link).expect("symlink ancestor");
    assert!(matches!(
        load_registry_from_path_with_uids(&link.join("registry"), owner.wrapping_add(1), Some(owner)),
        Err(RegistryError::EstateComponentRead { path, .. }) if path == link
    ));
}

/// ´test:crate:estate-registry-requires-exactly-one-matching-loop-uid´
#[test]
fn estate_registry_requires_exactly_one_matching_loop_uid() {
    let fixture = EstateFixture::new();
    let owner = fs::metadata(&fixture.0).expect("fixture owner").uid();
    let registry = fixture.registry(owner.wrapping_add(1));
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner.wrapping_add(2), Some(owner)),
        Err(RegistryError::EstateEntryMismatch { declared, matches: 0 }) if declared == owner
    ));
    EstateFixture::write_entry(&registry, "estate.env", owner);
    EstateFixture::write_entry(&registry, "other.env", owner);
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner.wrapping_add(2), Some(owner)),
        Err(RegistryError::GenerationChanged)
    ));
}

/// ´test:crate:private-registry-retains-owner-and-entry-mode-rules´
#[test]
fn private_registry_retains_owner_and_entry_mode_rules() {
    let fixture = EstateFixture::new();
    let owner = fs::metadata(&fixture.0).expect("fixture owner").uid();
    let registry = fixture.registry(owner);
    let entry = registry.join("estate.env");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700))
        .expect("private registry directory");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o600)).expect("private registry entry");
    assert_eq!(
        load_registry_from_path_with_uids(&registry, owner, None)
            .expect("private registry loads")
            .entries()
            .len(),
        1
    );
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner.wrapping_add(1), Some(owner)),
        Err(RegistryError::DirectoryOwner { .. })
    ));
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o644))
        .expect("public-mode private entry");
    assert!(matches!(
        load_registry_from_path_with_uids(&registry, owner, None),
        Err(RegistryError::DirectoryShape)
    ));
}

/// ´test:crate:estate-uid-instance-value-has-strict-decimal-u32-grammar´
#[test]
fn estate_uid_instance_value_has_strict_decimal_u32_grammar() {
    for invalid in ["+41004", " 41004", "0x7d4", "", "4294967296"] {
        assert!(matches!(
            load_registry_with_estate_uid(None, Some(OsString::from(invalid))),
            Err(RegistryError::InvalidEstateUid)
        ));
    }
    assert!(
        load_registry_with_estate_uid(None, Some(OsString::from("41004")))
            .expect("decimal uid parses")
            .is_none()
    );
}

fn request(tool: &str, tool_input: Value) -> Vec<u8> {
    let mut value = json!({
        "session_id": "session-hook",
        "cwd": "/workspace/project",
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_use_id": "use-hook"
    });
    value["tool_input"] = tool_input;
    serde_json::to_vec(&value).expect("hook fixture serializes")
}

fn decoded_request(tool: &str, input: Value) -> DecodeResult {
    decode_request(&request(tool, input))
}

/// ´test:crate:config-custody-pairs-impose-estate-floor-outside-checkout´
#[test]
fn config_custody_pairs_impose_estate_floor_outside_checkout() {
    let registry = parsed_worker_registry(&[(
        "one.env",
        "LOOP_NAME=one\nLOOP_CWD=/workspace/project\nLOOP_HOME=/var/loops/one\n".to_owned(),
    )]);
    let role = resolve_role(Some(&registry), 42, "", "/workspace/project", None, false);
    assert!(matches!(role, CallerRole::Orchestrator(_)));

    for second in [
        "loops",
        "gnupg",
        "codex",
        "gpg-loops",
        "gh-loops",
        "custody",
    ] {
        let path = format!("/var/loops/one/runs/.config/{second}/nested/item");
        let DecodeResult::Decoded(request) =
            decoded_request("Bash", json!({ "command": format!("touch {path}") }))
        else {
            panic!("Bash fixture decodes");
        };
        assert_eq!(scope_floor(&request, &role), Scope::Estate, "{path}");
    }

    let path = "/var/loops/one/runs/a/.config/loops/b";
    let DecodeResult::Decoded(request) =
        decoded_request("Bash", json!({ "command": format!("touch {path}") }))
    else {
        panic!("nested pair fixture decodes");
    };
    assert_eq!(scope_floor(&request, &role), Scope::Estate, "{path}");
}

/// ´test:crate:bare-loops-and-checkout-config-paths-stay-loop-scoped´
#[test]
fn bare_loops_and_checkout_config_paths_stay_loop_scoped() {
    let registry = parsed_worker_registry(&[(
        "one.env",
        "LOOP_NAME=one\nLOOP_CWD=/workspace/project\nLOOP_HOME=/var/loops/one\n".to_owned(),
    )]);
    let role = resolve_role(Some(&registry), 42, "", "/workspace/project", None, false);
    assert!(matches!(role, CallerRole::Orchestrator(_)));

    for path in [
        "/var/loops/one/runs/build/output",
        "/workspace/project/.config/loops/item",
        "/var/loops/one/runs/.config/x/loops/item",
    ] {
        let DecodeResult::Decoded(request) =
            decoded_request("Bash", json!({ "command": format!("touch {path}") }))
        else {
            panic!("Bash fixture decodes");
        };
        assert_eq!(scope_floor(&request, &role), Scope::Loop, "{path}");
    }
}

/// ´test:crate:mode-has-a-closed-exact-grammar´
#[test]
fn mode_has_a_closed_exact_grammar() {
    assert_eq!(Mode::parse(OsStr::new("audit")), Some(Mode::Audit));
    assert_eq!(Mode::parse(OsStr::new("enforce")), Some(Mode::Enforce));
    for invalid in ["", "Audit", "Enforce", "audti", "auto", " audit"] {
        assert_eq!(Mode::parse(OsStr::new(invalid)), None);
    }
}

fn agent_error(defect: &'static str) -> FastLane {
    FastLane::AgentError {
        rule: "fixture-rule",
        defect,
        correction: "repair the request",
    }
}

/// ´test:crate:pure-adapter-maps-fast-lane-agent-error´
#[test]
fn pure_adapter_maps_fast_lane_agent_error() {
    let decoded = decoded_request("Bash", json!({ "command": "printf fixture" }));
    let fast = agent_error("fixture defect");
    let outcome = adapt_hook(
        &decoded,
        Some(&fast),
        ModelStage::NotRun,
        HookTiming::new(7, 0),
    );
    assert_eq!(outcome.response().decision(), PermissionDecision::Deny);
    assert_eq!(
        outcome.response().reason(),
        "correction: fixture defect; repair the request; rule=fixture-rule"
    );
    assert_eq!(
        outcome.response().additional_context(),
        "correction: fixture defect; repair the request; rule=fixture-rule; wall_ms=7 model_wall_ms=0"
    );
}

/// ´test:crate:pure-adapter-refuses-unaccepted-read-only-verdict´
#[test]
fn pure_adapter_refuses_unaccepted_read_only_verdict() {
    let decoded = decoded_request("Read", json!({ "file_path": "README.md" }));
    let fast = FastLane::ReadOnlyAllow {
        rule: "native-read",
    };
    let outcome = adapt_hook(
        &decoded,
        Some(&fast),
        ModelStage::NotRun,
        HookTiming::new(7, 0),
    );
    assert_eq!(outcome.response().decision(), PermissionDecision::Deny);
    assert_eq!(
        outcome.response().reason(),
        "infrastructure-failure: hook adapter failed: the read-only verdict did not name an accepted rule; no policy judgment was made"
    );
}

/// ´test:crate:pure-adapter-denies-model-cleanup-timeout´
#[test]
fn pure_adapter_denies_model_cleanup_timeout() {
    let decoded = decoded_request("Bash", json!({ "command": "printf fixture" }));
    let error = ModelError::CleanupTimeout;
    let outcome = adapt_hook(
        &decoded,
        Some(&FastLane::ToModel),
        ModelStage::ModelError(&error),
        HookTiming::default(),
    );
    assert_eq!(outcome.response().decision(), PermissionDecision::Deny);
    assert_eq!(
        outcome.response().reason(),
        "infrastructure-failure: model runner failed: classifier process cleanup exceeded its deadline; no policy judgment was made"
    );
}

/// ´test:crate:pure-adapter-names-the-nesting-token-mint-failure´
#[test]
fn pure_adapter_names_the_nesting_token_mint_failure() {
    let decoded = decoded_request("Bash", json!({ "command": "printf fixture" }));
    let error = ModelError::NestingTokenMint;
    let outcome = adapt_hook(
        &decoded,
        Some(&FastLane::ToModel),
        ModelStage::ModelError(&error),
        HookTiming::default(),
    );
    assert_eq!(outcome.response().decision(), PermissionDecision::Deny);
    assert_eq!(
        outcome.response().reason(),
        "infrastructure-failure: model runner failed: the classifier nesting token could not be minted; no policy judgment was made"
    );
}

/// ´test:crate:pure-adapter-command-echo-threshold-is-four-bytes´
#[test]
fn pure_adapter_command_echo_threshold_is_four_bytes() {
    for command in ["w", "ls"] {
        let decoded = decoded_request("Bash", json!({ "command": command }));
        let fast = agent_error(command);
        let outcome = adapt_hook(
            &decoded,
            Some(&fast),
            ModelStage::NotRun,
            HookTiming::default(),
        );
        assert_eq!(
            outcome.response().reason(),
            format!("correction: {command}; repair the request; rule=fixture-rule")
        );
    }

    let decoded = decoded_request("Bash", json!({ "command": "echo" }));
    let fast = agent_error("echo");
    let outcome = adapt_hook(
        &decoded,
        Some(&fast),
        ModelStage::NotRun,
        HookTiming::default(),
    );
    assert_eq!(
        outcome.response().reason(),
        "correction: reason omitted because it repeated command text"
    );
}

/// ´test:crate:pure-adapter-caps-reasons-at-one-thousand-valid-utf8-bytes´
#[test]
fn pure_adapter_caps_reasons_at_one_thousand_valid_utf8_bytes() {
    let decoded = DecodeResult::Unclassifiable {
        reason: "é".repeat(MAX_REASON_BYTES),
    };
    let outcome = adapt_hook(&decoded, None, ModelStage::NotRun, HookTiming::default());
    assert!(outcome.response().reason().len() <= MAX_REASON_BYTES);
    assert!(outcome.response().reason().ends_with('…'));
    assert!(
        outcome
            .response()
            .additional_context()
            .starts_with(outcome.response().reason())
    );
}

/// ´test:crate:hook-ceiling-variable-defaults-caps-and-refuses-invalid-values´
#[test]
fn hook_ceiling_variable_defaults_caps_and_refuses_invalid_values() {
    assert_eq!(hook_ceiling_ms(None), HOOK_CEILING_MS);
    assert_eq!(hook_ceiling_ms(Some(OsStr::new("17"))), 17);
    assert_eq!(hook_ceiling_ms(Some(OsStr::new("60000"))), HOOK_CEILING_MS);
    for value in ["60001", "not-a-number", ""] {
        assert_eq!(hook_ceiling_ms(Some(OsStr::new(value))), HOOK_CEILING_MS);
    }
    let invalid = OsString::from_vec(vec![0xff]);
    assert_eq!(hook_ceiling_ms(Some(invalid.as_os_str())), HOOK_CEILING_MS);
}

/// ´test:crate:pure-nesting-response-is-fixed-allow´
#[test]
fn pure_nesting_response_is_fixed_allow() {
    let outcome = nested_hook_response(HookTiming::new(3, 0));
    assert_eq!(outcome.response().decision(), PermissionDecision::Allow);
    assert_eq!(
        outcome.response().reason(),
        "nested invocation: classifier child hook allowed without another policy evaluation"
    );
}

/// ´test:crate:response-boundary-keeps-audit-silence-distinct-from-enforce-decisions´
#[test]
fn response_boundary_keeps_audit_silence_distinct_from_enforce_decisions() {
    let response = nested_hook_response(HookTiming::new(3, 0))
        .response()
        .clone();
    assert_eq!(
        HookResponseBoundary::for_mode(Mode::Audit, response.clone()),
        HookResponseBoundary::SilentSuccess
    );
    assert_eq!(
        HookResponseBoundary::for_mode(Mode::Enforce, response.clone()),
        HookResponseBoundary::SerializedDecision(response)
    );
}

#[derive(Clone)]
struct SyntheticProc {
    self_stat: Option<Vec<u8>>,
    stats: Vec<(u32, Vec<u8>)>,
    executables: Vec<(u32, PathBuf)>,
    current_executable: Option<PathBuf>,
}

impl SyntheticProc {
    fn valid() -> Self {
        Self {
            self_stat: Some(proc_stat(400, 300, 1_200)),
            stats: vec![
                (100, proc_stat(100, 1, 900)),
                (300, proc_stat(300, 100, 1_100)),
            ],
            executables: vec![(100, PathBuf::from("/fixture/permission-triage"))],
            current_executable: Some(PathBuf::from("/fixture/permission-triage")),
        }
    }

    fn read_self_stat(&self) -> io::Result<Vec<u8>> {
        self.self_stat.clone().ok_or_else(missing_proc_entry)
    }

    fn read_stat(&self, pid: u32) -> io::Result<Vec<u8>> {
        self.stats
            .iter()
            .find_map(|(candidate, stat)| (*candidate == pid).then(|| stat.clone()))
            .ok_or_else(missing_proc_entry)
    }

    fn read_executable(&self, pid: u32) -> io::Result<PathBuf> {
        self.executables
            .iter()
            .find_map(|(candidate, path)| (*candidate == pid).then(|| path.clone()))
            .ok_or_else(missing_proc_entry)
    }

    fn current_executable(&self) -> io::Result<PathBuf> {
        self.current_executable
            .clone()
            .ok_or_else(missing_proc_entry)
    }
}

fn missing_proc_entry() -> io::Error {
    io::Error::new(ErrorKind::NotFound, "synthetic proc entry is absent")
}

fn proc_stat(pid: u32, parent_pid: u32, start_time: u64) -> Vec<u8> {
    format!(
        "{pid} (synthetic ) process) S {parent_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start_time} 0\n"
    )
    .into_bytes()
}

fn verify_fixture(value: Option<&OsStr>, fixture: &SyntheticProc) -> NestingGuard {
    verify_nesting_guard_for_test(
        value,
        || fixture.read_self_stat(),
        |pid| fixture.read_stat(pid),
        |pid| fixture.read_executable(pid),
        || fixture.current_executable(),
    )
}

/// ´test:crate:nesting-proof-token-grammar-is-exact´
#[test]
fn nesting_proof_token_grammar_is_exact() {
    let fixture = SyntheticProc::valid();
    assert_eq!(verify_fixture(None, &fixture), NestingGuard::Absent);
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &fixture),
        NestingGuard::Verified
    );
    for malformed in [
        "",
        "100",
        "100:",
        ":900",
        "100:900:1",
        "+100:900",
        "-100:900",
        "100:+900",
        " 100:900",
        "100:900 ",
        "4294967296:900",
        "100:18446744073709551616",
        "0100:900",
        "100:0900",
        "00100:900",
        "100:00900",
    ] {
        assert_eq!(
            verify_fixture(Some(OsStr::new(malformed)), &fixture),
            NestingGuard::Failed,
            "token {malformed:?}"
        );
    }
    let non_unicode = OsString::from_vec(vec![0xff, b':', b'1']);
    assert_eq!(
        verify_fixture(Some(non_unicode.as_os_str()), &fixture),
        NestingGuard::Failed
    );
}

/// ´test:crate:nesting-proof-rejects-every-identity-failure-class´
#[test]
fn nesting_proof_rejects_every_identity_failure_class() {
    let valid = SyntheticProc::valid();

    assert_eq!(
        verify_fixture(Some(OsStr::new("999:900")), &valid),
        NestingGuard::Failed
    );
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:901")), &valid),
        NestingGuard::Failed
    );

    let mut not_ancestor = valid.clone();
    not_ancestor.stats.push((200, proc_stat(200, 1, 700)));
    not_ancestor
        .executables
        .push((200, PathBuf::from("/fixture/permission-triage")));
    assert_eq!(
        verify_fixture(Some(OsStr::new("200:700")), &not_ancestor),
        NestingGuard::Failed
    );

    let mut different_executable = valid.clone();
    different_executable.executables =
        vec![(100, PathBuf::from("/fixture/different-permission-triage"))];
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &different_executable),
        NestingGuard::Failed
    );

    let mut unreadable_self_stat = valid.clone();
    unreadable_self_stat.self_stat = None;
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &unreadable_self_stat),
        NestingGuard::Failed
    );

    let mut unreadable_ancestor_stat = valid.clone();
    unreadable_ancestor_stat
        .stats
        .retain(|(pid, _stat)| *pid != 300);
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &unreadable_ancestor_stat),
        NestingGuard::Failed
    );

    let mut unreadable_executable = valid.clone();
    unreadable_executable.executables.clear();
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &unreadable_executable),
        NestingGuard::Failed
    );

    let mut unreadable_current_executable = valid;
    unreadable_current_executable.current_executable = None;
    assert_eq!(
        verify_fixture(Some(OsStr::new("100:900")), &unreadable_current_executable),
        NestingGuard::Failed
    );
}

/// ´test:crate:reviewed-non-bash-reducers-require-safety-targets´
#[test]
fn reviewed_non_bash_reducers_require_safety_targets() {
    let DecodeResult::Decoded(write) = decoded_request(
        "Write",
        json!({ "file_path": "docs/guide.md", "content": "omitted" }),
    ) else {
        panic!("Write fixture decodes");
    };
    assert_eq!(
        reduced_action(&write).expect("Write action reduces"),
        "Write file_path=\"docs/guide.md\""
    );

    let DecodeResult::Decoded(fetch) = decoded_request(
        "WebFetch",
        json!({ "url": "https://example.invalid/page", "prompt": "omitted" }),
    ) else {
        panic!("WebFetch fixture decodes");
    };
    assert_eq!(
        reduced_action(&fetch).expect("WebFetch action reduces"),
        "WebFetch url=\"https://example.invalid/page\""
    );

    let DecodeResult::Decoded(schedule) = decoded_request(
        "ScheduleWakeup",
        json!({ "delaySeconds": 30, "prompt": "omitted", "reason": "omitted", "noop": false }),
    ) else {
        panic!("ScheduleWakeup fixture decodes");
    };
    assert_eq!(
        reduced_action(&schedule).expect("ScheduleWakeup action reduces"),
        "ScheduleWakeup delaySeconds=30"
    );

    let DecodeResult::Decoded(missing) = decoded_request("Write", json!({ "content": "body" }))
    else {
        panic!("missing target fixture still decodes generically");
    };
    assert_eq!(
        reduced_action(&missing),
        Err(ReductionError::MissingSafetyTarget)
    );
}

const LONG_REDUCER_REASON: &str = concat!(
    "reducer-cap-sentinel-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
);

fn assert_new_reducer(tool: &str, input: Value, expected: &'static str, omitted: &[&str]) {
    let decoded = decoded_request(tool, input);
    let DecodeResult::Decoded(request) = &decoded else {
        panic!("new reducer fixture decodes");
    };
    let action = reduced_action(request).expect("new action reduces");
    assert_eq!(action, expected);
    for value in omitted {
        assert!(
            !action
                .as_bytes()
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        );
    }

    let echo = agent_error(expected);
    let echoed = adapt_hook(
        &decoded,
        Some(&echo),
        ModelStage::NotRun,
        HookTiming::default(),
    );
    assert_eq!(
        echoed.response().reason(),
        "correction: reason omitted because it repeated command text"
    );
    for value in omitted {
        assert!(!echoed.response().reason().contains(value));
        assert!(!echoed.response().additional_context().contains(value));
    }

    let long = agent_error(LONG_REDUCER_REASON);
    let capped = adapt_hook(
        &decoded,
        Some(&long),
        ModelStage::NotRun,
        HookTiming::default(),
    );
    assert!(capped.response().reason().len() <= MAX_REASON_BYTES);
    assert!(capped.response().reason().ends_with('…'));
}

/// Assert that a payload missing a schema-required field cannot form a safe action.
fn assert_reducer_rejects(tool: &str, input: Value) {
    let DecodeResult::Decoded(request) = decoded_request(tool, input) else {
        panic!("incomplete reducer fixture still decodes generically");
    };
    assert_eq!(
        reduced_action(&request),
        Err(ReductionError::MissingSafetyTarget)
    );
}

/// ´test:crate:schedule-wakeup-reducer-carries-disarm-or-delay-only´
#[test]
fn schedule_wakeup_reducer_carries_disarm_or_delay_only() {
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "stop": true }),
        "ScheduleWakeup stop=true",
        &[],
    );
    assert_new_reducer(
        "ScheduleWakeup",
        json!({
            "delaySeconds": 900,
            "prompt": "wakeup-prompt-sentinel",
            "reason": "wakeup-reason-sentinel",
            "noop": false
        }),
        "ScheduleWakeup delaySeconds=900",
        &["wakeup-prompt-sentinel", "wakeup-reason-sentinel"],
    );
    assert_new_reducer("ScheduleWakeup", json!({}), "ScheduleWakeup", &[]);
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "stop": false, "delaySeconds": 900 }),
        "ScheduleWakeup delaySeconds=900",
        &[],
    );
    assert_reducer_rejects("ScheduleWakeup", json!({ "delaySeconds": "900" }));
}

/// ´test:crate:schedule-wakeup-reducer-matches-the-guard-delay-and-stop-readings´
#[test]
fn schedule_wakeup_reducer_matches_the_guard_delay_and_stop_readings() {
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "delaySeconds": 1200.5, "prompt": "wakeup-prompt-sentinel" }),
        "ScheduleWakeup delaySeconds=1200.5",
        &["wakeup-prompt-sentinel"],
    );
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "delaySeconds": 1200, "prompt": "wakeup-prompt-sentinel" }),
        "ScheduleWakeup delaySeconds=1200",
        &["wakeup-prompt-sentinel"],
    );
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "stop": 1, "prompt": "wakeup-prompt-sentinel" }),
        "ScheduleWakeup stop=true",
        &["wakeup-prompt-sentinel"],
    );
    assert_new_reducer(
        "ScheduleWakeup",
        json!({ "stop": true, "prompt": "wakeup-prompt-sentinel" }),
        "ScheduleWakeup stop=true",
        &["wakeup-prompt-sentinel"],
    );
}

/// ´test:crate:ask-user-question-reducer-carries-count-but-omits-text´
#[test]
fn ask_user_question_reducer_carries_count_but_omits_text() {
    assert_new_reducer(
        "AskUserQuestion",
        json!({
            "questions": [
                {
                    "question": "question-text-sentinel",
                    "header": "header-sentinel",
                    "multiSelect": false,
                    "options": [
                        { "label": "first-option-sentinel" },
                        { "label": "second-option-sentinel" }
                    ]
                },
                { "question": "second omitted question" }
            ],
            "metadata": {}
        }),
        "AskUserQuestion questions=2",
        &[
            "question-text-sentinel",
            "header-sentinel",
            "first-option-sentinel",
            "second-option-sentinel",
            "second omitted question",
        ],
    );
    assert_reducer_rejects("AskUserQuestion", json!({ "metadata": {} }));
}

/// ´test:crate:list-agents-reducer-is-bare´
#[test]
fn list_agents_reducer_is_bare() {
    assert_new_reducer("ListAgents", json!({}), "ListAgents", &[]);
    assert_new_reducer(
        "ListAgents",
        json!({ "channel": "channel-sentinel", "q": "query-sentinel" }),
        "ListAgents",
        &["channel-sentinel", "query-sentinel"],
    );
}

/// ´test:crate:task-output-reducer-carries-identifier-and-filters´
#[test]
fn task_output_reducer_carries_identifier_and_filters() {
    assert_new_reducer(
        "TaskOutput",
        json!({ "task_id": "task-7", "block": true, "timeout": 30_000 }),
        "TaskOutput task_id=\"task-7\" block=true timeout=30000",
        &[],
    );
    assert_new_reducer(
        "TaskOutput",
        json!({ "task_id": "task-7" }),
        "TaskOutput task_id=\"task-7\"",
        &[],
    );
    assert_reducer_rejects("TaskOutput", json!({ "block": true }));
}

/// ´test:crate:exit-plan-mode-reducer-is-bare´
#[test]
fn exit_plan_mode_reducer_is_bare() {
    assert_new_reducer(
        "ExitPlanMode",
        json!({ "allowedPrompts": ["allowed-prompt-sentinel"], "plan": "plan-body-sentinel" }),
        "ExitPlanMode",
        &["allowed-prompt-sentinel", "plan-body-sentinel"],
    );
    assert_new_reducer("ExitPlanMode", json!({}), "ExitPlanMode", &[]);
}

/// ´test:crate:agent-reducer-carries-shape-but-omits-prompt´
#[test]
fn agent_reducer_carries_shape_but_omits_prompt() {
    assert_new_reducer(
        "Agent",
        json!({
            "subagent_type": "general-purpose",
            "model": "sonnet",
            "description": "review reducers",
            "isolation": "worktree",
            "run_in_background": true,
            "prompt": "prompt-body-sentinel"
        }),
        "Agent subagent_type=\"general-purpose\" model=\"sonnet\" description=\"review reducers\" isolation=\"worktree\" run_in_background=true prompt_bytes=20",
        &["prompt-body-sentinel"],
    );
}

/// ´test:crate:agent-reducer-accepts-the-schema-minimum´
#[test]
fn agent_reducer_accepts_the_schema_minimum() {
    assert_new_reducer(
        "Agent",
        json!({ "description": "review reducers", "prompt": "prompt-body-sentinel" }),
        "Agent description=\"review reducers\" prompt_bytes=20",
        &["prompt-body-sentinel"],
    );
    assert_reducer_rejects("Agent", json!({ "prompt": "prompt-body-sentinel" }));
    assert_reducer_rejects("Agent", json!({ "description": "review reducers" }));
}

/// ´test:crate:legacy-task-reducer-carries-shape-but-omits-prompt´
#[test]
fn legacy_task_reducer_carries_shape_but_omits_prompt() {
    assert_new_reducer(
        "Task",
        json!({
            "subagent_type": "Explore",
            "description": "inspect tree",
            "prompt": "legacy-prompt-body"
        }),
        "Task subagent_type=\"Explore\" description=\"inspect tree\" prompt_bytes=18",
        &["legacy-prompt-body"],
    );
}

/// ´test:crate:send-message-reducer-carries-addressee-and-message-length´
#[test]
fn send_message_reducer_carries_addressee_and_message_length() {
    assert_new_reducer(
        "SendMessage",
        json!({
            "to": "worker-a",
            "message": "message-body-sentinel",
            "summary": "omitted-summary",
            "notify_when_idle": true
        }),
        "SendMessage to=\"worker-a\" message_bytes=21 notify_when_idle=true",
        &["message-body-sentinel", "omitted-summary"],
    );
    assert_new_reducer(
        "SendMessage",
        json!({ "to": "worker-a", "message": "message-body-sentinel" }),
        "SendMessage to=\"worker-a\" message_bytes=21",
        &["message-body-sentinel"],
    );
    assert_reducer_rejects("SendMessage", json!({ "message": "message-body-sentinel" }));
    assert_reducer_rejects("SendMessage", json!({ "to": "worker-a" }));
}

/// ´test:crate:task-stop-reducer-accepts-either-identifier-spelling´
#[test]
fn task_stop_reducer_accepts_either_identifier_spelling() {
    assert_new_reducer(
        "TaskStop",
        json!({ "task_id": "task-7" }),
        "TaskStop task_id=\"task-7\"",
        &[],
    );
    assert_new_reducer(
        "TaskStop",
        json!({ "shell_id": "shell-2" }),
        "TaskStop shell_id=\"shell-2\"",
        &[],
    );
    assert_new_reducer("TaskStop", json!({}), "TaskStop", &[]);
}

/// ´test:crate:tool-search-reducer-carries-query-verbatim´
#[test]
fn tool_search_reducer_carries_query_verbatim() {
    assert_new_reducer(
        "ToolSearch",
        json!({ "query": "select:mcp__server__tool", "max_results": 5 }),
        "ToolSearch query=\"select:mcp__server__tool\"",
        &[],
    );
    assert_reducer_rejects("ToolSearch", json!({ "max_results": 5 }));
}

/// ´test:crate:skill-reducer-carries-name-and-arguments-verbatim´
#[test]
fn skill_reducer_carries_name_and_arguments_verbatim() {
    assert_new_reducer(
        "Skill",
        json!({ "skill": "slides", "args": "--theme dusk" }),
        "Skill name=\"slides\" arguments=\"--theme dusk\"",
        &[],
    );
    assert_new_reducer(
        "Skill",
        json!({ "skill": "slides" }),
        "Skill name=\"slides\"",
        &[],
    );
    assert_reducer_rejects("Skill", json!({ "args": "--theme dusk" }));
}

/// ´test:crate:notebook-edit-reducer-carries-path-and-optional-cell´
#[test]
fn notebook_edit_reducer_carries_path_and_optional_cell() {
    assert_new_reducer(
        "NotebookEdit",
        json!({
            "notebook_path": "/workspace/study.ipynb",
            "cell_id": "cell-4",
            "new_source": "notebook-source-sentinel"
        }),
        "NotebookEdit notebook_path=\"/workspace/study.ipynb\" cell_id=\"cell-4\"",
        &["notebook-source-sentinel"],
    );
    assert_new_reducer(
        "NotebookEdit",
        json!({
            "notebook_path": "/workspace/study.ipynb",
            "new_source": "notebook-source-sentinel"
        }),
        "NotebookEdit notebook_path=\"/workspace/study.ipynb\"",
        &["notebook-source-sentinel"],
    );
    assert_reducer_rejects("NotebookEdit", json!({ "new_source": "body" }));
}

/// ´test:crate:web-fetch-reducer-carries-url-but-omits-the-prompt´
#[test]
fn web_fetch_reducer_carries_url_but_omits_the_prompt() {
    assert_new_reducer(
        "WebFetch",
        json!({ "url": "https://example.invalid/page", "prompt": "fetch-prompt-sentinel" }),
        "WebFetch url=\"https://example.invalid/page\"",
        &["fetch-prompt-sentinel"],
    );
    assert_reducer_rejects("WebFetch", json!({ "prompt": "fetch-prompt-sentinel" }));
}

/// ´test:crate:web-search-reducer-carries-query-but-omits-domain-filters´
#[test]
fn web_search_reducer_carries_query_but_omits_domain_filters() {
    assert_new_reducer(
        "WebSearch",
        json!({ "query": "permission gate", "allowed_domains": ["omitted.invalid"] }),
        "WebSearch query=\"permission gate\"",
        &["omitted.invalid"],
    );
    assert_reducer_rejects(
        "WebSearch",
        json!({ "allowed_domains": ["omitted.invalid"] }),
    );
}

/// ´test:crate:enter-worktree-reducer-carries-the-named-worktree´
#[test]
fn enter_worktree_reducer_carries_the_named_worktree() {
    assert_new_reducer(
        "EnterWorktree",
        json!({ "name": "lane-work" }),
        "EnterWorktree name=\"lane-work\"",
        &[],
    );
    assert_new_reducer(
        "EnterWorktree",
        json!({ "path": "/workspace/tree" }),
        "EnterWorktree path=\"/workspace/tree\"",
        &[],
    );
    assert_new_reducer("EnterWorktree", json!({}), "EnterWorktree", &[]);
}

/// ´test:crate:exit-worktree-reducer-carries-disposition-and-discard-flag´
#[test]
fn exit_worktree_reducer_carries_disposition_and_discard_flag() {
    assert_new_reducer(
        "ExitWorktree",
        json!({ "action": "remove", "discard_changes": true }),
        "ExitWorktree action=\"remove\" discard_changes=true",
        &[],
    );
    assert_new_reducer(
        "ExitWorktree",
        json!({ "action": "keep" }),
        "ExitWorktree action=\"keep\"",
        &[],
    );
    assert_reducer_rejects("ExitWorktree", json!({ "discard_changes": true }));
}

fn assert_keywords_reducer(tool: &'static str, expected: &'static str) {
    assert_new_reducer(
        tool,
        json!({ "keywords": ["catalogue", "gate \"quoted\""] }),
        expected,
        &[],
    );
}

/// ´test:crate:list-plugins-reducer-treats-keywords-as-optional´
#[test]
fn list_plugins_reducer_treats_keywords_as_optional() {
    assert_keywords_reducer(
        "ListPlugins",
        "ListPlugins keywords=[\"catalogue\",\"gate \\\"quoted\\\"\"]",
    );
    assert_new_reducer("ListPlugins", json!({}), "ListPlugins", &[]);
}

/// ´test:crate:list-skills-reducer-treats-keywords-as-optional´
#[test]
fn list_skills_reducer_treats_keywords_as_optional() {
    assert_keywords_reducer(
        "ListSkills",
        "ListSkills keywords=[\"catalogue\",\"gate \\\"quoted\\\"\"]",
    );
    assert_new_reducer("ListSkills", json!({}), "ListSkills", &[]);
}

/// ´test:crate:search-plugins-reducer-requires-keywords´
#[test]
fn search_plugins_reducer_requires_keywords() {
    assert_keywords_reducer(
        "SearchPlugins",
        "SearchPlugins keywords=[\"catalogue\",\"gate \\\"quoted\\\"\"]",
    );
    assert_reducer_rejects("SearchPlugins", json!({}));
}

/// ´test:crate:search-skills-reducer-requires-keywords´
#[test]
fn search_skills_reducer_requires_keywords() {
    assert_keywords_reducer(
        "SearchSkills",
        "SearchSkills keywords=[\"catalogue\",\"gate \\\"quoted\\\"\"]",
    );
    assert_reducer_rejects("SearchSkills", json!({}));
}

/// ´test:crate:artifact-reducer-carries-targets-but-omits-page-content´
#[test]
fn artifact_reducer_carries_targets_but_omits_page_content() {
    assert_new_reducer(
        "Artifact",
        json!({
            "action": "publish",
            "file_path": "report.html",
            "url": "https://example.invalid/report",
            "title": "artifact-title-sentinel",
            "description": "artifact-description-sentinel"
        }),
        "Artifact action=\"publish\" file_path=\"report.html\" url=\"https://example.invalid/report\"",
        &["artifact-title-sentinel", "artifact-description-sentinel"],
    );
}

/// ´test:crate:artifact-reducer-accepts-the-implicit-publish-action´
#[test]
fn artifact_reducer_accepts_the_implicit_publish_action() {
    assert_new_reducer(
        "Artifact",
        json!({ "file_path": "report.html", "title": "artifact-title-sentinel" }),
        "Artifact file_path=\"report.html\"",
        &["artifact-title-sentinel"],
    );
}

/// ´test:crate:monitor-websocket-form-reduces-to-its-url´
#[test]
fn monitor_websocket_form_reduces_to_its_url() {
    assert_new_reducer(
        "Monitor",
        json!({
            "ws": { "url": "wss://events.example.invalid/stream", "protocols": ["v1"] },
            "description": "monitor-description-sentinel",
            "timeout_ms": 300_000,
            "persistent": false
        }),
        "Monitor ws=\"wss://events.example.invalid/stream\"",
        &["monitor-description-sentinel"],
    );
    assert_reducer_rejects(
        "Monitor",
        json!({ "ws": { "protocols": ["v1"] }, "description": "watch" }),
    );
}

/// ´test:crate:monitor-command-form-reduces-to-the-bare-command´
#[test]
fn monitor_command_form_reduces_to_the_bare_command() {
    assert_new_reducer(
        "Monitor",
        json!({
            "command": "tail -f build.log",
            "description": "monitor-description-sentinel",
            "timeout_ms": 3_600_000,
            "persistent": true
        }),
        "tail -f build.log",
        &["monitor-description-sentinel"],
    );
    assert_reducer_rejects(
        "Monitor",
        json!({ "command": "tail -f build.log", "timeout_ms": 3_600_001 }),
    );
    assert_reducer_rejects("Monitor", json!({ "description": "watch" }));
}

/// ´test:crate:unknown-tool-reducer-carries-sorted-keys-without-values´
#[test]
fn unknown_tool_reducer_carries_sorted_keys_without_values() {
    assert_new_reducer(
        "FutureTool",
        json!({ "zeta": "secret-zeta", "alpha": "secret-alpha" }),
        "FutureTool fields=[\"alpha\",\"zeta\"]",
        &["secret-zeta", "secret-alpha"],
    );
}

/// ´test:crate:tools-absent-from-the-harness-roster-take-the-unknown-tool-path´
#[test]
fn tools_absent_from_the_harness_roster_take_the_unknown_tool_path() {
    assert_new_reducer(
        "Glob",
        json!({ "pattern": "glob-pattern-sentinel" }),
        "Glob fields=[\"pattern\"]",
        &["glob-pattern-sentinel"],
    );
    assert_new_reducer(
        "Grep",
        json!({ "pattern": "grep-pattern-sentinel" }),
        "Grep fields=[\"pattern\"]",
        &["grep-pattern-sentinel"],
    );
    assert_new_reducer(
        "TodoWrite",
        json!({ "todos": [{ "content": "todo-text-sentinel" }] }),
        "TodoWrite fields=[\"todos\"]",
        &["todo-text-sentinel"],
    );
    assert_new_reducer(
        "BashOutput",
        json!({ "bash_id": "bash-identifier-sentinel" }),
        "BashOutput fields=[\"bash_id\"]",
        &["bash-identifier-sentinel"],
    );
    assert_new_reducer(
        "KillShell",
        json!({ "shell_id": "shell-identifier-sentinel" }),
        "KillShell fields=[\"shell_id\"]",
        &["shell-identifier-sentinel"],
    );
    assert_new_reducer(
        "MultiEdit",
        json!({ "edits": [{ "file_path": "multi-edit-path-sentinel" }] }),
        "MultiEdit fields=[\"edits\"]",
        &["multi-edit-path-sentinel"],
    );
}

/// ´test:crate:mcp-server-segment-is-anchored-against-separator-forgery´
#[test]
fn mcp_server_segment_is_anchored_against_separator_forgery() {
    assert_new_reducer(
        "mcp__filesystem__x__tool",
        json!({ "path": "/private/forged-path", "secret": "forged-mcp-secret" }),
        "mcp__filesystem__x__tool fields=[\"path\",\"secret\"]",
        &["/private/forged-path", "forged-mcp-secret"],
    );
}

/// ´test:crate:unallowlisted-mcp-tool-uses-value-free-unknown-reduction´
#[test]
fn unallowlisted_mcp_tool_uses_value_free_unknown_reduction() {
    assert_new_reducer(
        "mcp__unreviewed__call",
        json!({ "secret": "mcp-secret", "path": "/private/mcp-path" }),
        "mcp__unreviewed__call fields=[\"path\",\"secret\"]",
        &["mcp-secret", "/private/mcp-path"],
    );
}

/// ´test:crate:allowlisted-mcp-tool-carries-only-reviewed-string-fields´
#[test]
fn allowlisted_mcp_tool_carries_only_reviewed_string_fields() {
    assert_new_reducer(
        "mcp__filesystem__read_file",
        json!({ "path": "/workspace/project/README.md", "content": "mcp-page-sentinel" }),
        "mcp filesystem read_file path=\"/workspace/project/README.md\"",
        &["mcp-page-sentinel"],
    );
}

/// ´test:crate:stateful-modules-deny-raw-indexing´
#[test]
fn stateful_modules_deny_raw_indexing() {
    for source in [
        include_str!("../journal.rs"),
        include_str!("../review.rs"),
        include_str!("../hook.rs"),
        include_str!("../proc.rs"),
    ] {
        assert!(source.starts_with("#![deny(clippy::indexing_slicing)]"));
    }
}

/// ´test:crate:hook-module-doc-names-environment-inputs-and-pure-adapter´
#[test]
fn hook_module_doc_names_environment_inputs_and_pure_adapter() {
    let source = include_str!("../hook.rs");
    for contract in [
        "configured_hook_ceiling",
        "PERMISSION_TRIAGE_NESTED",
        "`adapt_hook` itself remains a pure response adapter",
    ] {
        assert!(source.contains(contract));
    }
}
