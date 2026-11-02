// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Control protocol, list comparison, and atomic maintenance tests.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`label_debt_round_trips_through_its_finding_fingerprint`] | control | Label debt appends under the fingerprint emitted from the check finding, and the next observation matches that row as tolerated debt. |
//! | [`a_rendered_list_loads_back_unchanged`] | control | A list the writer renders is a list the loader reads back unchanged, so a maintained declaration stays a declaration rather than becoming something only the writer can read. The rows come back in decoded byte-path order whatever order they were written in. |
//! | [`a_kept_reason_round_trips_through_a_rendered_list`] | control | A kept reason is read as the row's own text and rendered after its ceiling with TOML escaping, so a rewritten list carries the same reason back into the decoded row. # Panics Panics only if the temporary fixture cannot be read, written, or parsed. |
//! | [`a_blank_kept_reason_refuses_the_snapshot`] | control | The ordinary loader refuses both empty and whitespace-only kept reasons instead of accepting a marked row whose reason says nothing. |
//! | [`a_rendered_instanced_list_keeps_its_families_apart`] | control | A rendering keeps the deployments of one program apart, because a family is part of a pair's identity rather than a note beside it. Two invented deployments of one parameterized program are written under two distinct three-component keys and read back as the two pairs they were; a writer that emitted only owner and policy would put both under one key and hand back a file the loader refuses as a duplicate table. The families are invented rather than borrowed from this repository's own declaration, because what is under test is a family the writer has never seen rather than the three this corpus happens to deploy. |
//! | [`a_corpus_spanning_register_crosses_a_rewrite_whole`] | control | A rewrite carries every row the declaration stands on, including the rows of a census whose policy places them outside the owner they are filed under. Appending to one row of a corpus-spanning register leaves the other exactly where it was: the permissive reading an append renders from asks owner containment under the same condition the ordinary loader asks it, so a row the loader accepts is a row the writer keeps. |
//! | [`an_instanced_key_crosses_a_rewrite_whole`] | control | An instanced key crosses a rewrite whole. A key naming an instance document and one of its set entries is read as the program that entry deploys, so the tables standing at such keys are carried by the reading a rewrite renders from rather than dropped as though their middle component were a policy name nobody catalogues. |
//! | [`an_append_refuses_a_declaration_a_rewrite_would_truncate`] | control | An append refuses outright when the reading it would render from could not carry every declared row, and it names the rows at risk. The whole-file rewrite renders what that reading holds and nothing else, so a row missing from it is a row the write would delete; the question is therefore asked of the declaration entire rather than of the target's own table, and the file is left byte for byte as it stood. |
//! | [`an_append_refuses_a_zero_ceiling_row`] | control | An append over a declaration with a zero-ceiling row refuses the lossy rewrite and names the row it would delete. # Panics Panics only if the temporary fixture cannot be read or written. |
//! | [`path_set_control_observes_the_file_until_every_half_conforms`] | control | SPDX audit observes a failing file once however many halves fail. Listed failure is equal, unlisted failure is growth, and a listed file becomes stale only after its remaining half is repaired; shrink is unreachable because both registered and observed are set membership. Append accepts the maximum-free growth row, lowering removes the stale row, and named exclusions remain non-failing explanations throughout. |
//! | [`an_envelope_defect_is_observation_rather_than_disagreement`] | control | An envelope defect is the observation these modes compare and record, so it neither makes an audit incoherent nor blocks the append growth door — the same standing a header failure already has at the other path-set policy. A door that refused to open under it could never record the debt the burn-down ruling declares. A section defect keeps blocking, because a share that is not divided is a configuration disagreeing with the tree rather than an observation of one. |
//! | [`a_non_text_name_is_observation_rather_than_disagreement`] | control | A non-text name is an observation of the tree that the path-set list can record, so audit sees its growth and append can record it without treating it as a configuration disagreement; the next audit sees the same path as equal. |
//! | [`an_audit_classifies_each_identity_exactly_once`] | control | An audit classifies every selected identity exactly once, against what the tree holds now: a ceiling the tree meets is equal, one the tree exceeds is growth, one above what the tree holds is shrink, and a row the tree no longer answers at all is stale. |
//! | [`the_response_file_and_the_returned_bytes_are_one`] | control | The response file and the stdout object are the same bytes: the file is made durable first and the caller copies it, so the receipt travelling with a change and the object a caller reads cannot tell different stories. The digests it carries are of the request and of the list as it stands. |
//! | [`an_audit_reports_a_defect_rather_than_refusing_it`] | control | An audit reports a declaration defect rather than refusing it, which is the recovery role it exists for: a caller finding out what the lists say needs an answer from exactly the configuration no policy could run against. The run completes and exits with findings. |
//! | [`append_accepts_only_current_growth_at_the_observation`] | control | Append accepts a row only when it names growth the tree currently holds and its ceiling equals exactly that observation. A row the tree has not grown past, one above the observation, one below it, and one naming nothing the tree holds are each refused, so an append records a debt the tree already carries and cannot pre-authorize one not yet written. |
//! | [`one_refused_row_refuses_the_whole_batch`] | control | The batch is atomic: one refused row refuses all of them, the list is left exactly as it stood, and both digests are equal. A request is accepted as the ruling it claims to be rather than partially applied into a state nobody ruled on. |
//! | [`the_lowering_writer_never_raises_a_ceiling`] | control | The lowering writer lowers a ceiling to what the census now finds and removes a row whose occurrences are gone, and it never raises one: growth passes the other door or none. |
//! | [`a_kept_row_still_ratchets_in_both_directions`] | control | Marking a row kept changes no ratchet judgment: an observation above its ceiling raises growth, and one below its ceiling raises a stale entry. |
//! | [`lowering_preserves_a_kept_reason`] | control | Lowering a kept row moves its ceiling to the census and writes its reason beside the new ceiling. # Panics Panics only if the temporary fixture cannot be compiled, written, or parsed. |
//! | [`the_configuration_verdict_reaches_both_modes`] | control | An audit answers the partition and the dependency closure as well as the list comparison, because both are asked of the declarations the list file is checked against rather than of the list file itself. An append refuses outright under the same answer, since every writing mode refuses to mutate under a snapshot that disagrees with the tree. |
//! | [`a_response_may_not_overwrite_what_it_reports_on`] | control | A maintenance run may not overwrite the thing it is reporting on, and may not write its receipt into the declared surface. This is a refused precondition, so the declaration and the response path are left untouched. |
//! | [`a_request_that_does_not_validate_refuses_the_run`] | control | A request the command cannot make sense of refuses the run: an unknown schema, a pair the declaration does not activate, a codec the policy does not select, an audit selector carrying a ceiling, and an authority with an empty field are each a precondition failure rather than a partial answer. |

use std::collections::BTreeMap;
use std::path::Path;

use tempfile::TempDir;

use crate::control::finding_fingerprint;
use crate::pattern::BytePath;
use crate::snapshot::{Configuration, Snapshot, configuration};
use crate::test_support::{byte_named_fixture, initialise_and_track, track_all};
use crate::{
    Control, ExecutionPlan, Finding, Operation, Pair, Rows, check, lower, maintain, render_lists,
};

/// The pair every fixture declares: project B's section-reference debt.
fn pair() -> Pair {
    Pair::singleton("PROJECTB", "legacy.section-references")
}

/// The canonical prefix retained while the list tables are rendered.
const LISTS_ENVELOPE: &str = "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n";

/// The typed empty JSON array expected by response assertions.
const EMPTY_JSON_ARRAY: &[serde_json::Value] = &[];

/// Write a tree carrying the given prose under project B's documentation
/// surface, beside a declaration whose one activated pair counts it.
///
/// The prose is recognizer test data rather than a reference this corpus
/// makes, which is why every burn census excludes the linter's own package:
/// a recognizer is tested against the forms it recognizes.
fn tree(prose: &str, rows: &str) -> TempDir {
    let root = TempDir::new().expect("a temporary root");

    write(root.path(), "packages/project-b/docs/note.md", prose);

    write(
        root.path(),
        ".linter/owners.toml",
        "namespace = \"org.example.linter.owners\"\n\
             version = [1, 0, 0]\n\
             \n\
             root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"PROJECTB\"]\n\
             partitions = [{ name = \"project-b-package\", owner = \"PROJECTB\", pattern = '%s\"packages/project-b\" [ \"/\" *VCHAR ]' }, \
             { name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }]\n\
             may_cite = []\n",
    );
    write(
        root.path(),
        ".linter/environments.toml",
        "namespace = \"org.example.linter.environments\"\n\
             version = [1, 0, 0]\n\
             \n\
             environments = []\n",
    );
    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"org.example.linter.policies\"\n\
             version = [1, 0, 0]\n\
             \n\
             policies = [{ owner = \"PROJECTB\", policy = \"legacy.section-references\" }, { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }]\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        &format!(
            "namespace = \"class.linter.lists\"\n\
                 version = [1, 0, 0]\n\
                 \n\
                 [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n\
                 [PROJECTB.\"legacy.section-references\"]\npath_counts = [{rows}]\n"
        ),
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\n\
             version = [1, 0, 0]\n\
             \n\
             universe = \"git-tracked\"\n\
             \n\
             ignore = []\n",
    );
    // A census looks where the corpus says it does, and it says so in the
    // document of the policy that activates it, so a fixture whose ratchet is
    // about a census declares that policy's own surface.
    write(
        root.path(),
        ".linter/policy-legacy-section-references.toml",
        "namespace = \"class.linter.policy.legacy.section-references\"\n\
             version = [1, 0, 0]\n\
             \n\
             [owners.PROJECTB]\n\
             prose = '%s\"packages/project-b/docs\" [ \"/\" *VCHAR ]'\n\
             code = '%s\"packages/project-b/src\" [ \"/\" *VCHAR ]'\n",
    );

    initialise_and_track(root.path());

    root
}

/// Write one label-calculus tree carrying exactly one unpaired-backtick finding.
fn label_tree() -> TempDir {
    let root = TempDir::new().expect("a temporary root");

    write(
        root.path(),
        "note.md",
        "A paragraph carries one unpaired ` delimiter.\n",
    );
    write(
        root.path(),
        ".linter/owners.toml",
        "namespace = \"org.example.linter.owners\"\n\
             version = [1, 0, 0]\n\
             \n\
             root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
             partitions = [{ name = \"everything\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
             may_cite = []\n",
    );
    write(
        root.path(),
        ".linter/environments.toml",
        "namespace = \"org.example.linter.environments\"\n\
             version = [1, 0, 0]\n\
             \n\
             environments = []\n",
    );
    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"org.example.linter.policies\"\n\
             version = [1, 0, 0]\n\
             \n\
             policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\n\
             version = [1, 0, 0]\n\
             \n\
             [PROJECTA.\"labels.mints-well-formed\"]\n\
             allowances = []\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\n\
             version = [1, 0, 0]\n\
             \n\
             universe = \"git-tracked\"\n\
             \n\
             ignore = []\n",
    );

    initialise_and_track(root.path());
    root
}

/// Write a tree whose declaration deploys one parameterized program twice
/// beside a pair declared once, so a rendering of it has to hold two
/// families apart under a single policy and leave the family-less pair
/// spelled as it always was.
///
/// The tree is the ordinary fixture's, rewritten at the two declarations
/// that name pairs: everything else a load reads is what it already was.
fn instanced_tree() -> TempDir {
    let root = tree("A note carrying no reference at all.\n", "");

    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"org.example.linter.policies\"\n\
             version = [1, 0, 0]\n\
             \n\
             policies = [\n  \
             { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" },\n  \
             { owner = \"PROJECTB\", policy = \"legacy.section-references\" },\n  \
             { owner = \"PROJECTB\", policy = \"references.prefix-numbers-absent\" },\n\
             ]\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\n\
             version = [1, 0, 0]\n\
             \n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n\
             [PROJECTB.\"legacy.section-references\"]\npath_counts = []\n\
             \n\
             [PROJECTB.\"policy.references.quarry-numbers\".\"invented-alpha\"]\n\
             path_counts = [{ path = \"packages/project-b/docs/note.md\", maximum = 2 }]\n\
             \n\
             [PROJECTB.\"policy.references.quarry-numbers\".\"invented-beta\"]\npath_counts = []\n",
    );
    write(
        root.path(),
        ".linter/policy-quarry-numbers.toml",
        "namespace = \"class.linter.policy.references.quarry-numbers\"\n\
             version = [1, 0, 0]\n\
             \n\
             [set.prefix-numbers]\n\
             invented-alpha = { prefix = \"QA-\", exact = [\"1\"] }\n\
             invented-beta = { prefix = \"QB-\", exact = [\"2\"] }\n",
    );

    track_all(root.path());

    root
}

/// Write a tree whose one register is a census declared over the corpus root,
/// carrying rows whose files the partition attributes to another owner.
///
/// That is the shape a corpus-spanning census earns rather than a defect: the
/// census reaches every share at once and its ratchet is one repository-wide
/// artifact filed under the owner that activated it, wherever the counted
/// files stand (´[TOOLS-rule:lintcontracts:ownership]´). The fixture holds two
/// such rows so that appending to one of them still leaves the other to
/// survive the rewrite.
fn spanning_tree() -> TempDir {
    let root = tree("As §10.3 requires, and §11.1 also.\n", "");

    write(
        root.path(),
        "packages/project-b/docs/other.md",
        "As §12.4 requires.\n",
    );

    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"org.example.linter.policies\"\n\
             version = [1, 0, 0]\n\
             \n\
             policies = [{ owner = \"PROJECTA\", policy = \"legacy.section-references-repository\" }, { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }]\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\n\
             version = [1, 0, 0]\n\
             \n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n[PROJECTA.\"legacy.section-references-repository\"]\n\
             path_counts = [\n  \
             { path = \"packages/project-b/docs/note.md\", maximum = 1 },\n  \
             { path = \"packages/project-b/docs/other.md\", maximum = 1 },\n\
             ]\n",
    );
    std::fs::remove_file(
        root.path()
            .join(".linter/policy-legacy-section-references.toml"),
    )
    .expect("the retired document");
    write(
        root.path(),
        ".linter/policy-legacy-section-references-repository.toml",
        "namespace = \"class.linter.policy.legacy.section-references-repository\"\n\
             version = [1, 0, 0]\n\
             \n\
             [owners.PROJECTA]\n\
             prose = '*VCHAR'\n\
             code = '*VCHAR'\n",
    );

    track_all(root.path());

    root
}

/// A request naming the corpus-spanning pair, with these rows.
fn spanning_request(operation: &str, rows: &str) -> String {
    format!(
        r#"{{
              "schema": 1,
              "operation": "{operation}",
              "targets": [
                {{
                  "owner": "PROJECTA",
                  "policy": "legacy.section-references-repository",
                  "syntax": "path-count",
                  "rows": [{rows}],
                  "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
                }}
              ]
            }}"#
    )
}

/// Write a header-policy tree carrying equal, growth and half-repaired debt.
fn spdx_tree() -> TempDir {
    let root = TempDir::new().expect("a temporary root");

    write(
        root.path(),
        "src/equal.rs",
        "// SPDX-License-Identifier: GPL-3.0-or-later\n\nfn equal() {}\n",
    );
    write(root.path(), "src/growth.rs", "fn growth() {}\n");
    write(
        root.path(),
        "src/stale.rs",
        "// SPDX-License-Identifier: GPL-3.0-or-later\n\nfn stale() {}\n",
    );
    write(
        root.path(),
        "src/excluded.rs",
        "// SPDX-License-Identifier: GPL-3.0-or-later\n\nfn excluded() {}\n",
    );
    write(
        root.path(),
        ".linter/owners.toml",
        "namespace = \"org.example.linter.owners\"\n\
             version = [1, 0, 0]\n\
             \n\
             root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
             partitions = [{ name = \"everything\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
             may_cite = []\n",
    );
    write(
        root.path(),
        ".linter/environments.toml",
        "namespace = \"org.example.linter.environments\"\n\
             version = [1, 0, 0]\n\
             \n\
             environments = []\n",
    );
    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"org.example.linter.policies\"\n\
             version = [1, 0, 0]\n\
             \n\
             policies = [{ owner = \"PROJECTA\", policy = \"spdx.headers-conform\" }]\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\n\
             version = [1, 0, 0]\n\
             \n\
             [PROJECTA.\"spdx.headers-conform\"]\n\
             paths = [\"src/equal.rs\", \"src/stale.rs\"]\n",
    );
    write(
        root.path(),
        ".linter/policy-spdx.toml",
        "namespace = \"class.linter.policy.spdx\"\n\
             version = [1, 0, 0]\n\
             \n\
             [set.identifier]\n\
             gpl3later = \"GPL-3.0-or-later\"\n\
             \n\
             [set.copyright]\n\
             example2026 = \"2026 Torrust project contributors\"\n\
             \n\
             [owners.PROJECTA.identifier]\n\
             exclude = [{ name = \"configuration\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }]\n\
             partitions = [{ name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src\" [ \"/\" *VCHAR ] %s\".rs\"' }]\n\
             \n\
             [owners.PROJECTA.copyright]\n\
             exclude = [{ name = \"configuration\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }, \
               { name = \"generated\", pattern = '%s\"src/excluded.rs\"' }]\n\
             partitions = [{ name = \"code\", copyright = \"example2026\", pattern = '%s\"src/\" ( %s\"equal\" / %s\"growth\" / %s\"stale\" ) %s\".rs\"' }]\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\n\
             version = [1, 0, 0]\n\
             \n\
             universe = \"git-tracked\"\n\
             \n\
             ignore = []\n",
    );

    initialise_and_track(root.path());

    root
}

/// A tree whose one envelope pair governs two documents, of which one fails.
///
/// The declared files are governed by the same include row and carry their
/// own envelopes, which is the bootstrap the surface runs on: the
/// configuration is a document of the language it governs.
fn envelope_tree() -> TempDir {
    let root = TempDir::new().expect("a temporary root");

    write(root.path(), "share/failing.toml", "port = 7070\n");
    write(
        root.path(),
        "share/conforming.toml",
        "namespace = \"org.example.configuration\"\nversion = [2, 0, 0]\n\nport = 7070\n",
    );

    for (file, schema, text) in [
        (
            "owners",
            "owners",
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
                 partitions = [{ name = \"everything\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
                 may_cite = []\n",
        ),
        ("environments", "environments", "environments = []\n"),
        (
            "policies",
            "policies",
            "policies = [{ owner = \"PROJECTA\", policy = \"interchange.envelope-conform\" }]\n",
        ),
        (
            "lists",
            "lists",
            "[PROJECTA.\"interchange.envelope-conform\"]\npaths = []\n",
        ),
        (
            "shape",
            "shape",
            "universe = \"git-tracked\"\n\nignore = []\n",
        ),
        (
            "policy-interchange",
            "policy.interchange",
            "[set.interchange-documents]\nconfig = \"configuration documents\"\n\n\
                 [owners.PROJECTA.interchange-documents]\nexclude = []\ninclude = [{ name = \"configuration\", interchange-documents = \"config\", pattern = '( %s\".linter\" / %s\"share\" ) \"/\" *VCHAR %s\".toml\"' }]\n",
        ),
    ] {
        write(
            root.path(),
            &format!(".linter/{file}.toml"),
            &format!(
                "namespace = \"{}.{schema}\"\nversion = [1, 0, 0]\n\n{text}",
                if schema == "lists" || schema.starts_with("policy.") {
                    "class.linter"
                } else {
                    "org.example.linter"
                }
            ),
        );
    }

    initialise_and_track(root.path());

    root
}

/// A tree whose path-name pair governs one text name and one byte name.
fn names_tree() -> Option<TempDir> {
    let root = TempDir::new().expect("a temporary root");
    write(root.path(), "share/kept.txt", "Nothing stands here.\n");
    let _opaque = byte_named_fixture(root.path(), b"share/opaque\xff", "")?;

    for (file, schema, text) in [
        (
            "owners",
            "owners",
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
             partitions = [{ name = \"everything\", owner = \"PROJECTA\", pattern = '*PATHCHAR' }]\n\
             may_cite = []\n",
        ),
        ("environments", "environments", "environments = []\n"),
        (
            "policies",
            "policies",
            "policies = [{ owner = \"PROJECTA\", policy = \"paths.names-well-formed\" }]\n",
        ),
        (
            "lists",
            "lists",
            "[PROJECTA.\"paths.names-well-formed\"]\npaths = []\n",
        ),
        (
            "shape",
            "shape",
            "universe = \"git-tracked\"\n\nignore = []\n",
        ),
    ] {
        write(
            root.path(),
            &format!(".linter/{file}.toml"),
            &format!(
                "namespace = \"{}.{schema}\"\nversion = [1, 0, 0]\n\n{text}",
                if schema == "lists" || schema.starts_with("policy.") {
                    "class.linter"
                } else {
                    "org.example.linter"
                }
            ),
        );
    }

    initialise_and_track(root.path());
    Some(root)
}

/// A request for the fixture's envelope pair, with these rows.
fn envelope_request(operation: &str, rows: &str) -> String {
    format!(
        r#"{{
              "schema": 1,
              "operation": "{operation}",
              "targets": [
                {{
                  "owner": "PROJECTA",
                  "policy": "interchange.envelope-conform",
                  "syntax": "path-set",
                  "rows": [{rows}],
                  "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
                }}
              ]
            }}"#
    )
}

/// A request for the fixture's path-name pair, with these rows.
fn names_request(operation: &str, rows: &str) -> String {
    format!(
        r#"{{
              "schema": 1,
              "operation": "{operation}",
              "targets": [
                {{
                  "owner": "PROJECTA",
                  "policy": "paths.names-well-formed",
                  "syntax": "path-set",
                  "rows": [{rows}],
                  "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
                }}
              ]
            }}"#
    )
}

/// A request for the fixture's header pair, with these rows.
fn spdx_request(operation: &str, rows: &str) -> String {
    format!(
        r#"{{
              "schema": 1,
              "operation": "{operation}",
              "targets": [
                {{
                  "owner": "PROJECTA",
                  "policy": "spdx.headers-conform",
                  "syntax": "path-set",
                  "rows": [{rows}],
                  "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
                }}
              ]
            }}"#
    )
}

/// Write one file, creating every parent directory it needs.
fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);

    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a parent directory");
    std::fs::write(path, text).expect("a file");
}

/// Hold request bytes beside a response destination at the fixture root.
fn request(root: &Path, text: &str) -> (Vec<u8>, std::path::PathBuf) {
    (text.as_bytes().to_vec(), root.join("response.json"))
}

/// The response object a completed run wrote, parsed.
fn completed(control: Control) -> serde_json::Value {
    let Control::Completed { bytes, .. } = control else {
        panic!("expected a completed run")
    };

    serde_json::from_slice(&bytes).expect("one JSON object")
}

/// The message a refused run gave.
fn refused(control: Control) -> String {
    let Control::Refused { message } = control else {
        panic!("expected a refusal")
    };

    message
}

/// The snapshot a fixture declares.
fn snapshot(root: &Path) -> Snapshot {
    let loaded = configuration(root);
    let Configuration::Present(snapshot) = loaded else {
        panic!("expected the snapshot to load, found {loaded:?}")
    };

    *snapshot
}

fn lower_at(root: &Path) -> BTreeMap<Pair, Rows> {
    let snapshot = snapshot(root);
    let plan = ExecutionPlan::compile(root, Configuration::Present(Box::new(snapshot.clone())))
        .expect("fixture configuration");

    lower(
        root,
        &snapshot,
        plan.topology().corpus(),
        plan.topology().partition(),
    )
}

/// An audit request naming the one fixture pair and every identity at it.
const AUDIT: &str = r#"{
      "schema": 1,
      "operation": "audit",
      "targets": [
        {
          "owner": "PROJECTB",
          "policy": "legacy.section-references",
          "syntax": "path-count",
          "rows": [],
          "authority": { "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }
        }
      ]
    }"#;

/// Label debt appends under the fingerprint emitted from the check finding, and the next observation matches that row as tolerated debt.
///
/// ´claim:control:label-debt-round-trips-through-the-check-fingerprint´
/// ´test:crate:label-debt-round-trips-through-its-finding-fingerprint´
#[test]
fn label_debt_round_trips_through_its_finding_fingerprint() {
    let root = label_tree();
    let report = check(root.path());
    let [reported] = report.findings.as_slice() else {
        panic!(
            "expected exactly one label finding, found {:?}",
            report.findings
        )
    };
    assert!(matches!(
        &reported.finding,
        Finding::UnpairedBacktick { .. }
    ));
    let fingerprint = finding_fingerprint(&reported.finding).expect("a serializable finding");
    let initial_audit = r#"{
      "schema": 1,
      "operation": "audit",
      "targets": [{
        "owner": "PROJECTA",
        "policy": "labels.mints-well-formed",
        "syntax": "fingerprint",
        "rows": [],
        "authority": { "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }
      }]
    }"#;
    let (input, output) = request(root.path(), initial_audit);
    let first_observation = completed(maintain(root.path(), Operation::Audit, &input, &output));
    assert_eq!(
        first_observation["targets"][0]["growth"][0]["identity"]["fingerprint"], fingerprint,
        "response: {first_observation:#}"
    );
    let append = format!(
        r#"{{
          "schema": 1,
          "operation": "append",
          "targets": [{{
            "owner": "PROJECTA",
            "policy": "labels.mints-well-formed",
            "syntax": "fingerprint",
            "rows": [{{ "fingerprint": "{fingerprint}", "maximum": 1 }}],
            "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
          }}]
        }}"#
    );
    let (input, output) = request(root.path(), &append);
    let appended = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(appended["applied"], true, "response: {appended:#}");
    assert_eq!(
        appended["targets"][0]["new_state"][0]["fingerprint"],
        fingerprint
    );

    let audit = format!(
        r#"{{
          "schema": 1,
          "operation": "audit",
          "targets": [{{
            "owner": "PROJECTA",
            "policy": "labels.mints-well-formed",
            "syntax": "fingerprint",
            "rows": [{{ "fingerprint": "{fingerprint}" }}],
            "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
          }}]
        }}"#
    );
    let (input, output) = request(root.path(), &audit);
    let observed = completed(maintain(root.path(), Operation::Audit, &input, &output));

    assert_eq!(observed["clean"], true);
    assert_eq!(observed["failures"], 0);
    assert_eq!(observed["targets"][0]["equal"][0]["observed"], 1);
    assert_eq!(
        observed["targets"][0]["equal"][0]["identity"]["fingerprint"],
        fingerprint
    );
}

/// A list the writer renders is a list the loader reads back unchanged, so
/// a maintained declaration stays a declaration rather than becoming
/// something only the writer can read. The rows come back in decoded
/// byte-path order whatever order they were written in.
///
/// ´claim:control:a-rendered-list-loads-back-unchanged´
/// ´test:crate:a-rendered-list-loads-back-unchanged´
#[test]
fn a_rendered_list_loads_back_unchanged() {
    let root = tree(
        "As §10.3 requires.\n",
        "{ path = \"packages/project-b/docs/note.md\", maximum = 1 }",
    );

    let path = root.path().join(".linter/lists.toml");
    let loaded = snapshot(root.path());

    // What the writer writes is what it renders under what it held: the
    // ratchet maintains the row array and stays out of the envelope, which is
    // why the file it produces is still a file the loader will read.
    let rendered = format!(
        "{}{}",
        LISTS_ENVELOPE,
        render_lists(&loaded.list_keys(), loaded.lists())
    );

    assert_eq!(
        rendered,
        "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
             [PROJECTB.\"legacy.section-references\"]\npath_counts = [\n  \
             { path = \"packages/project-b/docs/note.md\", maximum = 1 },\n]\n\n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n"
    );

    std::fs::write(&path, &rendered).expect("the rendered list");

    assert_eq!(snapshot(root.path()).lists(), loaded.lists());
}

/// A kept reason is read as the row's own text and rendered after its ceiling
/// with TOML escaping, so a rewritten list carries the same reason back into
/// the decoded row.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be read, written, or parsed.
///
/// ´claim:control:a-kept-reason-round-trips-through-a-rendered-list´
/// ´test:crate:a-kept-reason-round-trips-through-a-rendered-list´
#[test]
fn a_kept_reason_round_trips_through_a_rendered_list() {
    let row = r#"{ path = "packages/project-b/docs/note.md", maximum = 1, kept = "machine reads \"word\"" }"#;
    let root = tree("As §10.3 requires.\n", row);
    let loaded = snapshot(root.path());
    let Rows::PathCounts(rows) = &loaded.lists()[&pair()] else {
        panic!("the fixture declares a path-count row")
    };
    assert_eq!(rows[0].kept.as_deref(), Some("machine reads \"word\""));

    let rendered = format!(
        "{}{}",
        LISTS_ENVELOPE,
        render_lists(&loaded.list_keys(), loaded.lists())
    );
    assert!(
        rendered.contains(row),
        "the reason is escaped in the row: {rendered}"
    );
    std::fs::write(root.path().join(".linter/lists.toml"), &rendered).expect("the rendered list");
    assert_eq!(snapshot(root.path()).lists(), loaded.lists());
}

/// The ordinary loader refuses both empty and whitespace-only kept reasons
/// instead of accepting a marked row whose reason says nothing.
///
/// ´claim:control:a-blank-kept-reason-refuses-the-snapshot´
/// ´test:crate:a-blank-kept-reason-refuses-the-snapshot´
#[test]
fn a_blank_kept_reason_refuses_the_snapshot() {
    for reason in ["", "   "] {
        let root = tree(
            "As §10.3 requires.\n",
            &format!(
                "{{ path = \"packages/project-b/docs/note.md\", maximum = 1, kept = \"{reason}\" }}"
            ),
        );
        let refused = configuration(root.path());
        assert_eq!(refused.refusals().len(), 1);
        assert!(
            refused.refusals()[0]
                .to_string()
                .contains("a kept reason is non-empty")
        );
        assert!(
            refused.refusals()[0]
                .to_string()
                .contains("packages/project-b/docs/note.md")
        );
    }
}

/// A rendering keeps the deployments of one program apart, because a family
/// is part of a pair's identity rather than a note beside it. Two invented
/// deployments of one parameterized program are written under two distinct
/// three-component keys and read back as the two pairs they were; a writer
/// that emitted only owner and policy would put both under one key and hand
/// back a file the loader refuses as a duplicate table.
///
/// The families are invented rather than borrowed from this repository's own
/// declaration, because what is under test is a family the writer has never
/// seen rather than the three this corpus happens to deploy.
///
/// ´claim:control:a-rendered-instanced-list-keeps-its-families-apart´
/// ´test:crate:a-rendered-instanced-list-keeps-its-families-apart´
#[test]
fn a_rendered_instanced_list_keeps_its_families_apart() {
    let root = instanced_tree();

    let path = root.path().join(".linter/lists.toml");
    let loaded = snapshot(root.path());

    assert_eq!(loaded.lists().len(), 4, "the fixture declares four pairs");

    let rendered = format!(
        "{}{}",
        LISTS_ENVELOPE,
        render_lists(&loaded.list_keys(), loaded.lists())
    );

    assert_eq!(
        rendered,
        "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n\
             [PROJECTB.\"legacy.section-references\"]\npath_counts = []\n\n\
             [PROJECTB.\"policy.references.quarry-numbers\".\"invented-alpha\"]\npath_counts = [\n  \
             { path = \"packages/project-b/docs/note.md\", maximum = 2 },\n]\n\n\
             [PROJECTB.\"policy.references.quarry-numbers\".\"invented-beta\"]\npath_counts = []\n"
    );

    std::fs::write(&path, &rendered).expect("the rendered list");

    assert_eq!(snapshot(root.path()).lists(), loaded.lists());
}

/// A rewrite carries every row the declaration stands on, including the rows
/// of a census whose policy places them outside the owner they are filed
/// under. Appending to one row of a corpus-spanning register leaves the
/// other exactly where it was: the permissive reading an append renders from
/// asks owner containment under the same condition the ordinary loader asks
/// it, so a row the loader accepts is a row the writer keeps.
///
/// ´claim:control:a-corpus-spanning-register-crosses-a-rewrite-whole´
/// ´test:crate:a-corpus-spanning-register-crosses-a-rewrite-whole´
#[test]
fn a_corpus_spanning_register_crosses_a_rewrite_whole() {
    let root = spanning_tree();
    let pair = Pair::singleton("PROJECTA", "legacy.section-references-repository");

    let held = snapshot(root.path());
    let Some(Rows::PathCounts(before)) = held.lists().get(&pair) else {
        panic!("the fixture declares one path-count register")
    };

    assert_eq!(
        before.len(),
        2,
        "both rows load, though neither file is the owner's"
    );

    let append = spanning_request(
        "append",
        r#"{ "path": "packages/project-b/docs/note.md", "maximum": 2 }"#,
    );
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], serde_json::json!(true), "{response}");
    assert_eq!(response["failures"], serde_json::json!(0), "{response}");

    let after = snapshot(root.path());
    let Some(Rows::PathCounts(rows)) = after.lists().get(&pair) else {
        panic!("the register survives the rewrite")
    };

    assert_eq!(
        rows.iter()
            .map(|row| (row.path.display(), row.maximum))
            .collect::<Vec<_>>(),
        vec![
            (String::from("packages/project-b/docs/note.md"), 2),
            (String::from("packages/project-b/docs/other.md"), 1),
        ],
        "the appended row grew and the row nobody named stood still"
    );
}

/// An instanced key crosses a rewrite whole. A key naming an instance
/// document and one of its set entries is read as the program that entry
/// deploys, so the tables standing at such keys are carried by the reading a
/// rewrite renders from rather than dropped as though their middle component
/// were a policy name nobody catalogues.
///
/// ´claim:control:an-instanced-key-crosses-a-rewrite-whole´
/// ´test:crate:an-instanced-key-crosses-a-rewrite-whole´
#[test]
fn an_instanced_key_crosses_a_rewrite_whole() {
    let root = instanced_tree();

    write(
        root.path(),
        "packages/project-b/docs/note.md",
        "As §10.3 requires.\n",
    );
    track_all(root.path());

    assert_eq!(
        snapshot(root.path()).lists().len(),
        4,
        "the fixture declares four pairs"
    );

    let (input, output) = request(
        root.path(),
        &format!(
            r#"{{
              "schema": 1,
              "operation": "append",
              "targets": [
                {{
                  "owner": "PROJECTB",
                  "policy": "legacy.section-references",
                  "syntax": "path-count",
                  "rows": [{}],
                  "authority": {{ "authorized_by": "the owner", "ruling": "a ruling", "reason": "a reason" }}
                }}
              ]
            }}"#,
            r#"{ "path": "packages/project-b/docs/note.md", "maximum": 1 }"#
        ),
    );

    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], serde_json::json!(true), "{response}");

    let after = snapshot(root.path());

    assert_eq!(
        after.lists().len(),
        4,
        "the two instanced tables stand beside the appended one and prose activation"
    );
    assert!(
        after
            .lists()
            .keys()
            .any(|key| key.family.as_deref() == Some("invented-alpha")),
        "the deployment carrying a row survived the rewrite"
    );
    assert!(
        after
            .lists()
            .keys()
            .any(|key| key.family.as_deref() == Some("invented-beta")),
        "the empty deployment survived the rewrite, an empty list being a live statement"
    );
}

/// An append refuses outright when the reading it would render from could not
/// carry every declared row, and it names the rows at risk. The whole-file
/// rewrite renders what that reading holds and nothing else, so a row missing
/// from it is a row the write would delete; the question is therefore asked of
/// the declaration entire rather than of the target's own table, and the file
/// is left byte for byte as it stood.
///
/// ´claim:control:an-append-refuses-a-declaration-a-rewrite-would-truncate´
/// ´test:crate:an-append-refuses-a-declaration-a-rewrite-would-truncate´
#[test]
fn an_append_refuses_a_declaration_a_rewrite_would_truncate() {
    let root = spanning_tree();
    let path = root.path().join(".linter/lists.toml");

    // A second row for one file is an identity standing twice, which the
    // permissive reading reports and cannot carry. The target of the append
    // is the same pair here only because the fixture declares one; what the
    // guard answers is the state of the declaration, not of the target.
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\n\
             version = [1, 0, 0]\n\
             \n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n[PROJECTA.\"legacy.section-references-repository\"]\n\
             path_counts = [\n  \
             { path = \"packages/project-b/docs/note.md\", maximum = 1 },\n  \
             { path = \"packages/project-b/docs/other.md\", maximum = 1 },\n  \
             { path = \"packages/project-b/docs/other.md\", maximum = 1 },\n\
             ]\n",
    );

    let held = std::fs::read(&path).expect("the declaration as it stands");

    let append = spanning_request(
        "append",
        r#"{ "path": "packages/project-b/docs/note.md", "maximum": 2 }"#,
    );
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], serde_json::json!(false), "{response}");

    let refusals = response["targets"][0]["refused"]
        .as_array()
        .expect("refusals");
    let lossy = refusals
        .iter()
        .find(|refusal| refusal["code"] == serde_json::json!("lossy_declaration"))
        .unwrap_or_else(|| panic!("expected a lossy-declaration refusal, found {response}"));

    assert!(
        lossy["message"]
            .as_str()
            .expect("a message")
            .contains("packages/project-b/docs/other.md"),
        "the refusal names the row a rewrite would have deleted: {lossy}"
    );

    assert_eq!(
        std::fs::read(&path).expect("the declaration afterwards"),
        held,
        "a refused append writes not one byte"
    );
}

/// An append over a declaration with a zero-ceiling row refuses the lossy rewrite and names the row it would delete.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be read or written.
///
/// ´claim:control:an-append-refuses-a-zero-ceiling-row´
/// ´test:crate:an-append-refuses-a-zero-ceiling-row´
#[test]
fn an_append_refuses_a_zero_ceiling_row() {
    let root = spanning_tree();
    let path = root.path().join(".linter/lists.toml");
    let zero_path = "packages/project-b/docs/other.md";
    write(
        root.path(),
        ".linter/lists.toml",
        &format!(
            "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
             [PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\n[PROJECTA.\"legacy.section-references-repository\"]\npath_counts = [\n  \
             {{ path = \"packages/project-b/docs/note.md\", maximum = 1 }},\n  \
             {{ path = \"{zero_path}\", maximum = 0 }},\n]\n"
        ),
    );
    let held = std::fs::read(&path).expect("the declaration as it stands");
    let append = spanning_request(
        "append",
        r#"{ "path": "packages/project-b/docs/note.md", "maximum": 2 }"#,
    );
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], false, "{response}");
    let refusals = response["targets"][0]["refused"]
        .as_array()
        .expect("refusals");
    let lossy = refusals
        .iter()
        .find(|refusal| refusal["code"] == "lossy_declaration")
        .unwrap_or_else(|| panic!("expected a lossy-declaration refusal, found {response}"));
    assert!(
        lossy["message"]
            .as_str()
            .expect("a message")
            .contains(zero_path),
        "the refusal names the zero-ceiling row: {lossy}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the declaration afterwards"),
        held
    );
}

/// SPDX audit observes a failing file once however many halves fail.
/// Listed failure is equal, unlisted failure is growth, and a listed file
/// becomes stale only after its remaining half is repaired; shrink is
/// unreachable because both registered and observed are set membership.
/// Append accepts the maximum-free growth row, lowering removes the stale
/// row, and named exclusions remain non-failing explanations throughout.
///
/// ´claim:control:path-set-control-observes-the-file-until-every-half-conforms´
/// ´test:crate:path-set-control-observes-the-file-until-every-half-conforms´
#[test]
fn path_set_control_observes_the_file_until_every_half_conforms() {
    let root = spdx_tree();
    let audit = spdx_request("audit", "");
    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
    let target = &response["targets"][0];
    let paths = |class: &str| {
        target[class]
            .as_array()
            .expect("comparisons")
            .iter()
            .map(|comparison| {
                comparison["identity"]["path"]
                    .as_str()
                    .expect("a path")
                    .to_owned()
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(paths("equal"), ["src/equal.rs", "src/stale.rs"]);
    assert_eq!(paths("growth"), ["src/growth.rs"]);
    assert!(
        paths("shrink").is_empty(),
        "set membership has no positive smaller value"
    );
    assert!(
        paths("stale").is_empty(),
        "the half-repaired file still fails copyright"
    );
    assert!(
        target["explanations"].as_array().expect("explanations").iter().any(|row| {
            row.as_str() == Some("spdx section: src/excluded.rs: excluded from the PROJECTA copyright half by rule generated")
        }),
        "{target}"
    );

    let append = spdx_request("append", r#"{ "path": "src/growth.rs" }"#);
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], true);
    assert_eq!(response["failures"], 0);
    assert_eq!(response["targets"][0]["appended"][0]["observed"], 1);
    assert!(
        response["targets"][0]["requested"][0]
            .get("maximum")
            .is_none()
    );

    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));

    assert_eq!(response["clean"], true, "the explanation fails nothing");
    assert_eq!(
        response["targets"][0]["equal"]
            .as_array()
            .expect("equal")
            .len(),
        3
    );

    write(
        root.path(),
        "src/stale.rs",
        "// SPDX-License-Identifier: GPL-3.0-or-later\n\
             // SPDX-FileCopyrightText: 2026 Torrust project contributors\n\
             \n\
             fn stale() {}\n",
    );

    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
    let target = &response["targets"][0];

    assert_eq!(target["stale"][0]["identity"]["path"], "src/stale.rs");
    assert_eq!(
        target["shrink"].as_array().expect("shrink").as_slice(),
        EMPTY_JSON_ARRAY
    );

    let pair = Pair::singleton("PROJECTA", "spdx.headers-conform");
    let lowered = lower_at(root.path());
    let Rows::Paths(paths) = &lowered[&pair] else {
        panic!("the header pair keeps its codec");
    };
    let paths: Vec<String> = paths.iter().map(BytePath::display).collect();

    assert_eq!(paths, ["src/equal.rs", "src/growth.rs"]);
}

/// An envelope defect is the observation these modes compare and record, so
/// it neither makes an audit incoherent nor blocks the append growth door —
/// the same standing a header failure already has at the other path-set
/// policy. A door that refused to open under it could never record the debt
/// the burn-down ruling declares. A section defect keeps blocking, because a
/// share that is not divided is a configuration disagreeing with the tree
/// rather than an observation of one.
///
/// ´claim:control:an-envelope-defect-is-observation-rather-than-disagreement´
/// ´test:crate:an-envelope-defect-is-observation-rather-than-disagreement´
#[test]
fn an_envelope_defect_is_observation_rather_than_disagreement() {
    let root = envelope_tree();
    let audit = envelope_request("audit", "");
    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
    let target = &response["targets"][0];

    // The failing document is growth and the conforming one is nothing at
    // all, and the run is clean: the defect is what the list is compared
    // against, not a reason the comparison cannot be made.
    assert_eq!(response["clean"], true, "{response}");
    assert_eq!(target["growth"].as_array().expect("growth").len(), 1);
    assert_eq!(
        target["growth"][0]["identity"]["path"],
        "share/failing.toml"
    );
    assert_eq!(
        target["equal"].as_array().expect("equal").as_slice(),
        EMPTY_JSON_ARRAY
    );

    // And the growth door opens under it, which is the whole of the
    // declare-then-drain convention the burn-down ruling rests on.
    let append = envelope_request("append", r#"{ "path": "share/failing.toml" }"#);
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], true, "{response}");
    assert_eq!(response["failures"], 0);
    assert!(
        response["targets"][0]["requested"][0]
            .get("maximum")
            .is_none()
    );

    // A section whose declared include gloss leaves a governed path unnamed
    // is a different thing, and it goes on refusing the append: the
    // configuration is in disagreement with itself, whatever the tree holds.
    write(
        root.path(),
        ".linter/policy-interchange.toml",
        "namespace = \"class.linter.policy.interchange\"\n\
             version = [1, 0, 0]\n\
             \n\
             [set.interchange-documents]\n\
             config = \"configuration documents\"\n\
             \n\
             [owners.PROJECTA.interchange-documents]\n\
             exclude = []\n\
             include = [{ name = \"configuration\", interchange-documents = \"config\", pattern = '%s\"share/\" *VCHAR %s\".toml\"' }]\n",
    );

    let (input, output) = request(root.path(), &append);
    let Control::Refused { message } = maintain(root.path(), Operation::Append, &input, &output)
    else {
        panic!("expected the undivided share to refuse the append");
    };

    assert!(message.contains("named by no include row"), "{message}");
}

/// A non-text name is an observation of the tree that the path-set list can record, so audit sees its growth and append can record it without treating it as a configuration disagreement; the next audit sees the same path as equal.
///
/// ´claim:control:a-non-text-name-is-observation-rather-than-disagreement´
/// ´test:crate:a-non-text-name-is-observation-rather-than-disagreement´
#[test]
fn a_non_text_name_is_observation_rather_than_disagreement() {
    let Some(root) = names_tree() else {
        return;
    };
    let audit = names_request("audit", "");
    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
    let target = &response["targets"][0];

    assert_eq!(response["clean"], true, "{response}");
    assert_eq!(target["growth"].as_array().expect("growth").len(), 1);
    assert_eq!(target["growth"][0]["identity"]["path"], "share/opaque%FF");
    assert_eq!(
        target["equal"].as_array().expect("equal").as_slice(),
        EMPTY_JSON_ARRAY
    );

    let append = names_request("append", r#"{ "path": "share/opaque%FF" }"#);
    let (input, output) = request(root.path(), &append);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));
    assert_eq!(response["applied"], true, "{response}");
    assert_eq!(response["failures"], 0);

    let (input, output) = request(root.path(), &audit);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
    let target = &response["targets"][0];
    assert_eq!(response["clean"], true, "{response}");
    assert_eq!(
        target["growth"].as_array().expect("growth").as_slice(),
        EMPTY_JSON_ARRAY
    );
    assert_eq!(target["equal"].as_array().expect("equal").len(), 1);
    assert_eq!(target["equal"][0]["identity"]["path"], "share/opaque%FF");
}

/// An audit classifies every selected identity exactly once, against what
/// the tree holds now: a ceiling the tree meets is equal, one the tree
/// exceeds is growth, one above what the tree holds is shrink, and a row the
/// tree no longer answers at all is stale.
///
/// ´claim:control:an-audit-classifies-each-identity-exactly-once´
/// ´test:crate:an-audit-classifies-each-identity-exactly-once´
#[test]
fn an_audit_classifies_each_identity_exactly_once() {
    let cases = [
        ("As §10.3 requires.\n", 1, "equal"),
        ("As §10.3 requires, and §6.1 too.\n", 1, "growth"),
        ("As §10.3 requires.\n", 2, "shrink"),
        ("No reference at all.\n", 2, "stale"),
    ];

    for (prose, maximum, class) in cases {
        let root = tree(
            prose,
            &format!("{{ path = \"packages/project-b/docs/note.md\", maximum = {maximum} }}"),
        );
        let (input, output) = request(root.path(), AUDIT);

        let response = completed(maintain(root.path(), Operation::Audit, &input, &output));
        let target = &response["targets"][0];

        for other in ["equal", "growth", "shrink", "stale"] {
            let expected = usize::from(other == class);

            assert_eq!(
                target[other].as_array().expect("an array").len(),
                expected,
                "{prose} at {maximum} should be {class}, not {other}"
            );
        }

        assert_eq!(response["operation"], "audit");
        assert_eq!(response["clean"], true);
    }
}

/// The response file and the stdout object are the same bytes: the file is
/// made durable first and the caller copies it, so the receipt travelling
/// with a change and the object a caller reads cannot tell different
/// stories. The digests it carries are of the request and of the list as it
/// stands.
///
/// ´claim:control:the-response-file-and-the-returned-bytes-are-one´
/// ´test:crate:the-response-file-and-the-returned-bytes-are-one´
#[test]
fn the_response_file_and_the_returned_bytes_are_one() {
    let root = tree(
        "As §10.3 requires.\n",
        "{ path = \"packages/project-b/docs/note.md\", maximum = 1 }",
    );
    let (input, output) = request(root.path(), AUDIT);

    let Control::Completed { bytes, failures } =
        maintain(root.path(), Operation::Audit, &input, &output)
    else {
        panic!("expected a completed run");
    };

    assert_eq!(failures, 0);
    assert_eq!(std::fs::read(&output).expect("the response file"), bytes);
    assert_eq!(bytes.last(), Some(&b'\n'));

    let response: serde_json::Value = serde_json::from_slice(&bytes).expect("one JSON object");

    assert!(
        response["request_sha256"]
            .as_str()
            .expect("a digest")
            .starts_with("sha256:")
    );
    assert!(
        response["lists_sha256"]
            .as_str()
            .expect("a digest")
            .starts_with("sha256:")
    );
    assert_eq!(
        response["targets"][0]["authority"]["authorized_by"],
        "the owner"
    );
}

/// An audit reports a declaration defect rather than refusing it, which is
/// the recovery role it exists for: a caller finding out what the lists say
/// needs an answer from exactly the configuration no policy could run
/// against. The run completes and exits with findings.
///
/// ´claim:control:an-audit-reports-a-defect-rather-than-refusing-it´
/// ´test:crate:an-audit-reports-a-defect-rather-than-refusing-it´
#[test]
fn an_audit_reports_a_defect_rather_than_refusing_it() {
    let root = tree(
        "As §10.3 requires.\n",
        "{ path = \"packages/project-b/docs/note.md\", maximum = 1 }, { path = \"docs/elsewhere.md\", maximum = 1 }",
    );
    let (input, output) = request(root.path(), AUDIT);

    // The ordinary loader refuses this declaration outright.
    assert!(matches!(
        configuration(root.path()),
        Configuration::Refused(_)
    ));

    let Control::Completed { bytes, failures } =
        maintain(root.path(), Operation::Audit, &input, &output)
    else {
        panic!("expected the audit to survive the declaration it reports on");
    };

    assert!(failures > 0);

    let response: serde_json::Value = serde_json::from_slice(&bytes).expect("one JSON object");
    let codes: Vec<&str> = response["targets"][0]["anomalies"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|anomaly| anomaly["code"].as_str())
        .collect();

    assert!(codes.contains(&"owner_path_mismatch"), "{codes:?}");
    assert_eq!(response["clean"], false);
}

/// Append accepts a row only when it names growth the tree currently holds
/// and its ceiling equals exactly that observation. A row the tree has not
/// grown past, one above the observation, one below it, and one naming
/// nothing the tree holds are each refused, so an append records a debt the
/// tree already carries and cannot pre-authorize one not yet written.
///
/// ´claim:control:append-accepts-only-current-growth-at-the-observation´
/// ´test:crate:append-accepts-only-current-growth-at-the-observation´
#[test]
fn append_accepts_only_current_growth_at_the_observation() {
    let proposal = |maximum: u32, path: &str| {
        format!(
            r#"{{ "schema": 1, "operation": "append", "targets": [ {{ "owner": "PROJECTB",
                 "policy": "legacy.section-references", "syntax": "path-count",
                 "rows": [ {{ "path": "{path}", "maximum": {maximum} }} ],
                 "authority": {{ "authorized_by": "a", "ruling": "b", "reason": "c" }} }} ] }}"#
        )
    };

    let held = "packages/project-b/docs/note.md";
    let grown = "As §10.3 requires, and §6.1 too.\n";
    let refusals = [
        ("As §10.3 requires.\n", 1, held, "not_growth"),
        (grown, 3, held, "maximum_not_observed"),
        (grown, 1, held, "maximum_not_observed"),
        (
            grown,
            2,
            "packages/project-b/docs/absent.md",
            "not_observed",
        ),
    ];

    for (prose, maximum, path, code) in refusals {
        let root = tree(prose, &format!("{{ path = \"{held}\", maximum = 1 }}"));
        let (input, output) = request(root.path(), &proposal(maximum, path));
        let response = completed(maintain(root.path(), Operation::Append, &input, &output));

        assert_eq!(response["applied"], false, "{code}");
        assert_eq!(response["targets"][0]["refused"][0]["code"], code);
        assert_eq!(
            response["before_lists_sha256"],
            response["after_lists_sha256"]
        );
    }

    let root = tree(
        "As §10.3 requires, and §6.1 too.\n",
        &format!("{{ path = \"{held}\", maximum = 1 }}"),
    );
    let (input, output) = request(root.path(), &proposal(2, held));
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], true);
    assert_eq!(response["targets"][0]["appended"][0]["before"], 1);
    assert_eq!(response["targets"][0]["appended"][0]["observed"], 2);
    assert_eq!(response["targets"][0]["appended"][0]["after"], 2);
    assert_ne!(
        response["before_lists_sha256"],
        response["after_lists_sha256"]
    );

    assert_eq!(
        snapshot(root.path()).lists()[&pair()],
        Rows::PathCounts(vec![crate::snapshot::PathCount {
            path: crate::pattern::BytePath::decode(held).expect("a path"),
            maximum: 2,
            kept: None,
        }])
    );
}

/// The batch is atomic: one refused row refuses all of them, the list is
/// left exactly as it stood, and both digests are equal. A request is
/// accepted as the ruling it claims to be rather than partially applied into
/// a state nobody ruled on.
///
/// ´claim:control:one-refused-row-refuses-the-whole-batch´
/// ´test:crate:one-refused-row-refuses-the-whole-batch´
#[test]
fn one_refused_row_refuses_the_whole_batch() {
    let held = "packages/project-b/docs/note.md";
    let root = tree(
        "As §10.3 requires, and §6.1 too.\n",
        &format!("{{ path = \"{held}\", maximum = 1 }}"),
    );

    let text = format!(
        r#"{{ "schema": 1, "operation": "append", "targets": [ {{ "owner": "PROJECTB",
             "policy": "legacy.section-references", "syntax": "path-count",
             "rows": [ {{ "path": "{held}", "maximum": 2 }},
                       {{ "path": "packages/project-b/docs/absent.md", "maximum": 1 }} ],
             "authority": {{ "authorized_by": "a", "ruling": "b", "reason": "c" }} }} ] }}"#
    );

    let before = std::fs::read(root.path().join(".linter/lists.toml")).expect("the list file");
    let (input, output) = request(root.path(), &text);
    let response = completed(maintain(root.path(), Operation::Append, &input, &output));

    assert_eq!(response["applied"], false);
    assert_eq!(
        response["targets"][0]["appended"]
            .as_array()
            .expect("an array")
            .len(),
        0
    );
    assert_eq!(
        response["before_lists_sha256"],
        response["after_lists_sha256"]
    );
    assert_eq!(
        std::fs::read(root.path().join(".linter/lists.toml")).expect("the list file"),
        before
    );
}

/// The lowering writer lowers a ceiling to what the census now finds and
/// removes a row whose occurrences are gone, and it never raises one:
/// growth passes the other door or none.
///
/// ´claim:control:the-lowering-writer-never-raises-a-ceiling´
/// ´test:crate:the-lowering-writer-never-raises-a-ceiling´
#[test]
fn the_lowering_writer_never_raises_a_ceiling() {
    let held = "packages/project-b/docs/note.md";

    let root = tree(
        "As §10.3 requires.\n",
        &format!("{{ path = \"{held}\", maximum = 3 }}"),
    );
    let lowered = lower_at(root.path());

    assert_eq!(row_of(&lowered, &pair()), Some(1));

    let root = tree(
        "As §10.3 requires, and §6.1 too.\n",
        &format!("{{ path = \"{held}\", maximum = 1 }}"),
    );
    let lowered = lower_at(root.path());

    assert_eq!(
        row_of(&lowered, &pair()),
        Some(1),
        "growth is left where it stands"
    );

    let root = tree(
        "No reference at all.\n",
        &format!("{{ path = \"{held}\", maximum = 3 }}"),
    );
    let lowered = lower_at(root.path());

    assert_eq!(
        row_of(&lowered, &pair()),
        None,
        "a row whose occurrences are gone leaves"
    );
    assert!(
        lowered[&pair()].is_empty(),
        "and the list is retained and empty"
    );
}

/// Marking a row kept changes no ratchet judgment: an observation above its
/// ceiling raises growth, and one below its ceiling raises a stale entry.
///
/// ´claim:control:a-kept-row-still-ratchets-in-both-directions´
/// ´test:crate:a-kept-row-still-ratchets-in-both-directions´
#[test]
fn a_kept_row_still_ratchets_in_both_directions() {
    let held = "packages/project-b/docs/note.md";
    let growth = tree(
        "As §10.3 requires, and §6.1 too.\n",
        &format!("{{ path = \"{held}\", maximum = 1, kept = \"quotation\" }}"),
    );
    assert!(
        check(growth.path())
            .findings
            .iter()
            .any(|reported| matches!(
                &reported.finding,
                Finding::BurnListGrowth {
                    registered: 1,
                    found: 2,
                    ..
                }
            ))
    );

    let stale = tree(
        "As §10.3 requires.\n",
        &format!("{{ path = \"{held}\", maximum = 2, kept = \"quotation\" }}"),
    );
    assert!(check(stale.path()).findings.iter().any(|reported| matches!(
        &reported.finding,
        Finding::StaleBurnEntry {
            registered: 2,
            found: 1,
            ..
        }
    )));
}

/// Lowering a kept row moves its ceiling to the census and writes its reason
/// beside the new ceiling.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be compiled, written, or parsed.
///
/// ´claim:control:lowering-preserves-a-kept-reason´
/// ´test:crate:lowering-preserves-a-kept-reason´
#[test]
fn lowering_preserves_a_kept_reason() {
    let held = "packages/project-b/docs/note.md";
    let root = tree(
        "As §10.3 requires.\n",
        &format!("{{ path = \"{held}\", maximum = 3, kept = \"quotation\" }}"),
    );
    let loaded = snapshot(root.path());
    let plan = ExecutionPlan::compile(root.path(), Configuration::Present(Box::new(loaded)))
        .expect("fixture configuration");
    assert!(crate::control::lower_lists(&plan).expect("the lowered list"));

    let lowered = snapshot(root.path());
    let Rows::PathCounts(rows) = &lowered.lists()[&pair()] else {
        panic!("the fixture declares a path-count row")
    };
    assert_eq!(rows[0].maximum, 1);
    assert_eq!(rows[0].kept.as_deref(), Some("quotation"));
    assert!(
        std::fs::read_to_string(root.path().join(".linter/lists.toml"))
            .expect("the lowered list")
            .contains(&format!(
                "{{ path = \"{held}\", maximum = 1, kept = \"quotation\" }}"
            ))
    );
}

/// The one ceiling a pair's list declares, when it declares one.
fn row_of(lists: &BTreeMap<Pair, Rows>, pair: &Pair) -> Option<u64> {
    let Some(Rows::PathCounts(rows)) = lists.get(pair) else {
        return None;
    };

    rows.first().map(|row| row.maximum)
}

/// An audit answers the partition and the dependency closure as well as the
/// list comparison, because both are asked of the declarations the list file
/// is checked against rather than of the list file itself. An append refuses
/// outright under the same answer, since every writing mode refuses to
/// mutate under a snapshot that disagrees with the tree.
///
/// ´claim:control:the-configuration-verdict-reaches-both-modes´
/// ´test:crate:the-configuration-verdict-reaches-both-modes´
#[test]
fn the_configuration_verdict_reaches_both_modes() {
    let held = "packages/project-b/docs/note.md";
    let root = tree(
        "As §10.3 requires, and §6.1 too.\n",
        &format!("{{ path = \"{held}\", maximum = 1 }}"),
    );

    // Tracked, because the disagreement being staged is a path the
    // repository has and no row accounts. Left untracked it would not be
    // the repository's file at all, and the snapshot would agree with the
    // tree exactly as it should.
    write(root.path(), "stray.md", "nothing accounts for this\n");
    track_all(root.path());

    let (input, output) = request(root.path(), AUDIT);
    let response = completed(maintain(root.path(), Operation::Audit, &input, &output));

    assert_eq!(response["clean"], false);
    assert!(response["failures"].as_u64().expect("a count") > 0);

    let codes: Vec<&str> = response["findings"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();

    assert!(codes.contains(&"unaccounted_path"), "{codes:?}");

    let proposal = format!(
        r#"{{ "schema": 1, "operation": "append", "targets": [ {{ "owner": "PROJECTB",
             "policy": "legacy.section-references", "syntax": "path-count",
             "rows": [ {{ "path": "{held}", "maximum": 2 }} ],
             "authority": {{ "authorized_by": "a", "ruling": "b", "reason": "c" }} }} ] }}"#
    );

    let before = std::fs::read(root.path().join(".linter/lists.toml")).expect("the list file");
    let (input, output) = request(root.path(), &proposal);

    assert!(
        refused(maintain(root.path(), Operation::Append, &input, &output)).contains("unaccounted")
    );
    assert_eq!(
        std::fs::read(root.path().join(".linter/lists.toml")).expect("the list file"),
        before
    );
}

/// A maintenance run may not overwrite the thing it is reporting on, and may
/// not write its receipt into the declared surface. This is a refused
/// precondition, so the declaration and the response path are left untouched.
///
/// ´claim:control:a-response-may-not-overwrite-what-it-reports-on´
/// ´test:crate:a-response-may-not-overwrite-what-it-reports-on´
#[test]
fn a_response_may_not_overwrite_what_it_reports_on() {
    let root = tree(
        "As §10.3 requires.\n",
        "{ path = \"packages/project-b/docs/note.md\", maximum = 1 }",
    );
    let (input, _output) = request(root.path(), AUDIT);

    let lists = root.path().join(".linter/lists.toml");

    assert!(
        refused(maintain(root.path(), Operation::Audit, &input, &lists))
            .contains("declared configuration file"),
        "a declared file may not be written over"
    );

    assert!(
        refused(maintain(
            root.path(),
            Operation::Audit,
            &input,
            &root.path().join(".linter")
        ))
        .contains("declared configuration file"),
        "the declaration directory itself may not be replaced"
    );

    let disguised = root.path().join("packages/../.linter/response.json");

    assert!(
        refused(maintain(root.path(), Operation::Audit, &input, &disguised))
            .contains("declared configuration file"),
        "a lexical alias of the declaration directory is protected before the response exists"
    );

    let outside = TempDir::new().expect("an outside directory");
    let outside_response = outside.path().join("response.json");

    assert!(
        refused(maintain(
            root.path(),
            Operation::Audit,
            &input,
            &outside_response
        ))
        .contains("direct child"),
        "a response outside the sanctioned root location is refused"
    );

    assert!(
        !std::fs::read_to_string(&lists)
            .expect("the list file")
            .is_empty(),
        "and it stands untouched"
    );
}

/// A request the command cannot make sense of refuses the run: an unknown
/// schema, a pair the declaration does not activate, a codec the policy does
/// not select, an audit selector carrying a ceiling, and an authority with
/// an empty field are each a precondition failure rather than a partial
/// answer.
///
/// ´claim:control:a-request-that-does-not-validate-refuses-the-run´
/// ´test:crate:a-request-that-does-not-validate-refuses-the-run´
#[test]
fn a_request_that_does_not_validate_refuses_the_run() {
    let root = tree(
        "As §10.3 requires.\n",
        "{ path = \"packages/project-b/docs/note.md\", maximum = 1 }",
    );

    let authority = r#"{ "authorized_by": "a", "ruling": "b", "reason": "c" }"#;
    let cases = [
        String::from(r#"{ "schema": 2, "operation": "audit", "targets": [] }"#),
        format!(
            r#"{{ "schema": 1, "operation": "audit", "targets": [ {{ "owner": "PROJECTB", "policy": "legacy.todos",
                 "syntax": "path-count", "rows": [], "authority": {authority} }} ] }}"#
        ),
        format!(
            r#"{{ "schema": 1, "operation": "audit", "targets": [ {{ "owner": "PROJECTB",
                 "policy": "legacy.section-references", "syntax": "fingerprint", "rows": [],
                 "authority": {authority} }} ] }}"#
        ),
        format!(
            r#"{{ "schema": 1, "operation": "audit", "targets": [ {{ "owner": "PROJECTB",
                 "policy": "legacy.section-references", "syntax": "path-count",
                 "rows": [ {{ "path": "packages/project-b/docs/note.md", "maximum": 1 }} ],
                 "authority": {authority} }} ] }}"#
        ),
        String::from(
            r#"{ "schema": 1, "operation": "audit", "targets": [ { "owner": "PROJECTB",
                 "policy": "legacy.section-references", "syntax": "path-count", "rows": [],
                 "authority": { "authorized_by": "", "ruling": "b", "reason": "c" } } ] }"#,
        ),
    ];

    for text in cases {
        let (input, output) = request(root.path(), &text);

        assert!(
            matches!(
                maintain(root.path(), Operation::Audit, &input, &output),
                Control::Refused { .. }
            ),
            "expected a refusal for {text}"
        );

        assert!(!output.exists(), "and no response for {text}");
    }
}
