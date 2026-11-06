// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Declared-surface loading, whole-surface refusal, and policy-document tests.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`missing_local_partition_passes_only_in_public_pack_mode`] | snapshot | An activated burn family whose declared local value document is absent loads only when public-pack mode supplies a non-empty outside-tree document, preserving absence as an explicit mode rather than a fallback. |
//! | [`missing_local_partition_refuses_in_normal_mode`] | snapshot | Normal mode refuses the same absent local burn document by its declared repository-relative path, so extracting a pack cannot weaken an estate checkout implicitly. |
//! | [`pack_only_activation_selects_the_private_census`] | snapshot | An explicitly pack-only policy reads no private values in normal mode and still requires a non-empty outside document when checking a public pack. # Panics Panics only if fixture I/O fails or the selected mode violates its contract. |
//! | [`pack_only_activation_refuses_invalid_declarations`] | snapshot | A mode selector cannot hide unknown fields, malformed paths, or invalid selectors in an otherwise dormant burn declaration. # Panics Panics only if fixture I/O fails or an invalid declaration is admitted. |
//! | [`malformed_burn_document_refuses`] | snapshot | A selected burn document that is not the declared TOML schema refuses the entire snapshot with the document path named. |
//! | [`empty_burn_document_refuses`] | snapshot | A selected burn document with zero entries refuses the entire snapshot, preventing an activated zero scan from passing vacuously. |
//! | [`a_declared_file_carries_the_envelope_it_requires`] | snapshot | A declared file with an absent or defective envelope refuses the command before one declaration is interpreted. The requirement is unconditional and constitutional: it holds of the declared files because they are the configuration, not because the configuration says so, so it is checked before any activation is known. Every defect of the envelope earns one refusal and the same text, because what the loader reports is that the file made no claim rather than which way it failed to make one — a non-canonical input is no document at all, with nothing for satisfaction to hold of. A file that is not a well-formed document keeps the parser's own refusal, because the envelope joins the class a lexical error already occupies rather than absorbing it. |
//! | [`an_absent_declaration_directory_refuses_with_every_missing_file`] | snapshot | A tree with no declaration directory refuses once with all five required document names in their declared order, so repairing one absence does not reveal another only on the next run. |
//! | [`a_declaration_holding_only_shape_refuses_with_the_other_files`] | snapshot | A declaration directory holding only its shape document refuses once with the other four required document names in their declared order. |
//! | [`the_declared_files_load_as_one_snapshot`] | snapshot | The declared files load as one snapshot, and the parsed value carries each declaration back: the owner list, the two pattern relations, the reach rows, the environment rows, the activated pairs and the list at each pair, together with the SPDX, envelope and file-path parameters. The claim is the whole surface loading at once rather than how many members it currently has. |
//! | [`the_directory_is_exactly_the_declared_files`] | snapshot | The snapshot is exactly the declared filenames and no others. A file that is not there and an entry that is none of them are both refusals, because a partial load would let a command form a verdict from a configuration nobody wrote. The claim is the closed set rather than its size, which is why the seventh file joining it changes nothing here. |
//! | [`the_file_path_document_is_required_by_its_activation`] | snapshot | The file-path policy's instance document is required by its activation, and a repository holding no exception for an activated owner writes that owner an empty section rather than omitting it. A section is an exclusion list and an optional gloss: the `include` records are absent by default, and where they stand the decoder reads them so that the policy's own pass can hold them to the checked partition. The sections carry pair-to-section equality exactly, in both directions, so a section without a pair declares exceptions nothing reads and a pair without a section activates a verdict with no section to form it over. |
//! | [`the_header_document_is_required_by_its_activation`] | snapshot | The header policy's instance document is required by its activation and by nothing else. An owner activating the program without a section activates a verdict with no parameters to form it from; a section for an owner activating nothing declares a requirement nothing reads; and a corpus activating the program nowhere writes no document at all, which is how the ratified grammar says non-application. Its halves still require both lists, because here an inclusion row selects the governed set rather than describing it. |
//! | [`the_envelope_document_is_required_by_its_activation`] | snapshot | The envelope policy's instance document is required by its activation, and a corpus activating the program nowhere writes no document. Required is not the same set as recognized: a document whose name identifies a policy declaration joins the surface physically and answers for its envelope, while a name of no declared shape is a refusal wherever it stands, so the directory stays a closed surface without being a closed list of filenames. |
//! | [`each_section_name_is_read_against_its_own_table`] | snapshot | Each name in the fifth file is read against the table its own key makes it a name of. A row's `name` is read against no table at all: it is minted where it stands, names the region the row claims, and must only be unique in its own list. A partition row's reference is spelled under the half's own type and must resolve in that half's set. So a repeated row name refuses in either list, because two rows answering to one name make the report that names the row unreadable, and a repeated reference refuses too: where one licence entry reaches is one question, and an entry taking two disjoint pieces of a share writes one pattern admitting both. |
//! | [`a_set_entry_is_held_to_its_halfs_grammar`] | snapshot | A set entry is held to the grammar its half fixes: the identifier to the closed licence-expression syntax, the copyright to a nonempty line, and the name of each to the declared-name grammar. The identifier is never held to membership in a published list, which is what lets the surface carry an expression no list holds. |
//! | [`a_header_pair_and_a_section_require_each_other`] | snapshot | The header pair and the owner's section require each other exactly, in both directions. A section for an owner holding no pair declares a requirement nothing will ever read, and a pair whose owner has no section activates a verdict with no parameters to form it from. |
//! | [`an_envelope_pair_and_a_section_require_each_other`] | snapshot | The envelope pair and the owner's section require each other exactly, in both directions, as the header pair and its section already do. A section for an owner holding no pair declares a governed set nothing will ever read, and a pair whose owner has no section activates a verdict with no share to form it over. |
//! | [`a_malformed_spdx_selection_is_refused_once_where_written`] | snapshot | A malformed SPDX selection is refused once where written: the section is written, so a second refusal saying it is missing would send a reader to add what is there. |
//! | [`a_malformed_interchange_selection_is_refused_once_where_written`] | snapshot | A malformed interchange selection is refused once where written: the section is written, so a second refusal saying it is missing would send a reader to add what is there. |
//! | [`a_malformed_reference_selection_is_refused_once_where_written`] | snapshot | A malformed reference selection is refused once where written: the section is written, so a second refusal saying it is missing would send a reader to add what is there. |
//! | [`a_paths_document_declaring_an_unknown_encoding_is_refused_where_written`] | snapshot | Only `utf-8` is read; any other encoding is refused at the owner datum that wrote it. |
//! | [`a_paths_section_and_its_activation_are_held_equal`] | snapshot | The written document has one section for each activation and no others. |
//! | [`an_absent_paths_document_declares_utf_8`] | snapshot | Without an instance document, an activated owner reads the usual encoding. |
//! | [`a_path_set_row_is_a_bare_path_filed_under_its_owner`] | snapshot | A path-set row is a bare path and carries no ceiling, because the identity holds at most one violation and a ceiling that could only ever be one would encode nothing. The path is still held to the two rules every declared path is: it decodes canonically, and it is filed under the owner the inclusion relation attributes it to. |
//! | [`a_lexical_or_shape_defect_refuses_the_snapshot`] | snapshot | A file that does not parse, and a file carrying a key the schema does not have, are both refused before any name in them is looked at. A snapshot that is not a snapshot has nothing to cross-validate. |
//! | [`the_retired_spelling_of_the_partition_refuses_with_its_successor`] | snapshot | The relation dividing the universe among owners is declared under the word that says what it does, and the spelling it retired refuses by name with its successor rather than being read as a synonym. A surface carrying both words for one relation is one where the meaning depends on which a reader learnt first, and an author who wrote the old word was not guessing: what they are owed is the sentence saying where the declaration lives now. Declaring the relation under neither word refuses too, because a partition nobody wrote is not an empty partition — it is a universe nobody divided. |
//! | [`a_self_reach_row_refuses_the_snapshot`] | snapshot | A may-cite row stating an owner's reach to itself refuses the snapshot, and the refusal names the owner. Self reach follows from an owner being its own corpus rather than from any row, so a row spelling it states no decision and the surface declines to carry one; the relation the file writes down is the set of reaches somebody chose. A row between two different owners is untouched by this snapshot rule. Structural root reach is checked later, once the execution plan knows which owners bear crates. |
//! | [`an_unknown_name_refuses_the_snapshot`] | snapshot | A name the snapshot uses and the binary or the owner list does not know is a refusal wherever it stands: an unregistered owner in any of the three files, an uncatalogued policy, and an identifier outside either grammar. |
//! | [`an_unparseable_pattern_refuses_the_snapshot`] | snapshot | A pattern the engine will not compile is a refusal rather than a row that matches nothing, so a declaration whose regex is broken is refused where it is written instead of silently accounting no file. A pattern that merely uses the language's reach — the metacharacters the retired closed grammar refused — is an ordinary row and loads. |
//! | [`an_exact_duplicate_row_refuses_the_snapshot`] | snapshot | A row written twice adds no set and hides which of the two a reader is looking at, so an exact duplicate is a schema defect in every relation the snapshot carries. The partition is now guarded by its names as the exclusion set always was, and the two rules meet rather than replace each other: one name over two rows refuses before their reaches are compared, and two names over one reach is still one row written twice. A row naming no region refuses in the surface's own words, because a reader who wrote the nameless spelling was writing what was lawful before the ruling. |
//! | [`every_pair_carries_one_list_in_its_own_codec`] | snapshot | Every activated pair has exactly one list, in the codec its policy selects. A pair with no list, a list at a pair nothing activates, and a list written in the other codec are three ways of failing that, and each refuses. |
//! | [`a_row_identity_and_ceiling_are_held_to_their_forms`] | snapshot | A row's identity and its ceiling are held to their forms: a non-canonical fingerprint, a path display that does not decode, and a ceiling that is not a positive integer are each refused rather than repaired. |
//! | [`a_path_count_row_is_filed_under_its_own_owner`] | snapshot | A path-count row is filed under the owner the inclusion relation attributes its file to, and a row filed elsewhere is a defect of the snapshot rather than a disagreement with the tree — so it is refused without the tree being consulted at all. |
//! | [`a_refusal_carries_every_defect_it_found`] | snapshot | Every refusal a snapshot carries is collected rather than only the first, because a caller repairing a declaration wants the whole list and a second run to learn there is more is a poor way to find out. |
//! | [`the_scenario_document_declares_the_range_the_matrix_numbered`] | snapshot | The scenario document's set declares exactly the marked ordinal the retired matrix numbered: the mark, and one through ninety-one inclusive. The claim is equivalence with the value the compiled constant carried, because a payload that moved when it was written down would be a new bound rather than the same one relocated. |
//! | [`the_division_document_declares_the_twelve_sentences`] | snapshot | The division document's set declares the twelve sentences the compiled enumeration carried, and reads exactly what it read. The two hold them in different orders — the document's is its entries' and the enumeration's was the matrix's presentation — so the equivalence is asked over what they read, which is the only thing the program promises: occurrences come back ordered by where they stand rather than by which value found them. |
//! | [`the_prefix_number_document_declares_the_three_schemes`] | snapshot | The prefix-number document declares the three schemes the residual sweep left behind, each carrying the bound its own document issued: the eight work packages by enumeration, the thirty chapters by range, and the lettered records by their bands. The three are the values the compiled constants carried, and they remain mutually disjoint, which is what lets one occurrence be counted exactly once. |
//! | [`the_assembly_document_declares_the_publication_it_publishes`] | snapshot | The assembly document declares the parts directory, the document they publish, and the owner both belong to. The owner is the addition the document makes: the compiled constant carried a pair and left attribution to be derived, and a row standing on an owner's table states it. |
//! | [`the_owner_name_document_declares_the_prefix_and_the_unbuilt_member`] | snapshot | The owner-name document declares the prefix every crate name is stripped of and the one registered crate the workspace does not build, which are the two values the compiled constants carried. The unbuilt member is recognised by what its table does not say: a crate name and a directory with no manifest key is what it is to be registered and not yet built. |
//! | [`roots_the_partition_at_the_owner_whose_share_is_the_repository`] | snapshot | The root owner is explicitly declared independently of partition geography. A package-local fixture exercises this through the complete document loader. |
//! | [`names_no_root_owner_where_the_partition_roots_two_or_none`] | snapshot | Root-file partitions and subtree-only partitions both refuse without an explicit root owner declaration. # Panics Panics only if the temporary fixture cannot be written or unexpectedly loads. |

use tempfile::TempDir;

use crate::names::Encoding;
use crate::snapshot::{
    INTERCHANGE_NAMESPACE, PATH_LINKING_NAMESPACE, PATHS_NAMESPACE, SPDX_NAMESPACE,
};
use crate::{
    Configuration, DIRECTORY, ENVIRONMENTS_FILE, LISTS_FILE, OWNERS_FILE, POLICIES_FILE, Pair,
    Refusal, Rows, SHAPE_FILE, Snapshot, SnapshotMode, configuration, configuration_with_mode,
};

/// The names the fixtures write their three instance documents under.
///
/// A filename is where an author put a document and never its identity, so a
/// fixture naming them here rather than importing a compiled constant is
/// exercising the loader's own rule: a `policy-NAME.toml` entry is a member,
/// and which namespace it stamps is what the loader reads it by.
const POLICY_SPDX_FILE: &str = "policy-spdx.toml";

/// The name the fixtures write the envelope policy's document under.
const POLICY_INTERCHANGE_FILE: &str = "policy-interchange.toml";

/// The optional path-name policy document in these fixtures.
const POLICY_PATHS_FILE: &str = "policy-paths.toml";

/// The name the fixtures write the file-path policy's document under.
const POLICY_REFERENCES_FILE: &str = "policy-references.toml";

/// The name the fixtures give the external-value burn policy document.
const POLICY_PUBLIC_PACK_BURN_FILE: &str = "policy-public-pack-values.toml";
use crate::assembly::Publication;
use crate::catalogue::Codec;
use crate::program::{LiteralSet, MarkNumbered, PrefixBound, PrefixNumbers};
use crate::roster::{OwnerNames, UnbuiltMember};
use crate::spdx::Half;

/// A fictional owner file carried by this package's fixtures.
const OWNERS_DOCUMENT: &str = include_str!("../../tests/fixtures/root-owner.toml");

/// The owner file a fixture starts from: one owner, one subtree, no ignore, self reach.
const OWNERS: &str = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]\n\
        partitions = [{ name = \"crate-sources\", owner = \"PROJECTB\", pattern = '%s\"src\" [ \"/\" *VCHAR ]' }]\n\
        may_cite = []\n";

/// The shape document a fixture starts from: the tracked universe, nothing ignored.
///
/// It is a fixed core member like the other four, so every fixture writes one:
/// its absence is a refusal rather than a shorter snapshot, and a corpus whose
/// universe answer and owner activations resolve every exclusion class declares
/// the empty ignore relation rather than no relation.
const SHAPE: &str = "universe = \"git-tracked\"\n\nignore = []\n";

/// The environment file a fixture starts from.
const ENVIRONMENTS: &str = "reserved_kinds = [\"test\"]\n\
    reserved_extensions = [\"todo\"]\n\
    environments = [{ environment = \"Rule\", kind = \"rule\" }]\n\
    extensions = [{ environment = \"Note\", kind = \"rem\" }]\n";

/// The activation file a fixture starts from: one pair, whose policy has no prerequisite.
const POLICIES: &str =
    "policies = [{ owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }]\n";

/// The list file a fixture starts from: the one pair's list, retained and empty.
const LISTS: &str = "[PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n";

/// A small owner share for the path-name document's three loader claims.
const NAMES_OWNERS: &str = "root_owner = \"QUARRY\"\nowners = [\"QUARRY\"]\n\
        partitions = [{ name = \"src\", owner = \"QUARRY\", pattern = '%s\"src\" [ \"/\" *VCHAR ]' }]\n\
        may_cite = []\n";

/// One path-name activation and its empty path-set debt.
const NAMES_POLICIES: &str =
    "policies = [{ owner = \"QUARRY\", policy = \"paths.names-well-formed\" }]\n";
const NAMES_LISTS: &str = "[QUARRY.\"paths.names-well-formed\"]\npaths = []\n";

/// The optional document's envelope, without an owner section.
const NAMES_DOCUMENT: &str = "namespace = \"class.linter.policy.paths\"\nversion = [1, 0, 0]\n";

/// The fifth file a fixture starts from: its envelope, two empty sets and no section.
///
/// This is the surface's own idiom for applicable and clean, and it is what a
/// repository activating no header pair writes.
const PARAMETERS: &str = "namespace = \"class.linter.policy.spdx\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.identifier]\n\
        \n\
        [set.copyright]\n";

/// The sixth file a fixture starts from: its envelope and an empty owner table.
///
/// The file is required whether or not any owner activates the policy, so
/// this is what a repository governing nothing writes — the same idiom the
/// fifth file's default already is.
const INTERCHANGE: &str = "namespace = \"class.linter.policy.interchange\"\n\
        version = [1, 0, 0]\n";

/// The seventh file a fixture starts from: its envelope and an empty owner table.
///
/// It is required on the same ground the sixth is, and a repository holding
/// no exception writes exactly this.
const REFERENCES: &str = "namespace = \"class.linter.policy.references.path-linking\"\n\
        version = [1, 0, 0]\n";

/// The envelope a declared file carries, under the label allocated for its schema.
///
/// Every fixture writes one, because the loader requires it of every declared
/// file before it interprets a single declaration: a file without it is not a
/// configuration the loader reads at all, which is a different test from the
/// one each of these is.
fn envelope(schema: &str) -> String {
    format!(
        "namespace = \"{}.{schema}\"\nversion = [1, 0, 0]\n\n",
        if schema == "lists" || schema.starts_with("policy.") {
            "class.linter"
        } else {
            "org.example.linter"
        }
    )
}

/// Write a declaration directory carrying these four values and the default fifth file.
///
/// The four are written under their envelopes and the fifth carries its own,
/// so what a caller passes is the declaration it is testing rather than the
/// header every declared file repeats.
fn tree(owners: &str, environments: &str, policies: &str, lists: &str) -> TempDir {
    let root = TempDir::new().expect("a temporary root");
    let directory = root.path().join(DIRECTORY);

    std::fs::create_dir(&directory).expect("the declaration directory");

    for (file, schema, text) in [
        (OWNERS_FILE, "owners", owners),
        (ENVIRONMENTS_FILE, "environments", environments),
        (POLICIES_FILE, "policies", policies),
        (LISTS_FILE, "lists", lists),
        (SHAPE_FILE, "shape", SHAPE),
    ] {
        std::fs::write(directory.join(file), format!("{}{text}", envelope(schema)))
            .expect("a declared file");
    }

    std::fs::write(directory.join(POLICY_SPDX_FILE), PARAMETERS).expect("a declared file");
    std::fs::write(directory.join(POLICY_INTERCHANGE_FILE), INTERCHANGE).expect("a declared file");
    std::fs::write(directory.join(POLICY_REFERENCES_FILE), REFERENCES).expect("a declared file");

    root
}

/// A fixture whose seven files are the defaults.
fn complete() -> TempDir {
    tree(OWNERS, ENVIRONMENTS, POLICIES, LISTS)
}

/// A complete fixture activating one external-value family at the root owner.
fn external_burn_fixture() -> TempDir {
    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"public-pack.values-absent\" }]\n";
    let lists = "[PROJECTB.\"labels.mints-well-formed\"]\n\
            allowances = []\n\
            \n\
            [PROJECTB.\"public-pack.values-absent\"]\n\
            path_counts = []\n";
    let root = tree(OWNERS, ENVIRONMENTS, policies, lists);
    let document = "namespace = \"class.linter.policy.public-pack.values-absent\"\n\
            version = [1, 0, 0]\n\
            \n\
            [owners.PROJECTB]\n\
            surface = \"*VCHAR\"\n\
            values = \"local/linter/example-burn.toml\"\n\
            exclude = '%s\"local\" [ \"/\" *VCHAR ]'\n";

    write_document(&root, POLICY_PUBLIC_PACK_BURN_FILE, document);

    root
}

/// Write the repository-local burn-value document selected by the fixture policy.
fn write_burn_values(root: &TempDir, source: &str) {
    let directory = root.path().join("local/linter");
    std::fs::create_dir_all(&directory).expect("the local fixture directory");
    std::fs::write(directory.join("example-burn.toml"), source).expect("the burn-value document");
}

/// The twelve division names, as the retiring matrix wrote them.
const DIVISION_NAMES: [&str; 12] = [
    "Information flows strictly forward",
    "The core model and the decision layer are independent",
    "Structure can change without destroying what was learned",
    "Stale state dissolves on a bounded schedule",
    "Learning converges despite censoring and class imbalance",
    "The anchor provides coverage when the sister can't",
    "The decision landscape faithfully reflects model belief",
    "Calibration and companion trackers stay current",
    "The fast path stays fast",
    "The system knows when it's struggling",
    "None of the above breaks under weird inputs",
    "Recovery preserves state and failures stay explicit",
];

/// The eight dotted numbers the retired work plan issued.
const WORK_PACKAGE_NUMBERS: [&str; 8] = ["2", "8", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5"];

/// The numbers the lettered record series carried.
const RECORD_LOCATORS: [u32; 35] = [
    110, 120, 130, 140, 150, 160, 170, 210, 220, 230, 240, 250, 260, 270, 310, 320, 330, 340, 350,
    360, 370, 410, 420, 430, 440, 450, 460, 510, 520, 530, 540, 550, 560, 570, 580,
];

/// The scenario document's set, as the corpus declares it.
const SCENARIOS_DOCUMENT: &str = "namespace = \"class.linter.policy.references.scenarios\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.numbered-marks]\n\
        hash-one-to-91 = { mark = \"#\", minimum = 1, maximum = 91 }\n";

/// The prefix-number document's set, as the corpus declares it.
const PREFIX_NUMBERS_DOCUMENT: &str = "namespace = \"class.linter.policy.references.prefix-numbers\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.prefix-numbers]\n\
        work-packages = { prefix = \"WP-\", exact = [\"2\", \"8\", \"4.0\", \"4.1\", \"4.2\", \"4.3\", \"4.4\", \"4.5\"] }\n\
        chapters = { prefix = \"L-\", leading-minimum = 1, leading-maximum = 30 }\n\
        records = { prefix = \"L-\", leading = [110, 120, 130, 140, 150, 160, 170, 210, 220, 230, 240, 250, 260, 270, 310, \
        320, 330, 340, 350, 360, 370, 410, 420, 430, 440, 450, 460, 510, 520, 530, 540, 550, 560, 570, 580] }\n";

/// The division document's set, as the corpus declares it.
const DIVISIONS_DOCUMENT: &str = "namespace = \"class.linter.policy.references.divisions\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.literals]\n\
        information = \"Information flows strictly forward\"\n\
        independence = \"The core model and the decision layer are independent\"\n\
        structure = \"Structure can change without destroying what was learned\"\n\
        staleness = \"Stale state dissolves on a bounded schedule\"\n\
        convergence = \"Learning converges despite censoring and class imbalance\"\n\
        anchor-coverage = \"The anchor provides coverage when the sister can't\"\n\
        landscape = \"The decision landscape faithfully reflects model belief\"\n\
        calibration = \"Calibration and companion trackers stay current\"\n\
        latency = \"The fast path stays fast\"\n\
        self-knowledge = \"The system knows when it's struggling\"\n\
        robustness = \"None of the above breaks under weird inputs\"\n\
        recovery = \"Recovery preserves state and failures stay explicit\"\n";

/// The assembly document's publication row, as the corpus declares it.
const ASSEMBLY_DOCUMENT: &str = "namespace = \"class.linter.policy.assembly-publications\"\n\
        version = [1, 0, 0]\n\
        \n\
        [owners.PROJECTA]\n\
        spec = { parts = \"packages/project-a/docs/spec\", target = \"packages/project-a/docs/spec.md\" }\n";

/// The owner-name document's prefix set and its unbuilt member's table.
const OWNER_NAMES_DOCUMENT: &str = "namespace = \"class.linter.policy.owner.names\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.name-prefix-ignore]\n\
        fixture = \"fixture-\"\n\
        \n\
        [owners.PROJECTC]\n\
        crate-name = \"fixture-project-c\"\n\
        package-directory = \"packages/project-c\"\n";

/// Write one further instance document into a complete declaration.
fn write_document(root: &TempDir, file: &str, text: &str) {
    std::fs::write(root.path().join(DIRECTORY).join(file), text).expect("a declared file");
}

/// The set declarations a section fixture references, and the empty owner table.
///
/// Both set tables are required and either may be empty, so the sets and
/// envelope alone are a complete declaration of a repository that activates
/// nothing.
const SETS: &str = "namespace = \"class.linter.policy.spdx\"\n\
        version = [1, 0, 0]\n\
        \n\
        [set.identifier]\n\
        gpl3later = \"GPL-3.0-or-later\"\n\
        \n\
        [set.copyright]\n\
        fixture2026 = \"2026 Fixture project contributors\"\n";

/// One owner's section over the fixture owner's share, shaped as a declared section is.
const SECTION: &str = "\n[owners.PROJECTB.identifier]\n\
        exclude = [{ name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".md\"' }]\n\
        partitions = [{ name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src/\" *VCHAR %s\".rs\"' }]\n\
        \n\
        [owners.PROJECTB.copyright]\n\
        exclude = [{ name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".md\"' }]\n\
        partitions = [{ name = \"code\", copyright = \"fixture2026\", pattern = '%s\"src/\" *VCHAR %s\".rs\"' }]\n";

/// A fixture whose owner holds the header pair and whose fifth file is this declaration.
///
/// The pair and the section require each other exactly, so a fixture
/// exercising a section activates the pair beside it and carries the empty
/// list the pair's codec selects.
fn headed(parameters: &str) -> TempDir {
    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"spdx.headers-conform\" }]\n";
    let lists = "[PROJECTB.\"labels.mints-well-formed\"]\n\
            allowances = []\n\
            \n\
            [PROJECTB.\"spdx.headers-conform\"]\n\
            paths = []\n";

    let root = tree(OWNERS, ENVIRONMENTS, policies, lists);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_SPDX_FILE),
        parameters,
    )
    .expect("the fifth file");

    root
}

/// A fixture whose owner holds the envelope pair and whose sixth file is this declaration.
///
/// The pair and the section require each other exactly, so a fixture
/// exercising a section activates the pair beside it and carries the empty
/// path set the pair's codec selects.
/// A fixture whose seventh file is this text, beside the pair it needs.
///
/// The pair stands because pair-to-section equality is exact in both
/// directions: a section written for an owner holding no pair is itself a
/// refusal, so a fixture testing a section has to activate the policy.
fn referenced(parameters: &str) -> TempDir {
    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"references.file-paths-absent\" }]\n";
    let lists = "[PROJECTB.\"labels.mints-well-formed\"]\n\
            allowances = []\n\
            \n\
            [PROJECTB.\"references.file-paths-absent\"]\n\
            path_counts = []\n";

    let root = tree(OWNERS, ENVIRONMENTS, policies, lists);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_REFERENCES_FILE),
        parameters,
    )
    .expect("the seventh file");

    root
}

fn enveloped(parameters: &str) -> TempDir {
    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"interchange.envelope-conform\" }]\n";
    let lists = "[PROJECTB.\"labels.mints-well-formed\"]\n\
            allowances = []\n\
            \n\
            [PROJECTB.\"interchange.envelope-conform\"]\n\
            paths = []\n";

    let root = tree(OWNERS, ENVIRONMENTS, policies, lists);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_INTERCHANGE_FILE),
        parameters,
    )
    .expect("the sixth file");

    root
}

/// A fixture whose first four files are the defaults and whose fifth is this declaration.
///
/// The default activation carries no header pair, so this is the shape of a
/// repository that declares a vocabulary and activates none of it.
fn parameterized(parameters: &str) -> TempDir {
    let root = complete();
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_SPDX_FILE),
        parameters,
    )
    .expect("the fifth file");

    root
}

/// The snapshot a fixture loads as, failing the test when it is refused.
fn loaded(root: &TempDir) -> Snapshot {
    let loaded = configuration(root.path());
    let Configuration::Present(snapshot) = loaded else {
        panic!("expected the snapshot to load, found {loaded:?}")
    };

    *snapshot
}

/// The refusals a fixture is refused with, failing the test when it is not refused.
fn refusals(root: &TempDir) -> Vec<Refusal> {
    let loaded = configuration(root.path());
    let Configuration::Refused(refusals) = loaded else {
        panic!("expected a refusal, found {loaded:?}")
    };

    refusals
}

/// The refusals a fixture earns when one of its declared files is written this way.
fn written(file: &'static str, text: &str) -> Vec<Refusal> {
    let root = complete();
    std::fs::write(root.path().join(DIRECTORY).join(file), text).expect("a declared file");

    refusals(&root)
}

/// The one refusal a declared file with a defective envelope earns.
fn envelope_refusal(file: &str) -> Vec<Refusal> {
    vec![Refusal::Envelope {
        text: format!(
            "declared configuration: {file}: no envelope; a declared file carries the envelope it requires"
        ),
    }]
}

/// Assert that one SPDX section is refused by the declaration reader.
fn assert_declaration_refusal(section: &str, words: &str) {
    let root = headed(&format!("{SETS}{section}"));
    let refused = refusals(&root);

    assert!(
        refused.iter().any(|refusal| matches!(
            refusal,
            Refusal::Declaration { message, .. } if message.contains(words)
        )),
        "{refused:?}"
    );
}

/// An activated burn family whose declared local value document is absent loads
/// only when public-pack mode supplies a non-empty outside-tree document,
/// preserving absence as an explicit mode rather than a fallback.
///
/// ´claim:snapshot:missing-local-burn-data-is-an-explicit-pack-mode-case´
/// ´test:crate:missing-local-partition-passes-only-in-public-pack-mode´
#[test]
fn missing_local_partition_passes_only_in_public_pack_mode() {
    let root = external_burn_fixture();
    let verifier = TempDir::new().expect("an outside verifier directory");
    let input = verifier.path().join("values.toml");
    std::fs::write(
        &input,
        "values = [{ value = \"sagofink\", match = \"identifier\" }]\n",
    )
    .expect("the outside verifier input");

    let configured =
        configuration_with_mode(root.path(), SnapshotMode::public_pack(Some(input.clone())));
    let Configuration::Present(snapshot) = configured else {
        panic!("public-pack mode should load the external input: {configured:?}")
    };
    let external = snapshot.external_burn().expect("the activated burn family");

    assert!(snapshot.public_pack());
    assert_eq!(external.source(), input.to_string_lossy().as_ref());
    assert_eq!(external.values().len(), 1);
}

/// Normal mode refuses the same absent local burn document by its declared
/// repository-relative path, so extracting a pack cannot weaken an estate
/// checkout implicitly.
///
/// ´claim:snapshot:normal-mode-requires-the-repository-burn-document´
/// ´test:crate:missing-local-partition-refuses-in-normal-mode´
#[test]
fn missing_local_partition_refuses_in_normal_mode() {
    let root = external_burn_fixture();

    assert_eq!(
        refusals(&root),
        [Refusal::MissingBurnDocument {
            path: String::from("local/linter/example-burn.toml"),
        }]
    );
}

/// An explicitly pack-only policy reads no private values in normal mode and
/// still requires a non-empty outside document when checking a public pack.
///
/// # Panics
///
/// Panics only if fixture I/O fails or the selected mode violates its contract.
///
/// ´claim:snapshot:pack-only-activation-preserves-an-unmeasured-normal-check´
/// ´test:crate:pack-only-activation-selects-the-private-census´
#[test]
fn pack_only_activation_selects_the_private_census() {
    let root = external_burn_fixture();
    let policy = root
        .path()
        .join(DIRECTORY)
        .join(POLICY_PUBLIC_PACK_BURN_FILE);
    let mut source = std::fs::read_to_string(&policy).expect("fixture policy");
    source.push_str("activation = \"public-pack\"\n");
    std::fs::write(&policy, source).expect("pack-only policy");
    let Configuration::Present(snapshot) = configuration(root.path()) else {
        panic!("normal mode must not require private input")
    };
    assert!(snapshot.external_burn().is_none());
    assert!(matches!(
        configuration_with_mode(root.path(), SnapshotMode::public_pack(None)),
        Configuration::Refused(_)
    ));
    let verifier = TempDir::new().expect("outside directory");
    let input = verifier.path().join("values.toml");
    for invalid in ["values = []\n", "not valid TOML"] {
        std::fs::write(&input, invalid).expect("invalid external input");
        assert!(matches!(
            configuration_with_mode(root.path(), SnapshotMode::public_pack(Some(input.clone()))),
            Configuration::Refused(_)
        ));
    }
    std::fs::write(
        &input,
        "values = [{ value = \"sagofink\", match = \"identifier\" }]\n",
    )
    .expect("external input");
    let Configuration::Present(snapshot) =
        configuration_with_mode(root.path(), SnapshotMode::public_pack(Some(input)))
    else {
        panic!("pack mode must read valid external input")
    };
    assert_eq!(
        snapshot
            .external_burn()
            .expect("measured family")
            .values()
            .len(),
        1
    );
    write_burn_values(&root, "invalid private input ignored by normal mode");
    assert!(matches!(
        configuration(root.path()),
        Configuration::Present(_)
    ));
}

/// A mode selector cannot hide unknown fields, malformed paths, or invalid
/// selectors in an otherwise dormant burn declaration.
///
/// # Panics
///
/// Panics only if fixture I/O fails or an invalid declaration is admitted.
///
/// ´claim:snapshot:pack-only-declarations-remain-strict-in-normal-mode´
/// ´test:crate:pack-only-activation-refuses-invalid-declarations´
#[test]
fn pack_only_activation_refuses_invalid_declarations() {
    for extra in [
        "activation = \"sometimes\"\n",
        "activation = 1\n",
        "activation = { mode = \"public-pack\" }\n",
        "activation = \"public-pack\"\nunknown = \"ignored\"\n",
    ] {
        let root = external_burn_fixture();
        let policy = root
            .path()
            .join(DIRECTORY)
            .join(POLICY_PUBLIC_PACK_BURN_FILE);
        let mut source = std::fs::read_to_string(&policy).expect("fixture policy");
        source.push_str(extra);
        std::fs::write(&policy, source).expect("invalid policy");
        assert!(!refusals(&root).is_empty(), "accepted {extra}");
    }
    let root = external_burn_fixture();
    let policy = root
        .path()
        .join(DIRECTORY)
        .join(POLICY_PUBLIC_PACK_BURN_FILE);
    let mut source = std::fs::read_to_string(&policy)
        .expect("fixture policy")
        .replace("local/linter/example-burn.toml", "../outside.toml");
    source.push_str("activation = \"public-pack\"\n");
    std::fs::write(&policy, source).expect("invalid path");
    assert!(matches!(
        refusals(&root).as_slice(),
        [Refusal::MalformedBurnDocument { .. }]
    ));
}

/// A selected burn document that is not the declared TOML schema refuses the
/// entire snapshot with the document path named.
///
/// ´claim:snapshot:a-malformed-burn-document-refuses-the-snapshot´
/// ´test:crate:malformed-burn-document-refuses´
#[test]
fn malformed_burn_document_refuses() {
    let root = external_burn_fixture();
    write_burn_values(
        &root,
        "values = [{ value = \"sagofink\", match = \"nearby\" }]\n",
    );
    let refused = refusals(&root);

    assert!(matches!(
        refused.as_slice(),
        [Refusal::MalformedBurnDocument { path, .. }]
            if path == "local/linter/example-burn.toml"
    ));
}

/// A selected burn document with zero entries refuses the entire snapshot,
/// preventing an activated zero scan from passing vacuously.
///
/// ´claim:snapshot:an-empty-burn-document-refuses-the-snapshot´
/// ´test:crate:empty-burn-document-refuses´
#[test]
fn empty_burn_document_refuses() {
    let root = external_burn_fixture();
    write_burn_values(&root, "values = []\n");

    assert_eq!(
        refusals(&root),
        [Refusal::EmptyBurnDocument {
            path: String::from("local/linter/example-burn.toml"),
        }]
    );
}

/// A declared file with an absent or defective envelope refuses the command
/// before one declaration is interpreted. The requirement is unconditional
/// and constitutional: it holds of the declared files because they are the
/// configuration, not because the configuration says so, so it is checked
/// before any activation is known. Every defect of the envelope earns one
/// refusal and the same text, because what the loader reports is that the
/// file made no claim rather than which way it failed to make one — a
/// non-canonical input is no document at all, with nothing for satisfaction
/// to hold of. A file that is not a well-formed document keeps the parser's
/// own refusal, because the envelope joins the class a lexical error already
/// occupies rather than absorbing it.
///
/// ´claim:snapshot:a-declared-file-carries-the-envelope-it-requires´
/// ´test:crate:a-declared-file-carries-the-envelope-it-requires´
#[test]
fn a_declared_file_carries_the_envelope_it_requires() {
    // A file carrying no envelope has not identified itself, and the refusal
    // arrives instead of the unknown-owner refusal its content would earn:
    // the envelope is read before the content rather than beside it.
    assert_eq!(
        written(
            POLICIES_FILE,
            "policies = [{ owner = \"NOBODY\", policy = \"labels.mints-unique\" }]\n"
        ),
        envelope_refusal(POLICIES_FILE)
    );

    // A label of one atom is a bare top-level word and no label; a triple of
    // two members is no triple; and the pair written the other way round is
    // the envelope misplaced. Each is one refusal, and each refuses alike.
    for envelope in [
        "namespace = \"policies\"\nversion = [1, 0, 0]\n",
        "namespace = \"org.example.linter.policies\"\nversion = [1, 0]\n",
        "version = [1, 0, 0]\nnamespace = \"org.example.linter.policies\"\n",
    ] {
        assert_eq!(
            written(POLICIES_FILE, &format!("{envelope}\npolicies = []\n")),
            envelope_refusal(POLICIES_FILE),
            "{envelope}"
        );
    }

    // A reserved name carrying content is the reservation rather than the
    // placement: the document opened a table where a claim belongs.
    assert_eq!(
        written(
            POLICIES_FILE,
            "version = [1, 0, 0]\npolicies = []\n\n[namespace]\nheld = \"a theory of its own\"\n"
        ),
        envelope_refusal(POLICIES_FILE)
    );

    // And the one rule TOML does not give for free: a bare key written after
    // the first table header belongs to that table, so an envelope standing
    // there is no top-level envelope at all.
    assert_eq!(
        written(
            LISTS_FILE,
            "[PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n\nnamespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n"
        ),
        envelope_refusal(LISTS_FILE)
    );

    // A file that is not a well-formed document keeps the parser's own
    // refusal, which is the text that says what to repair.
    assert!(
        matches!(
            written(POLICIES_FILE, "policies = [").as_slice(),
            [Refusal::Malformed { file, .. }] if *file == POLICIES_FILE
        ),
        "{:?}",
        written(POLICIES_FILE, "policies = [")
    );

    // The sixth file is asked for its envelope like the other five, and it
    // is a declared file rather than a special one: the requirement holds of
    // it because it stands in the directory, not because of what it carries.
    let root = complete();
    let sixth = root.path().join(DIRECTORY).join(POLICY_INTERCHANGE_FILE);

    assert!(sixth.exists());

    std::fs::write(&sixth, "[owners]\n").expect("the sixth file");

    assert!(
        matches!(refusals(&root).as_slice(), [Refusal::Envelope { .. }]),
        "{:?}",
        refusals(&root)
    );
}

/// A tree with no declaration directory refuses once with all five required
/// document names in their declared order, so repairing one absence does not
/// reveal another only on the next run.
///
/// ´claim:snapshot:an-absent-declaration-refuses-with-every-missing-file´
/// ´test:crate:an-absent-declaration-directory-refuses-with-every-missing-file´
#[test]
fn an_absent_declaration_directory_refuses_with_every_missing_file() {
    let root = TempDir::new().expect("a temporary root");

    assert_eq!(
        configuration(root.path()),
        Configuration::Refused(vec![
            Refusal::MissingFile { file: OWNERS_FILE },
            Refusal::MissingFile {
                file: ENVIRONMENTS_FILE,
            },
            Refusal::MissingFile {
                file: POLICIES_FILE,
            },
            Refusal::MissingFile { file: LISTS_FILE },
            Refusal::MissingFile { file: SHAPE_FILE },
        ])
    );
}

/// A declaration directory holding only its shape document refuses once with
/// the other four required document names in their declared order.
///
/// ´claim:snapshot:a-shape-only-declaration-refuses-with-every-other-missing-file´
/// ´test:crate:a-declaration-holding-only-shape-refuses-with-the-other-files´
#[test]
fn a_declaration_holding_only_shape_refuses_with_the_other_files() {
    let root = TempDir::new().expect("a temporary root");
    let directory = root.path().join(DIRECTORY);
    std::fs::create_dir(&directory).expect("the declaration directory");
    std::fs::write(
        directory.join(SHAPE_FILE),
        format!("{}{SHAPE}", envelope("shape")),
    )
    .expect("the shape document");

    assert_eq!(
        configuration(root.path()),
        Configuration::Refused(vec![
            Refusal::MissingFile { file: OWNERS_FILE },
            Refusal::MissingFile {
                file: ENVIRONMENTS_FILE,
            },
            Refusal::MissingFile {
                file: POLICIES_FILE,
            },
            Refusal::MissingFile { file: LISTS_FILE },
        ])
    );
}

/// The declared files load as one snapshot, and the parsed value carries
/// each declaration back: the owner list, the two pattern relations, the
/// reach rows, the environment rows, the activated pairs and the list at
/// each pair, together with the SPDX, envelope and file-path parameters.
/// The claim is the whole surface loading at once rather than how many
/// members it currently has.
///
/// ´claim:snapshot:the-declared-files-load-as-one-snapshot´
/// ´test:crate:the-declared-files-load-as-one-snapshot´
#[test]
fn the_declared_files_load_as_one_snapshot() {
    let root = complete();

    let Configuration::Present(snapshot) = configuration(root.path()) else {
        panic!("expected the snapshot to load");
    };

    assert_eq!(snapshot.owners(), ["PROJECTB"]);
    assert_eq!(snapshot.partitions().len(), 1);
    assert_eq!(snapshot.shape().ignore().len(), 0);
    assert_eq!(snapshot.may_cite().len(), 0);
    assert_eq!(snapshot.environments().len(), 1);
    assert_eq!(snapshot.environment_extensions().len(), 1);
    assert_eq!(
        snapshot
            .reserved_kinds()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["test"]
    );
    assert_eq!(
        snapshot
            .reserved_extensions()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["todo"]
    );
    assert_eq!(snapshot.policies().len(), 1);

    let pair = Pair::singleton("PROJECTB", "labels.mints-well-formed");

    assert_eq!(
        snapshot.lists().get(&pair),
        Some(&Rows::Allowances(Vec::new()))
    );
    assert!(snapshot.lists()[&pair].is_empty());
}

/// The snapshot is exactly the declared filenames and no others. A file that
/// is not there and an entry that is none of them are both refusals, because
/// a partial load would let a command form a verdict from a configuration
/// nobody wrote. The claim is the closed set rather than its size, which is
/// why the seventh file joining it changes nothing here.
///
/// ´claim:snapshot:the-directory-is-exactly-the-declared-files´
/// ´test:crate:the-directory-is-exactly-the-declared-files´
#[test]
fn the_directory_is_exactly_the_declared_files() {
    let root = complete();
    std::fs::remove_file(root.path().join(DIRECTORY).join(LISTS_FILE)).expect("the list file");

    assert_eq!(
        refusals(&root),
        vec![Refusal::MissingFile { file: LISTS_FILE }]
    );

    let root = complete();
    std::fs::write(root.path().join(DIRECTORY).join("notes.toml"), "").expect("a stray file");

    assert_eq!(
        refusals(&root),
        vec![Refusal::UnknownMember {
            name: String::from("notes.toml")
        }]
    );
}

/// The file-path policy's instance document is required by its activation,
/// and a repository holding no exception for an activated owner writes that
/// owner an empty section rather than omitting it. A section is an exclusion
/// list and an optional gloss: the `include` records are absent by default,
/// and where they stand the decoder reads them so that the policy's own pass
/// can hold them to the checked partition. The sections carry pair-to-section
/// equality exactly, in both directions, so a section without a pair declares
/// exceptions nothing reads and a pair without a section activates a verdict
/// with no section to form it over.
///
/// ´claim:snapshot:the-file-path-document-is-required-by-its-activation´
/// ´test:crate:the-file-path-document-is-required-by-its-activation´
#[test]
fn the_file_path_document_is_required_by_its_activation() {
    // Absent with no activation, and the directory loads: the policy governs
    // nothing.
    let root = complete();
    std::fs::remove_file(root.path().join(DIRECTORY).join(POLICY_REFERENCES_FILE))
        .expect("the file-path document");

    assert!(loaded(&root).references().sections.is_empty());

    // Present with a section, and it is read. The exclusion names this
    // owner's own exception; there is no inclusion list to carry, because a
    // policy assigning no parameter per cell has nothing for one to name.
    let root = referenced(
        "namespace = \"class.linter.policy.references.path-linking\"\nversion = [1, 0, 0]\n\n\
             [owners.PROJECTB.path-references]\n\
             exclude = [{ name = \"readmes\", pattern = '[ *VCHAR \"/\" ] %s\"README.md\"' }, \
             { name = \"vendored\", pattern = '%s\"src/vendor\" [ \"/\" *VCHAR ]' }]\n",
    );

    let snapshot = loaded(&root);
    let section = &snapshot.references().sections["PROJECTB"];

    assert_eq!(section.exclude.len(), 2);
    assert_eq!(section.exclude[0].name, "readmes");
    assert_eq!(section.exclude[1].name, "vendored");

    // A section with no gloss declares none, and the two states stay apart: a
    // section with an empty list would declare an empty gloss, which is a
    // claim the policy's own pass can find false.
    let root = referenced(
        "namespace = \"class.linter.policy.references.path-linking\"\nversion = [1, 0, 0]\n\n\
             [owners.PROJECTB.path-references]\nexclude = []\n",
    );

    assert!(!loaded(&root).references().sections["PROJECTB"].glossed());

    // Pair-to-section equality, in the direction the section stands without
    // the pair: an owner the activation document never names declares
    // exceptions nothing will read.
    let root = tree(OWNERS, ENVIRONMENTS, POLICIES, LISTS);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_REFERENCES_FILE),
        "namespace = \"class.linter.policy.references.path-linking\"\nversion = [1, 0, 0]\n\n\
             [owners.PROJECTB.path-references]\nexclude = []\n",
    )
    .expect("the file-path document");

    assert_eq!(
        refusals(&root),
        vec![Refusal::UnpairedReferenceSection {
            owner: String::from("PROJECTB"),
            found: "the section"
        }]
    );
}

/// The header policy's instance document is required by its activation and
/// by nothing else. An owner activating the program without a section
/// activates a verdict with no parameters to form it from; a section for an
/// owner activating nothing declares a requirement nothing reads; and a
/// corpus activating the program nowhere writes no document at all, which is
/// how the ratified grammar says non-application. Its halves still require
/// both lists, because here an inclusion row selects the governed set rather
/// than describing it.
///
/// ´claim:snapshot:the-header-document-is-required-by-its-activation´
/// ´test:crate:the-header-document-is-required-by-its-activation´
#[test]
fn the_header_document_is_required_by_its_activation() {
    // Absent with no activation, and the directory loads: a program no owner
    // activates asks the corpus for nothing.
    let root = complete();
    std::fs::remove_file(root.path().join(DIRECTORY).join(POLICY_SPDX_FILE))
        .expect("the header document");

    assert!(matches!(
        configuration(root.path()),
        Configuration::Present(_)
    ));

    // Absent with an activation, and the directory refuses.
    let root = headed(PARAMETERS);
    std::fs::remove_file(root.path().join(DIRECTORY).join(POLICY_SPDX_FILE))
        .expect("the header document");

    assert_eq!(
        refusals(&root),
        vec![Refusal::UnpairedSection {
            owner: String::from("PROJECTB"),
            found: "the activated pair"
        }]
    );

    // A half omitting its inclusion list still refuses. The key is not
    // optional here and not defaulted to empty: a half with no inclusion row
    // governs nothing, so reading an omission as one would silently retire
    // the requirement for that owner's whole share.
    let root = headed(
        "namespace = \"class.linter.policy.spdx\"\nversion = [1, 0, 0]\n\n\
             [set.identifier]\n\n[set.copyright]\n\n\
             [owners.PROJECTB.identifier]\nexclude = []\n\n\
             [owners.PROJECTB.copyright]\nexclude = []\npartitions = []\n",
    );

    assert!(
        loaded(&root).spdx().sections()["PROJECTB"]
            .half(Half::Identifier)
            .partitions()
            .is_empty(),
        "a half declaring no inclusion row governs nothing rather than everything"
    );
}

/// The envelope policy's instance document is required by its activation, and
/// a corpus activating the program nowhere writes no document. Required is
/// not the same set as recognized: a document whose name identifies a policy
/// declaration joins the surface physically and answers for its envelope,
/// while a name of no declared shape is a refusal wherever it stands, so the
/// directory stays a closed surface without being a closed list of filenames.
///
/// ´claim:snapshot:the-envelope-document-is-required-by-its-activation´
/// ´test:crate:the-envelope-document-is-required-by-its-activation´
#[test]
fn the_envelope_document_is_required_by_its_activation() {
    // Absent with no activation, and the directory loads: the policy governs
    // nothing and asks the corpus for nothing.
    let root = complete();
    std::fs::remove_file(root.path().join(DIRECTORY).join(POLICY_INTERCHANGE_FILE))
        .expect("the envelope document");

    assert!(loaded(&root).interchange().sections.is_empty());

    // Present with a section, and it is read: the section divides its owner's
    // share, and the pair the relation requires stands beside it.
    let root = enveloped(
        "namespace = \"class.linter.policy.interchange\"\nversion = [1, 0, 0]\n\n\
             [set.interchange-documents]\nlinter-config = \"the declared surface\"\n\n\
             [owners.PROJECTB.interchange-documents]\n\
             exclude = [{ name = \"cargo-manifest\", pattern = '%s\"Cargo.toml\"' }]\n\
             include = [{ name = \"declared-surface\", interchange-documents = \"linter-config\", pattern = '%s\".linter/\" *VCHAR %s\".toml\"' }]\n",
    );

    let snapshot = loaded(&root);
    let section = &snapshot.interchange().sections["PROJECTB"];

    assert_eq!(section.exclude.len(), 1);
    assert_eq!(section.exclude[0].name, "cargo-manifest");

    // The gloss is optional, and this section declares one, so it is read as
    // a declaration rather than defaulted away.
    assert!(section.glossed(), "the section declares an include gloss");
    assert_eq!(section.gloss().len(), 1);
    assert_eq!(section.gloss()[0].name, "declared-surface");

    // A document whose name identifies a policy declaration joins the surface
    // physically rather than refusing beside it, and a name of no declared
    // shape refuses wherever it stands.
    let root = complete();
    std::fs::write(root.path().join(DIRECTORY).join("notes.toml"), "note = 1\n")
        .expect("an unknown member");

    assert_eq!(
        refusals(&root),
        vec![Refusal::UnknownMember {
            name: String::from("notes.toml")
        }]
    );
}

/// Each name in the fifth file is read against the table its own key makes it
/// a name of. A row's `name` is read against no table at all: it is minted
/// where it stands, names the region the row claims, and must only be unique
/// in its own list. A partition row's reference is spelled under the half's
/// own type and must resolve in that half's set. So a repeated row name
/// refuses in either list, because two rows answering to one name make the
/// report that names the row unreadable, and a repeated reference refuses
/// too: where one licence entry reaches is one question, and an entry taking
/// two disjoint pieces of a share writes one pattern admitting both.
///
/// ´claim:snapshot:each-section-name-is-read-against-its-own-table´
/// ´test:crate:each-section-name-is-read-against-its-own-table´
#[test]
fn each_section_name_is_read_against_its_own_table() {
    let root = headed(&format!("{SETS}{SECTION}"));
    let snapshot = loaded(&root);
    let section = &snapshot.spdx().sections()["PROJECTB"];

    assert_eq!(
        snapshot.spdx().text(Half::Identifier, "gpl3later"),
        Some("GPL-3.0-or-later")
    );
    assert_eq!(
        snapshot.spdx().text(Half::Copyright, "fixture2026"),
        Some("2026 Fixture project contributors")
    );
    assert_eq!(section.half(Half::Identifier).partitions().len(), 1);
    assert_eq!(section.half(Half::Copyright).exclude()[0].name, "prose");

    // One word standing in both halves' exclusion lists is two separate
    // rules, because each list is its own namespace.
    assert_eq!(section.half(Half::Identifier).exclude()[0].name, "prose");

    assert_eq!(
        section.half(Half::Identifier).partitions()[0].name,
        "code",
        "a partition row's name is the region it claims"
    );
    assert_eq!(
        section.half(Half::Identifier).partitions()[0]
            .entry
            .as_deref(),
        Some("gpl3later"),
        "and the entry it carries there is a second declaration beside it"
    );

    // A repeated row name refuses in a partition, as a repeated exclusion
    // name always did: a partition's rows name its parts, and two parts
    // answering to one name make the report that names the part unreadable.
    let repeated = SECTION.replace(
        "partitions = [{ name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src/\" *VCHAR %s\".rs\"' }]",
        "partitions = [{ name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src/one/\" *VCHAR %s\".rs\"' }, \
             { name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src/two/\" *VCHAR %s\".rs\"' }]",
    );
    assert_declaration_refusal(&repeated, "two rows answer to this name");

    // A repeated reference refuses too, and separately: two rows named apart
    // still make one entry reach out of two places, and where an entry
    // reaches is one question.
    let carried_twice = SECTION.replace(
        "partitions = [{ name = \"code\", identifier = \"gpl3later\", pattern = '%s\"src/\" *VCHAR %s\".rs\"' }]",
        "partitions = [{ name = \"one\", identifier = \"gpl3later\", pattern = '%s\"src/one/\" *VCHAR %s\".rs\"' }, \
             { name = \"two\", identifier = \"gpl3later\", pattern = '%s\"src/two/\" *VCHAR %s\".rs\"' }]",
    );
    assert_declaration_refusal(&carried_twice, "two rows carry this entry");

    // The retired spelling — the reference written as the row's name, and so
    // no row name at all — refuses saying which word carries the reference now.
    let retired = SECTION.replace(
        "{ name = \"code\", identifier = \"gpl3later\", pattern =",
        "{ name = \"gpl3later\", pattern =",
    );
    assert_declaration_refusal(&retired, "under the set's own type");

    // A repeated exclusion name refuses.
    let doubled = SECTION.replace(
        "exclude = [{ name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".md\"' }]\npartitions = [{ name = \"code\", identifier",
        "exclude = [{ name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".md\"' }, \
             { name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".txt\"' }]\npartitions = [{ name = \"code\", identifier",
    );
    assert_declaration_refusal(&doubled, "prose");

    // A reference no set declares refuses, and it is a different refusal from
    // a duplicate because it is a different table's question.
    let unknown = SECTION.replace("identifier = \"gpl3later\"", "identifier = \"mit\"");
    assert_declaration_refusal(&unknown, "mit");
}

/// A set entry is held to the grammar its half fixes: the identifier to the
/// closed licence-expression syntax, the copyright to a nonempty line, and
/// the name of each to the declared-name grammar. The identifier is never
/// held to membership in a published list, which is what lets the surface
/// carry an expression no list holds.
///
/// ´claim:snapshot:a-set-entry-is-held-to-its-halfs-grammar´
/// ´test:crate:a-set-entry-is-held-to-its-halfs-grammar´
#[test]
fn a_set_entry_is_held_to_its_halfs_grammar() {
    let envelope = envelope("policy.spdx");
    let broken = "[set.identifier]\ngpl3later = \"GPL 3.0 only\"\n\n[set.copyright]\n";
    let root = parameterized(&format!("{envelope}{broken}"));

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::MalformedText { half, .. } if *half == "identifier"
        )),
        "{:?}",
        refusals(&root)
    );

    let broken = "[set.identifier]\n\n[set.copyright]\nfixture2026 = \" 2026 Fixture\"\n";
    let root = parameterized(&format!("{envelope}{broken}"));

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::MalformedText { half, .. } if *half == "copyright"
        )),
        "{:?}",
        refusals(&root)
    );

    let broken = "[set.identifier]\nGPL = \"GPL-3.0-or-later\"\n\n[set.copyright]\n";
    let root = parameterized(&format!("{envelope}{broken}"));

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::Declaration { message, .. } if message.contains("GPL")
        )),
        "{:?}",
        refusals(&root)
    );

    // And the expression the governing ruling was written with loads, which
    // is the case a published-list check would have rejected.
    let fictional = "[set.identifier]\ngpl5plus = \"GPL-5.0+\"\n\n[set.copyright]\n";
    let root = parameterized(&format!("{envelope}{fictional}"));

    assert_eq!(
        loaded(&root).spdx().text(Half::Identifier, "gpl5plus"),
        Some("GPL-5.0+")
    );
}

/// The header pair and the owner's section require each other exactly, in
/// both directions. A section for an owner holding no pair declares a
/// requirement nothing will ever read, and a pair whose owner has no section
/// activates a verdict with no parameters to form it from.
///
/// ´claim:snapshot:a-header-pair-and-a-section-require-each-other´
/// ´test:crate:a-header-pair-and-a-section-require-each-other´
#[test]
fn a_header_pair_and_a_section_require_each_other() {
    // The pair, with no section for it.
    let root = headed(SETS);

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::UnpairedSection { found, .. } if *found == "the activated pair"
        )),
        "{:?}",
        refusals(&root)
    );

    // The section, with no pair activating it: the default activation file
    // carries the other policy alone.
    let root = parameterized(&format!("{SETS}{SECTION}"));

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::UnpairedSection { found, .. } if *found == "the section"
        )),
        "{:?}",
        refusals(&root)
    );
}

/// The envelope pair and the owner's section require each other exactly, in
/// both directions, as the header pair and its section already do. A section
/// for an owner holding no pair declares a governed set nothing will ever
/// read, and a pair whose owner has no section activates a verdict with no
/// share to form it over.
///
/// ´claim:snapshot:an-envelope-pair-and-a-section-require-each-other´
/// ´test:crate:an-envelope-pair-and-a-section-require-each-other´
#[test]
fn an_envelope_pair_and_a_section_require_each_other() {
    // The pair, with no section for it: the sixth file carries the empty
    // owner table a repository governing nothing writes.
    let root = enveloped(INTERCHANGE);

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::UnpairedEnvelopeSection { found, .. } if *found == "the activated pair"
        )),
        "{:?}",
        refusals(&root)
    );

    // The section, with no pair activating it: the default activation file
    // carries the other policy alone.
    let root = complete();
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_INTERCHANGE_FILE),
        "namespace = \"class.linter.policy.interchange\"\nversion = [1, 0, 0]\n\n\
             [owners.PROJECTB.interchange-documents]\nexclude = [{ name = \"prose\", pattern = '%s\"src/\" *VCHAR %s\".md\"' }]\n",
    )
    .expect("the envelope document");

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::UnpairedEnvelopeSection { found, .. } if *found == "the section"
        )),
        "{:?}",
        refusals(&root)
    );
}

/// A malformed SPDX selection is refused once where written: the section is
/// written, so a second refusal saying it is missing would send a reader to add
/// what is there.
///
/// ´claim:snapshot:a-malformed-spdx-selection-is-refused-once-where-written´
/// ´test:crate:a-malformed-spdx-selection-is-refused-once-where-written´
#[test]
fn a_malformed_spdx_selection_is_refused_once_where_written() {
    let root = headed(&format!(
        "{SETS}\n[owners.PROJECTB.identifier]\nuse = \"gpl3later\"\n"
    ));
    let refused = Refusal::MalformedSelection {
        file: SPDX_NAMESPACE,
        owner: String::from("PROJECTB"),
        set: String::from("identifier"),
    };

    assert_eq!(
        refused.to_string(),
        "class.linter.policy.spdx: PROJECTB: identifier: a section of rows is wanted here and a singular reference stands"
    );
    assert_eq!(refusals(&root), vec![refused]);
}

/// A malformed interchange selection is refused once where written: the section
/// is written, so a second refusal saying it is missing would send a reader to
/// add what is there.
///
/// ´claim:snapshot:a-malformed-interchange-selection-is-refused-once-where-written´
/// ´test:crate:a-malformed-interchange-selection-is-refused-once-where-written´
#[test]
fn a_malformed_interchange_selection_is_refused_once_where_written() {
    let root = enveloped(&format!(
        "{INTERCHANGE}\n[set.interchange-documents]\nselected = \"document\"\n\n[owners.PROJECTB.interchange-documents]\nuse = \"selected\"\n"
    ));
    let refused = Refusal::MalformedSelection {
        file: INTERCHANGE_NAMESPACE,
        owner: String::from("PROJECTB"),
        set: String::from("interchange-documents"),
    };

    assert_eq!(
        refused.to_string(),
        "class.linter.policy.interchange: PROJECTB: interchange-documents: a section of rows is wanted here and a singular reference stands"
    );
    assert_eq!(refusals(&root), vec![refused]);
}

/// A malformed reference selection is refused once where written: the section
/// is written, so a second refusal saying it is missing would send a reader to
/// add what is there.
///
/// ´claim:snapshot:a-malformed-reference-selection-is-refused-once-where-written´
/// ´test:crate:a-malformed-reference-selection-is-refused-once-where-written´
#[test]
fn a_malformed_reference_selection_is_refused_once_where_written() {
    let root = referenced(&format!(
        "{REFERENCES}\n[set.path-references]\nselected = \"reference\"\n\n[owners.PROJECTB.path-references]\nuse = \"selected\"\n"
    ));
    let refused = Refusal::MalformedSelection {
        file: PATH_LINKING_NAMESPACE,
        owner: String::from("PROJECTB"),
        set: String::from("path-references"),
    };

    assert_eq!(
        refused.to_string(),
        "class.linter.policy.references.path-linking: PROJECTB: path-references: a section of rows is wanted here and a singular reference stands"
    );
    assert_eq!(refusals(&root), vec![refused]);
}

/// Only `utf-8` is read; any other encoding is refused at the owner datum that wrote it.
///
/// ´claim:snapshot:a-paths-document-declaring-an-unknown-encoding-is-refused-where-written´
/// ´test:crate:a-paths-document-declaring-an-unknown-encoding-is-refused-where-written´
#[test]
fn a_paths_document_declaring_an_unknown_encoding_is_refused_where_written() {
    for encoding in ["latin-1", concat!("utf-16", "le")] {
        let root = tree(NAMES_OWNERS, ENVIRONMENTS, NAMES_POLICIES, NAMES_LISTS);
        write_document(
            &root,
            POLICY_PATHS_FILE,
            &format!("{NAMES_DOCUMENT}\n[owners.QUARRY]\nencoding = \"{encoding}\"\n"),
        );

        let refused = Refusal::Declaration {
            document: PATHS_NAMESPACE.to_owned(),
            message: format!("QUARRY: encoding: {encoding}: not an encoding this policy reads"),
        };
        assert_eq!(
            refused.to_string(),
            format!(
                ".linter/class.linter.policy.paths: QUARRY: encoding: {encoding}: not an encoding this policy reads"
            )
        );
        assert_eq!(refusals(&root), vec![refused]);
    }
}

/// The written document has one section for each activation and no others.
///
/// ´claim:snapshot:a-paths-section-and-its-activation-are-held-equal´
/// ´test:crate:a-paths-section-and-its-activation-are-held-equal´
#[test]
fn a_paths_section_and_its_activation_are_held_equal() {
    let without_pair = tree(NAMES_OWNERS, ENVIRONMENTS, "policies = []\n", "");
    write_document(
        &without_pair,
        POLICY_PATHS_FILE,
        &format!("{NAMES_DOCUMENT}\n[owners.QUARRY]\n"),
    );
    assert!(
        refusals(&without_pair).contains(&Refusal::UnpairedNamesSection {
            owner: String::from("QUARRY"),
            found: "the section",
        })
    );

    let without_section = tree(NAMES_OWNERS, ENVIRONMENTS, NAMES_POLICIES, NAMES_LISTS);
    write_document(&without_section, POLICY_PATHS_FILE, NAMES_DOCUMENT);
    assert!(
        refusals(&without_section).contains(&Refusal::UnpairedNamesSection {
            owner: String::from("QUARRY"),
            found: "the activated pair",
        })
    );

    let unknown_owner = tree(NAMES_OWNERS, ENVIRONMENTS, NAMES_POLICIES, NAMES_LISTS);
    write_document(
        &unknown_owner,
        POLICY_PATHS_FILE,
        &format!("{NAMES_DOCUMENT}\n[owners.QUARRY]\n\n[owners.OPAQUE]\n"),
    );
    assert_eq!(
        refusals(&unknown_owner),
        vec![Refusal::UnknownOwner {
            file: PATHS_NAMESPACE,
            owner: String::from("OPAQUE"),
        }]
    );

    let paired = tree(NAMES_OWNERS, ENVIRONMENTS, NAMES_POLICIES, NAMES_LISTS);
    write_document(
        &paired,
        POLICY_PATHS_FILE,
        &format!("{NAMES_DOCUMENT}\n[owners.QUARRY]\n"),
    );
    assert_eq!(loaded(&paired).names().encoding("QUARRY"), Encoding::Utf8);
}

/// Without an instance document, an activated owner reads the usual encoding.
///
/// ´claim:snapshot:an-absent-paths-document-declares-utf-8´
/// ´test:crate:an-absent-paths-document-declares-utf-8´
#[test]
fn an_absent_paths_document_declares_utf_8() {
    let root = tree(NAMES_OWNERS, ENVIRONMENTS, NAMES_POLICIES, NAMES_LISTS);
    assert_eq!(loaded(&root).names().encoding("QUARRY"), Encoding::Utf8);
}

/// A path-set row is a bare path and carries no ceiling, because the
/// identity holds at most one violation and a ceiling that could only ever
/// be one would encode nothing. The path is still held to the two rules
/// every declared path is: it decodes canonically, and it is filed under the
/// owner the inclusion relation attributes it to.
///
/// ´claim:snapshot:a-path-set-row-is-a-bare-path-filed-under-its-owner´
/// ´test:crate:a-path-set-row-is-a-bare-path-filed-under-its-owner´
#[test]
fn a_path_set_row_is_a_bare_path_filed_under_its_owner() {
    let policies = "policies = [{ owner = \"PROJECTB\", policy = \"spdx.headers-conform\" }]\n";
    let parameters = format!("{SETS}{SECTION}");

    let declared = "[PROJECTB.\"spdx.headers-conform\"]\npaths = [\"src/one.rs\"]\n";
    let root = tree(OWNERS, ENVIRONMENTS, policies, declared);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_SPDX_FILE),
        &parameters,
    )
    .expect("the fifth file");

    let snapshot = loaded(&root);
    let pair = Pair::singleton("PROJECTB", "spdx.headers-conform");

    let Some(Rows::Paths(rows)) = snapshot.lists().get(&pair) else {
        panic!(
            "expected a path set, found {:?}",
            snapshot.lists().get(&pair)
        );
    };

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].display(), "src/one.rs");
    assert_eq!(snapshot.lists()[&pair].codec(), Codec::PathSet);

    // The other codec's field at this pair is the wrong codec, exactly as it
    // is at every other pair.
    let wrong = "[PROJECTB.\"spdx.headers-conform\"]\npath_counts = []\n";
    let root = tree(OWNERS, ENVIRONMENTS, policies, wrong);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_SPDX_FILE),
        &parameters,
    )
    .expect("the fifth file");

    assert!(
        refusals(&root).iter().any(|refusal| matches!(
            refusal,
            Refusal::WrongCodec { expected, .. } if *expected == Codec::PathSet
        )),
        "{:?}",
        refusals(&root)
    );

    // And a row naming a file the inclusion relation attributes elsewhere is
    // a defect of the snapshot rather than a disagreement with the tree.
    let foreign = "[PROJECTB.\"spdx.headers-conform\"]\npaths = [\"elsewhere/one.rs\"]\n";
    let root = tree(OWNERS, ENVIRONMENTS, policies, foreign);
    std::fs::write(
        root.path().join(DIRECTORY).join(POLICY_SPDX_FILE),
        &parameters,
    )
    .expect("the fifth file");

    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::OwnerPathMismatch { .. })),
        "{:?}",
        refusals(&root)
    );
}

/// A file that does not parse, and a file carrying a key the schema does not
/// have, are both refused before any name in them is looked at. A snapshot
/// that is not a snapshot has nothing to cross-validate.
///
/// ´claim:snapshot:a-lexical-or-shape-defect-refuses-the-snapshot´
/// ´test:crate:a-lexical-or-shape-defect-refuses-the-snapshot´
#[test]
fn a_lexical_or_shape_defect_refuses_the_snapshot() {
    let root = tree("owners = [", ENVIRONMENTS, POLICIES, LISTS);
    assert!(
        matches!(refusals(&root).as_slice(), [Refusal::Malformed { file, .. }] if *file == OWNERS_FILE)
    );

    let extra = format!("{OWNERS}extra = 1\n");
    let root = tree(&extra, ENVIRONMENTS, POLICIES, LISTS);
    assert!(
        matches!(refusals(&root).as_slice(), [Refusal::Malformed { file, .. }] if *file == OWNERS_FILE)
    );

    let root = tree(
        "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]\npartitions = []\n",
        ENVIRONMENTS,
        POLICIES,
        LISTS,
    );
    assert!(matches!(
        refusals(&root).as_slice(),
        [Refusal::Malformed { .. }]
    ));
}

/// The relation dividing the universe among owners is declared under the word
/// that says what it does, and the spelling it retired refuses by name with
/// its successor rather than being read as a synonym. A surface carrying both
/// words for one relation is one where the meaning depends on which a reader
/// learnt first, and an author who wrote the old word was not guessing: what
/// they are owed is the sentence saying where the declaration lives now.
/// Declaring the relation under neither word refuses too, because a partition
/// nobody wrote is not an empty partition — it is a universe nobody divided.
///
/// ´claim:snapshot:the-retired-spelling-of-the-partition-refuses-with-its-successor´
/// ´test:crate:the-retired-spelling-of-the-partition-refuses-with-its-successor´
#[test]
fn the_retired_spelling_of_the_partition_refuses_with_its_successor() {
    let retired = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]\n\
            inclusions = [{ name = \"crate-sources\", owner = \"PROJECTB\", pattern = '%s\"src\" [ \"/\" *VCHAR ]' }]\n\
            may_cite = []\n";
    let root = tree(retired, ENVIRONMENTS, POLICIES, LISTS);

    let refused = refusals(&root);

    assert!(
        refused
            .iter()
            .any(|refusal| matches!(refusal, Refusal::Retired { key, .. } if *key == "inclusions")),
        "{refused:?}"
    );

    assert!(
        refused.iter().any(|refusal| refusal
            .to_string()
            .contains("partitions is the word for it")),
        "the refusal says which word carries the declaration now: {refused:?}"
    );

    // Both words at once is still the retired one standing, so it refuses
    // there too rather than being quietly outvoted by its successor.
    let both = format!(
        "{OWNERS}inclusions = [{{ name = \"crate-sources\", owner = \"PROJECTB\", pattern = '%s\"src\" [ \"/\" *VCHAR ]' }}]\n"
    );
    let root = tree(&both, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::Retired { .. })),
        "{:?}",
        refusals(&root)
    );

    // Neither word, and the owner file has declared no partition at all.
    let neither = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]\nmay_cite = []\n";
    let root = tree(neither, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root).iter().any(|refusal| refusal
            .to_string()
            .contains("partitions: the owner file declares the relation")),
        "{:?}",
        refusals(&root)
    );
}

/// A may-cite row stating an owner's reach to itself refuses the snapshot,
/// and the refusal names the owner. Self reach follows from an owner being
/// its own corpus rather than from any row, so a row spelling it states no
/// decision and the surface declines to carry one; the relation the file
/// writes down is the set of reaches somebody chose. A row between two
/// different owners is untouched by this snapshot rule. Structural root reach
/// is checked later, once the execution plan knows which owners bear crates.
///
/// ´claim:snapshot:a-self-reach-row-refuses-the-snapshot´
/// ´test:crate:a-self-reach-row-refuses-the-snapshot´
#[test]
fn a_self_reach_row_refuses_the_snapshot() {
    let spelled = OWNERS.replace(
        "may_cite = []",
        "may_cite = [{ owner = \"PROJECTB\", target = \"PROJECTB\" }]",
    );
    let root = tree(&spelled, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root).contains(&Refusal::SelfReach {
            owner: String::from("PROJECTB"),
        }),
        "{:?}",
        refusals(&root)
    );

    assert!(
        refusals(&root).iter().any(|refusal| refusal
            .to_string()
            .contains("an owner reaches itself by being itself")),
        "the refusal says why the row is not written: {:?}",
        refusals(&root)
    );

    // A row naming two different owners is a decision and stands. The
    // fixture registers one owner, so the second is registered alongside it
    // and the partition is left as it was: what is under test is the reach
    // relation's own rule and not the partition's.
    let crossing = OWNERS
        .replace(
            "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]",
            "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\", \"OTHER\"]",
        )
        .replace(
            "may_cite = []",
            "may_cite = [{ owner = \"OTHER\", target = \"PROJECTB\" }]",
        );
    let root = tree(&crossing, ENVIRONMENTS, POLICIES, LISTS);

    assert_eq!(
        loaded(&root).may_cite(),
        [crate::snapshot::ReachRow {
            owner: String::from("OTHER"),
            target: String::from("PROJECTB"),
        }],
        "a reach between two owners is a decision and is carried"
    );
}

/// A name the snapshot uses and the binary or the owner list does not know
/// is a refusal wherever it stands: an unregistered owner in any of the
/// three files, an uncatalogued policy, and an identifier outside either
/// grammar.
///
/// ´claim:snapshot:an-unknown-name-refuses-the-snapshot´
/// ´test:crate:an-unknown-name-refuses-the-snapshot´
#[test]
fn an_unknown_name_refuses_the_snapshot() {
    let owners = OWNERS.replace(
        "owner = \"PROJECTB\", pattern",
        "owner = \"GHOST\", pattern",
    );
    let root = tree(&owners, ENVIRONMENTS, POLICIES, LISTS);
    assert!(refusals(&root).contains(&Refusal::UnknownOwner {
        file: OWNERS_FILE,
        owner: String::from("GHOST"),
    }));

    let root = tree(
        "owners = [\"projectb\"]\npartitions = []\nmay_cite = []\n",
        ENVIRONMENTS,
        POLICIES,
        LISTS,
    );
    assert!(refusals(&root).contains(&Refusal::MalformedOwner {
        owner: String::from("projectb"),
    }));

    let policies = POLICIES.replace("labels.mints-well-formed", "labels.mints-unheard-of");
    let root = tree(OWNERS, ENVIRONMENTS, &policies, LISTS);
    assert!(refusals(&root).contains(&Refusal::UnknownPolicy {
        file: POLICIES_FILE,
        policy: String::from("labels.mints-unheard-of"),
    }));

    let owners = OWNERS.replace("root_owner = \"PROJECTB\"", "root_owner = \"GHOST\"");
    let root = tree(&owners, ENVIRONMENTS, POLICIES, LISTS);
    assert!(refusals(&root).contains(&Refusal::UnknownOwner {
        file: OWNERS_FILE,
        owner: String::from("GHOST"),
    }));

    let policies = POLICIES.replace("labels.mints-well-formed", "assembly.retired-current");
    let lists = LISTS.replace("labels.mints-well-formed", "assembly.retired-current");
    let root = tree(OWNERS, ENVIRONMENTS, &policies, &lists);
    for (file, policy) in [
        (POLICIES_FILE, "assembly.retired-current"),
        (LISTS_FILE, "PROJECTB : assembly.retired-current"),
    ] {
        assert!(refusals(&root).iter().any(|refusal| refusal.to_string() == format!(
            ".linter/{file}: {policy}: this binary catalogues no such policy; use assembly.publications-current"
        )));
    }

    let policies = POLICIES.replace("labels.mints-well-formed", "Labels");
    let root = tree(OWNERS, ENVIRONMENTS, &policies, LISTS);
    assert!(refusals(&root).contains(&Refusal::MalformedPolicy {
        file: POLICIES_FILE,
        policy: String::from("Labels"),
    }));
}

/// A pattern the engine will not compile is a refusal rather than a row that
/// matches nothing, so a declaration whose regex is broken is refused where
/// it is written instead of silently accounting no file. A pattern that
/// merely uses the language's reach — the metacharacters the retired closed
/// grammar refused — is an ordinary row and loads.
///
/// ´claim:snapshot:an-unparseable-pattern-refuses-the-snapshot´
/// ´test:crate:an-unparseable-pattern-refuses-the-snapshot´
#[test]
fn an_unparseable_pattern_refuses_the_snapshot() {
    let broken = OWNERS.replace("'%s\"src\" [ \"/\" *VCHAR ]'", "'%s\"src/\" *NOSUCHRULE'");
    let root = tree(&broken, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::MalformedPattern { .. }))
    );

    // The same substitution with a pattern the engine accepts is not a
    // refusal at all. Under the retired grammar it was one, and that is
    // exactly the rule the owner withdrew.
    let open = OWNERS.replace("'%s\"src\" [ \"/\" *VCHAR ]'", "'%s\"src/\" *VCHAR'");
    let root = tree(&open, ENVIRONMENTS, POLICIES, LISTS);

    assert!(matches!(
        configuration(root.path()),
        Configuration::Present(_)
    ));
}

/// A row written twice adds no set and hides which of the two a reader is
/// looking at, so an exact duplicate is a schema defect in every relation
/// the snapshot carries. The partition is now guarded by its names as the
/// exclusion set always was, and the two rules meet rather than replace each
/// other: one name over two rows refuses before their reaches are compared,
/// and two names over one reach is still one row written twice. A row naming
/// no region refuses in the surface's own words, because a reader who wrote
/// the nameless spelling was writing what was lawful before the ruling.
///
/// ´claim:snapshot:an-exact-duplicate-row-refuses-the-snapshot´
/// ´test:crate:an-exact-duplicate-row-refuses-the-snapshot´
#[test]
fn an_exact_duplicate_row_refuses_the_snapshot() {
    let owners = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\"]\n\
            partitions = [{ name = \"first-tree\", owner = \"PROJECTB\", pattern = '%s\"a\" [ \"/\" *VCHAR ]' }, { name = \"second-tree\", owner = \"PROJECTB\", pattern = '%s\"a\" [ \"/\" *VCHAR ]' }]\n\
            may_cite = []\n";
    let root = tree(owners, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root).iter().any(
            |refusal| matches!(refusal, Refusal::DuplicateRow { file, .. } if *file == OWNERS_FILE)
        ),
        "{:?}",
        refusals(&root)
    );

    let named_twice = owners.replace("second-tree", "first-tree");
    let root = tree(&named_twice, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::DuplicateRow { row, .. } if row == "partitions: first-tree")),
        "{:?}",
        refusals(&root)
    );

    let nameless = owners.replace("{ name = \"first-tree\", ", "{ ");
    let root = tree(&nameless, ENVIRONMENTS, POLICIES, LISTS);

    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::NamelessRow { relation, .. } if *relation == "partitions")),
        "{:?}",
        refusals(&root)
    );
}

/// Every activated pair has exactly one list, in the codec its policy
/// selects. A pair with no list, a list at a pair nothing activates, and a
/// list written in the other codec are three ways of failing that, and each
/// refuses.
///
/// ´claim:snapshot:every-pair-carries-one-list-in-its-own-codec´
/// ´test:crate:every-pair-carries-one-list-in-its-own-codec´
#[test]
fn every_pair_carries_one_list_in_its_own_codec() {
    let pair = Pair::singleton("PROJECTB", "labels.mints-well-formed");

    let root = tree(OWNERS, ENVIRONMENTS, POLICIES, "");
    assert_eq!(
        refusals(&root),
        vec![Refusal::UnpairedPolicy { pair: pair.clone() }]
    );

    let lists = format!("{LISTS}\n[PROJECTB.\"labels.mints-unique\"]\nallowances = []\n");
    let root = tree(OWNERS, ENVIRONMENTS, POLICIES, &lists);
    assert_eq!(
        refusals(&root),
        vec![Refusal::OrphanList {
            pair: Pair::singleton("PROJECTB", "labels.mints-unique")
        }]
    );

    let root = tree(
        OWNERS,
        ENVIRONMENTS,
        POLICIES,
        "[PROJECTB.\"labels.mints-well-formed\"]\npath_counts = []\n",
    );
    assert_eq!(
        refusals(&root),
        vec![
            Refusal::WrongCodec {
                pair: pair.clone(),
                expected: Codec::Fingerprint,
                found: String::from("path_counts"),
            },
            Refusal::UnpairedPolicy { pair },
        ]
    );
}

/// A row's identity and its ceiling are held to their forms: a
/// non-canonical fingerprint, a path display that does not decode, and a
/// ceiling that is not a positive integer are each refused rather than
/// repaired.
///
/// ´claim:snapshot:a-row-identity-and-ceiling-are-held-to-their-forms´
/// ´test:crate:a-row-identity-and-ceiling-are-held-to-their-forms´
#[test]
fn a_row_identity_and_ceiling_are_held_to_their_forms() {
    let lists = "[PROJECTB.\"labels.mints-well-formed\"]\nallowances = [{ fingerprint = \"sha256:00\", maximum = 1 }]\n";
    let root = tree(OWNERS, ENVIRONMENTS, POLICIES, lists);
    assert!(refusals(&root).contains(&Refusal::MalformedFingerprint {
        fingerprint: String::from("sha256:00"),
    }));

    let digest = format!("sha256:{}", "a".repeat(64));
    let lists = format!(
        "[PROJECTB.\"labels.mints-well-formed\"]\nallowances = [{{ fingerprint = \"{digest}\", maximum = 0 }}]\n"
    );
    let root = tree(OWNERS, ENVIRONMENTS, POLICIES, &lists);
    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::NonPositiveMaximum { .. }))
    );

    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"legacy.todos\" }]\n";
    let lists = format!(
        "{LISTS}\n[PROJECTB.\"legacy.todos\"]\npath_counts = [{{ path = \"src/../a\", maximum = 1 }}]\n"
    );
    let root = tree(OWNERS, ENVIRONMENTS, policies, &lists);
    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::MalformedPath { .. }))
    );
}

/// A path-count row is filed under the owner the inclusion relation
/// attributes its file to, and a row filed elsewhere is a defect of the
/// snapshot rather than a disagreement with the tree — so it is refused
/// without the tree being consulted at all.
///
/// ´claim:snapshot:a-path-count-row-is-filed-under-its-own-owner´
/// ´test:crate:a-path-count-row-is-filed-under-its-own-owner´
#[test]
fn a_path_count_row_is_filed_under_its_own_owner() {
    let policies = "policies = [\
            { owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, \
            { owner = \"PROJECTB\", policy = \"legacy.todos\" }]\n";

    let lists = format!(
        "{LISTS}\n[PROJECTB.\"legacy.todos\"]\npath_counts = [{{ path = \"src/a.md\", maximum = 2 }}]\n"
    );
    let root = tree(OWNERS, ENVIRONMENTS, policies, &lists);
    assert!(matches!(
        configuration(root.path()),
        Configuration::Present(_)
    ));

    let lists = format!(
        "{LISTS}\n[PROJECTB.\"legacy.todos\"]\npath_counts = [{{ path = \"docs/a.md\", maximum = 2 }}]\n"
    );
    let root = tree(OWNERS, ENVIRONMENTS, policies, &lists);
    assert!(
        refusals(&root)
            .iter()
            .any(|refusal| matches!(refusal, Refusal::OwnerPathMismatch { .. }))
    );
}

/// Every refusal a snapshot carries is collected rather than only the first,
/// because a caller repairing a declaration wants the whole list and a
/// second run to learn there is more is a poor way to find out.
///
/// ´claim:snapshot:a-refusal-carries-every-defect-it-found´
/// ´test:crate:a-refusal-carries-every-defect-it-found´
#[test]
fn a_refusal_carries_every_defect_it_found() {
    let owners = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\", \"PROJECTB\"]\n\
            partitions = [{ name = \"crate-sources\", owner = \"GHOST\", pattern = '%s\"src\" [ \"/\" *VCHAR ]' }]\n\
            may_cite = []\n";
    let root = tree(owners, ENVIRONMENTS, POLICIES, LISTS);

    let found = refusals(&root);

    assert!(
        found.len() >= 2,
        "expected several refusals, found {found:?}"
    );
    assert!(
        found
            .iter()
            .any(|refusal| matches!(refusal, Refusal::DuplicateRow { .. }))
    );
    assert!(
        found
            .iter()
            .any(|refusal| matches!(refusal, Refusal::UnknownOwner { .. }))
    );
}

/// The scenario document's set declares exactly the marked ordinal the
/// retired matrix numbered: the mark, and one through ninety-one inclusive.
/// The claim is equivalence with the value the compiled constant carried,
/// because a payload that moved when it was written down would be a new
/// bound rather than the same one relocated.
///
/// ´claim:snapshot:the-scenario-document-declares-the-range-the-matrix-numbered´
/// ´test:crate:the-scenario-document-declares-the-range-the-matrix-numbered´
#[test]
fn the_scenario_document_declares_the_range_the_matrix_numbered() {
    let root = complete();
    write_document(&root, "policy-scenarios.toml", SCENARIOS_DOCUMENT);

    let snapshot = loaded(&root);

    assert_eq!(
        snapshot.numbered_marks(),
        [(
            String::from("hash-one-to-91"),
            MarkNumbered::new('#', 1, 91)
        )],
        "the declared mark and bound are the compiled constant's"
    );
}

/// The division document's set declares the twelve sentences the compiled
/// enumeration carried, and reads exactly what it read. The two hold them in
/// different orders — the document's is its entries' and the enumeration's
/// was the matrix's presentation — so the equivalence is asked over what they
/// read, which is the only thing the program promises: occurrences come back
/// ordered by where they stand rather than by which value found them.
///
/// ´claim:snapshot:the-division-document-declares-the-twelve-sentences´
/// ´test:crate:the-division-document-declares-the-twelve-sentences´
#[test]
fn the_division_document_declares_the_twelve_sentences() {
    let root = complete();
    write_document(&root, "policy-divisions.toml", DIVISIONS_DOCUMENT);

    let snapshot = loaded(&root);

    let declared = snapshot.declared_literals().expect("the declared set");
    let compiled =
        LiteralSet::new(DIVISION_NAMES).expect("twelve distinct nonempty unbroken values");

    // The two carry the twelve in different orders — the document's is its
    // entries' and the enumeration's was the matrix's presentation — so the
    // equivalence that matters is over what they read rather than over how
    // they are written. The program guarantees exactly that: occurrences come
    // back ordered by where they stand rather than by which value found them.
    let sentences = DIVISION_NAMES.join(". Then ");

    assert_eq!(
        declared.scan_text(0, &sentences),
        compiled.scan_text(0, &sentences),
        "the declared set reads what the compiled enumeration read"
    );
    assert_eq!(
        declared.scan_text(0, &sentences).len(),
        12,
        "and reads all twelve"
    );
}

/// The prefix-number document declares the three schemes the residual sweep
/// left behind, each carrying the bound its own document issued: the eight
/// work packages by enumeration, the thirty chapters by range, and the
/// lettered records by their bands. The three are the values the compiled
/// constants carried, and they remain mutually disjoint, which is what lets
/// one occurrence be counted exactly once.
///
/// ´claim:snapshot:the-prefix-number-document-declares-the-three-schemes´
/// ´test:crate:the-prefix-number-document-declares-the-three-schemes´
#[test]
fn the_prefix_number_document_declares_the_three_schemes() {
    let root = complete();
    write_document(&root, "policy-prefix-numbers.toml", PREFIX_NUMBERS_DOCUMENT);

    let declared = loaded(&root).declared_prefix_numbers();
    let named = |name: &str| {
        declared
            .iter()
            .find(|(entry, _numbers)| entry == name)
            .map(|(_entry, numbers)| numbers.clone())
            .expect("the declared scheme")
    };

    let work = named("work-packages");
    let chapters = named("chapters");
    let records = named("records");

    assert_eq!(
        work,
        PrefixNumbers::new(
            "WP-",
            PrefixBound::Exact(
                WORK_PACKAGE_NUMBERS
                    .iter()
                    .map(|number| (*number).to_owned())
                    .collect()
            ),
            true
        )
    );
    assert_eq!(
        chapters,
        PrefixNumbers::new(
            "L-",
            PrefixBound::LeadingRange {
                minimum: 1,
                maximum: 30
            },
            true
        )
    );
    assert_eq!(
        records,
        PrefixNumbers::new(
            "L-",
            PrefixBound::LeadingSet(RECORD_LOCATORS.to_vec()),
            true
        )
    );

    assert!(
        !chapters.overlaps(&records),
        "one prefix, and no leading value in both"
    );
    assert!(!work.overlaps(&chapters));
    assert!(!work.overlaps(&records));
}

/// The assembly document declares the parts directory, the document they
/// publish, and the owner both belong to. The owner is the addition the
/// document makes: the compiled constant carried a pair and left attribution
/// to be derived, and a row standing on an owner's table states it.
///
/// ´claim:snapshot:the-assembly-document-declares-the-publication-it-publishes´
/// ´test:crate:the-assembly-document-declares-the-publication-it-publishes´
#[test]
fn the_assembly_document_declares_the_publication_it_publishes() {
    let root = complete();
    write_document(
        &root,
        "policy-assembly-publications.toml",
        ASSEMBLY_DOCUMENT,
    );

    assert_eq!(
        loaded(&root).declared_publications(),
        [Publication::new(
            "PROJECTA",
            "packages/project-a/docs/spec",
            "packages/project-a/docs/spec.md"
        )],
        "the declared parts and target are the compiled constant's, and the owner is the document's"
    );
}

/// The owner-name document declares the prefix every crate name is stripped
/// of and the one registered crate the workspace does not build, which are
/// the two values the compiled constants carried. The unbuilt member is
/// recognised by what its table does not say: a crate name and a directory
/// with no manifest key is what it is to be registered and not yet built.
///
/// ´claim:snapshot:the-owner-name-document-declares-the-prefix-and-the-unbuilt-member´
/// ´test:crate:the-owner-name-document-declares-the-prefix-and-the-unbuilt-member´
#[test]
fn the_owner_name_document_declares_the_prefix_and_the_unbuilt_member() {
    let root = complete();
    write_document(&root, "policy-owner-names.toml", OWNER_NAMES_DOCUMENT);

    let names = loaded(&root)
        .declared_owner_names()
        .expect("the declared reconciliation");

    assert_eq!(
        names,
        OwnerNames::new(
            "fixture-",
            [UnbuiltMember::new(
                "fixture-project-c",
                "packages/project-c"
            )]
        ),
        "the declared prefix and unbuilt member are the compiled constants'"
    );
    assert_eq!(
        names
            .derive("superloop-lint")
            .map(|prefix| prefix.as_str().to_owned()),
        Some(String::from("SUPERLOOPLINT")),
        "and the prefix derives what it always derived"
    );
}

/// The root owner is explicitly declared independently of partition geography.
/// A package-local fixture exercises this through the complete document loader.
///
/// ´claim:snapshot:the-root-owner-is-the-one-whose-share-begins-at-the-corpus-root´
/// ´test:crate:roots-the-partition-at-the-owner-whose-share-is-the-repository´
#[test]
fn roots_the_partition_at_the_owner_whose_share_is_the_repository() {
    let invented = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\", \"PART\"]\n\
            partitions = [{ name = \"documentation\", owner = \"PROJECTB\", pattern = '%s\"docs\" [ \"/\" *VCHAR ]' }, \
            { name = \"readme\", owner = \"PROJECTB\", pattern = '%s\"README.md\"' }, \
            { name = \"part-package\", owner = \"PART\", pattern = '%s\"packages/part\" [ \"/\" *VCHAR ]' }]\n\
            may_cite = []\n";

    assert_eq!(
        loaded(&tree(invented, ENVIRONMENTS, POLICIES, LISTS)).root_owner(),
        "PROJECTB",
        "one share opens on a tree and a root file and so shares no opening; the other opens inside the packages tree"
    );
    let explicit = invented.replace("root_owner = \"PROJECTB\"", "root_owner = \"PART\"");
    assert_eq!(
        loaded(&tree(&explicit, ENVIRONMENTS, POLICIES, LISTS)).root_owner(),
        "PART",
        "the declaration governs even when another owner owns the root files"
    );

    let archive_policies =
        "policies = [{ owner = \"ARCHIVE\", policy = \"labels.mints-well-formed\" }]\n";
    let archive_lists = "[ARCHIVE.\"labels.mints-well-formed\"]\nallowances = []\n";
    let root = tree(OWNERS, ENVIRONMENTS, archive_policies, archive_lists);

    std::fs::write(
        root.path().join(DIRECTORY).join(OWNERS_FILE),
        OWNERS_DOCUMENT,
    )
    .expect("the fictional owner file");

    assert_eq!(
        loaded(&root).root_owner(),
        "ARCHIVE",
        "the external fixture supplies its own root owner"
    );
}

/// Root-file partitions and subtree-only partitions both refuse without an
/// explicit root owner declaration.
///
/// # Panics
/// Panics only if the temporary fixture cannot be written or unexpectedly loads.
///
/// ´claim:snapshot:a-partition-rooting-two-owners-or-none-names-no-root-owner´
/// ´test:crate:names-no-root-owner-where-the-partition-roots-two-or-none´
#[test]
fn names_no_root_owner_where_the_partition_roots_two_or_none() {
    let two = "root_owner = \"PROJECTB\"\nowners = [\"PROJECTB\", \"OTHER\"]\n\
            partitions = [{ name = \"readme\", owner = \"PROJECTB\", pattern = '%s\"README.md\"' }, \
            { name = \"licence-text\", owner = \"OTHER\", pattern = '%s\"LICENSE\"' }]\n\
            may_cite = []\n";

    let one = OWNERS.replace("%s\"src\" [ \"/\" *VCHAR ]", "%s\"README.md\"");
    for owners in [two, OWNERS, one.as_str()] {
        let missing = owners.replace("root_owner = \"PROJECTB\"\n", "");
        let root = tree(&missing, ENVIRONMENTS, POLICIES, LISTS);
        assert!(refusals(&root).iter().any(|refusal| refusal.to_string().contains(
            "missing root owner declaration; add root_owner = \"OWNER\" at top level in .linter/owners.toml, replacing OWNER with a name in owners"
        )));
    }
}
