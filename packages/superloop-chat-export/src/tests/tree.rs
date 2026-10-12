use std::collections::BTreeMap;

use super::super::agents::{AgentThread, MetaFile, Spawn, attach, load_agents};
use super::super::head::RecordId;
use super::super::load::Heads;
use super::super::plan::{PAGE_BUDGET, PageKind, PagePlan, Part, Summary, pack, plan, write_dump};
use super::super::tree::{
    Answer, Exchange, FileRole, Group, Item, Link, LinkCounts, OwnerForm, ToolRun, Tree, Turn,
    topological_order,
};
use super::{ORDER, UNKNOWN, discover, fixture_projects, id, load};

const GAMMA_A: &[u8] =
    include_bytes!("../../tests/fixtures/projects/-home-alpha-dev-gamma/SESSION-ID-A.jsonl");

struct Gamma {
    heads: Heads,
    agents: Vec<AgentThread>,
    tree: Tree,
}

fn gamma() -> Gamma {
    let source = discover(&fixture_projects().join("-home-alpha-dev-gamma"));
    let heads = Heads::load(&source).expect("load");
    let (mut agents, _) = load_agents(&source.agents).expect("agents");
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    Gamma {
        heads,
        agents,
        tree,
    }
}

fn node(heads: &Heads, number: u64) -> usize {
    heads.index[&id(number)] as usize
}

fn ids(heads: &Heads, nodes: &[usize]) -> Vec<RecordId> {
    nodes.iter().map(|&node| heads.nodes[node].id).collect()
}

/// ´test:crate:every-link-rule-places-its-nodes´
#[test]
fn every_link_rule_places_its_nodes() {
    let Gamma { heads, tree, .. } = gamma();
    let links = &tree.links;
    assert_eq!(
        links.counts,
        LinkCounts {
            parent: 26,
            logical_parent: 1,
            preserved_tail: 1,
            previous_record: 1,
            roots: 2,
            dangling: 0,
        }
    );
    assert_eq!(links.missing_logical_parents, 2);
    for (child, parent, rule) in [
        (0x514, 0x513, Link::LogicalParent),
        (0x517, 0x516, Link::PreservedTail),
        (0x520, 0x519, Link::PreviousRecord),
        (0x5b1, 0x505, Link::Parent),
        (0x5d1, 0x525, Link::Parent),
    ] {
        let child = node(&heads, child);
        assert_eq!(links.parent[child], Some(node(&heads, parent)));
        assert_eq!(links.rule[child], rule);
    }
    assert_eq!(links.rule[node(&heads, 0x501)], Link::Root);
}

/// ´test:crate:a-dangling-parent-and-a-bare-boundary-start-conversations´
#[test]
fn a_dangling_parent_and_a_bare_boundary_start_conversations() {
    let text = [
        format!(r#"{{"type":"system","subtype":"compact_boundary","uuid":"{}","timestamp":"2026-03-01T00:00:00Z"}}"#, id(0x601)),
        format!(r#"{{"type":"user","uuid":"{}","parentUuid":"{}","timestamp":"2026-03-01T00:00:01Z","message":{{"content":"Words."}}}}"#, id(0x602), id(0x6ff)),
        format!(r#"{{"type":"assistant","uuid":"{}","parentUuid":"{}","timestamp":"2026-03-01T00:00:02Z","message":{{"content":[{{"type":"text","text":"Yes."}}]}}}}"#, id(0x603), id(0x602)),
    ]
    .join("\n");
    let heads = load(&[("SESSION-ID-F", text.as_bytes())]);
    let tree = Tree::build(&heads);
    assert_eq!(tree.links.rule, [Link::Root, Link::Dangling, Link::Parent]);
    assert_eq!(tree.links.missing_logical_parents, 1);
    assert_eq!(tree.conversations.len(), 2);
    assert_eq!(
        ids(&heads, &tree.conversations[1].main),
        [id(0x602), id(0x603)]
    );
}

/// ´test:crate:records-written-before-their-parent-are-held-back´
#[test]
fn records_written_before_their_parent_are_held_back() {
    let heads = load(&[("SESSION-ID-ORDER", ORDER)]);
    let tree = Tree::build(&heads);
    assert_eq!(tree.held_back, 1);
    assert_eq!(
        ids(&heads, &tree.conversations[0].main),
        [id(0x201), id(0x203), id(0x202), id(0x204)]
    );
    let (order, held_back) = topological_order(&[Some(2), Some(0), None, Some(1)]);
    assert_eq!((order, held_back), (vec![2, 0, 1, 3], 2));
    let (order, held_back) = topological_order(&[Some(3), Some(3), Some(0), None]);
    assert_eq!((order, held_back), (vec![3, 0, 1, 2], 3));
    let (order, held_back) = topological_order(&[None, Some(0), None, Some(2)]);
    assert_eq!((order, held_back), (vec![0, 1, 2, 3], 0));
    let (order, _) = topological_order(&[Some(1), Some(0), None]);
    assert_eq!(order, [2, 0, 1]);
}

/// ´test:crate:session-files-are-spine-branch-or-copy´
#[test]
fn session_files_are_spine_branch_or_copy() {
    let Gamma { heads, tree, .. } = gamma();
    let stems: Vec<_> = heads.files.iter().map(|file| file.stem.as_str()).collect();
    assert_eq!(
        stems,
        [
            "SESSION-ID-A",
            "SESSION-ID-B",
            "SESSION-ID-C",
            "SESSION-ID-D",
            "SESSION-ID-E"
        ]
    );
    let roles: Vec<_> = tree.conversations[0]
        .files
        .iter()
        .map(|view| (view.file, view.role, view.own))
        .collect();
    assert_eq!(
        roles,
        [
            (0, FileRole::Spine, 25),
            (
                1,
                FileRole::Branch {
                    fork: Some(node(&heads, 0x505))
                },
                2
            ),
            (2, FileRole::Copy, 0),
            (3, FileRole::Spine, 2),
        ]
    );
    let branch = &tree.conversations[0].branches[0];
    assert_eq!(ids(&heads, &branch.nodes), [id(0x5b1), id(0x5b2)]);
    assert_eq!(branch.fork, Some(node(&heads, 0x505)));
    let second: Vec<_> = tree.conversations[1]
        .files
        .iter()
        .map(|view| (view.file, view.role))
        .collect();
    assert_eq!(second, [(4, FileRole::Spine)]);
}

/// ´test:crate:conversations-are-components-in-first-timestamp-order´
#[test]
fn conversations_are_components_in_first_timestamp_order() {
    let Gamma { heads, tree, .. } = gamma();
    assert_eq!(tree.conversations.len(), 2);
    let first = &tree.conversations[0].main;
    assert_eq!(first.len(), 27);
    assert_eq!(heads.nodes[first[0]].id, id(0x501));
    assert_eq!(*first.last().expect("records"), node(&heads, 0x5d2));
    assert_eq!(
        ids(&heads, &tree.conversations[1].main),
        [id(0x5e1), id(0x5e2)]
    );
    let unknown = load(&[("SESSION-ID-UNKNOWN", UNKNOWN)]);
    let tree = Tree::build(&unknown);
    let mains: Vec<_> = tree
        .conversations
        .iter()
        .map(|conversation| ids(&unknown, &conversation.main))
        .collect();
    assert_eq!(
        mains,
        [
            vec![id(0x301), id(0x302), id(0x303), id(0x3ab)],
            vec![id(0x307)]
        ]
    );
}

/// ´test:crate:segments-cut-at-each-boundary-in-write-order´
#[test]
fn segments_cut_at_each_boundary_in_write_order() {
    let Gamma { heads, tree, .. } = gamma();
    let segments = &tree.conversations[0].segments;
    let cuts: Vec<_> = segments
        .iter()
        .map(|segment| (segment.positions.clone(), segment.boundary))
        .collect();
    assert_eq!(
        cuts,
        [
            (0..13, None),
            (13..16, Some(node(&heads, 0x514))),
            (16..19, Some(node(&heads, 0x517))),
            (19..27, Some(node(&heads, 0x520))),
        ]
    );
    let compactions: Vec<_> = segments
        .iter()
        .map(|segment| {
            segment.compaction.as_ref().map(|compaction| {
                (
                    compaction.trigger.clone(),
                    compaction.pre_tokens,
                    compaction.post_tokens,
                    compaction.duration_ms,
                )
            })
        })
        .collect();
    assert_eq!(
        compactions,
        [
            None,
            Some((Some("manual".to_owned()), Some(1200), Some(300), Some(4500))),
            Some((Some("auto".to_owned()), Some(180_000), None, None)),
            Some((Some("manual".to_owned()), None, None, None)),
        ]
    );
}

/// ´test:crate:turns-open-at-typed-and-queued-prompts´
#[test]
fn turns_open_at_typed_and_queued_prompts() {
    let Gamma { heads, tree, .. } = gamma();
    let conversation = &tree.conversations[0];
    let owners: Vec<_> = conversation
        .turns
        .iter()
        .map(|turn| turn.owner.map(|owner| heads.nodes[owner].id))
        .collect();
    assert_eq!(
        owners,
        [
            Some(id(0x501)),
            None,
            Some(id(0x516)),
            None,
            Some(id(0x519)),
            None,
            Some(id(0x524)),
            Some(id(0x5d1)),
        ]
    );
    let segment_turns: Vec<_> = conversation
        .segments
        .iter()
        .map(|segment| segment.turns.clone())
        .collect();
    assert_eq!(segment_turns, [0..1, 1..3, 3..5, 5..8]);
    let bytes: u64 = conversation.turns.iter().map(|turn| turn.bytes).sum();
    let expected: u64 = conversation
        .main
        .iter()
        .map(|&node| u64::from(heads.nodes[node].loc.len))
        .sum();
    assert_eq!(bytes, expected);
    assert_eq!(
        conversation.branches[0].turns[0].owner,
        Some(node(&heads, 0x5b1))
    );
}

/// ´test:crate:items-group-responses-runs-exchanges-and-notes´
#[test]
fn items_group_responses_runs_exchanges_and_notes() {
    let Gamma { heads, tree, .. } = gamma();
    let n = |number| node(&heads, number);
    let exchange = |call: u64, call_id: &str, result: Option<u64>| Exchange {
        call: n(call),
        block: 0,
        call_id: Some(call_id.into()),
        result: result.map(|result| Answer {
            record: n(result),
            block: 0,
        }),
    };
    let turns = &tree.conversations[0].turns;
    assert_eq!(
        turns[0].items,
        [
            Item::Owner {
                node: n(0x501),
                form: OwnerForm::Typed
            },
            Item::Response {
                nodes: vec![n(0x502), n(0x503)]
            },
            Item::ToolRun(ToolRun {
                groups: vec![
                    Group {
                        exchanges: vec![
                            exchange(0x504, "TOOL-USE-ID-T1", Some(0x506)),
                            exchange(0x505, "TOOL-USE-ID-T2", Some(0x507)),
                        ]
                    },
                    Group {
                        exchanges: vec![exchange(0x508, "TOOL-USE-ID-T3", Some(0x509))]
                    },
                ],
                notes: vec![],
            }),
            Item::Response {
                nodes: vec![n(0x510)]
            },
            Item::ToolRun(ToolRun {
                groups: vec![Group {
                    exchanges: vec![exchange(0x512, "TOOL-USE-ID-T4", None)]
                }],
                notes: vec![n(0x511)],
            }),
            Item::Owner {
                node: n(0x513),
                form: OwnerForm::Command
            },
        ]
    );
    assert_eq!(
        turns[1].items,
        [Item::Compaction {
            boundary: Some(n(0x514)),
            summary: Some(n(0x515))
        }]
    );
    assert_eq!(
        turns[5].items,
        [
            Item::Compaction {
                boundary: Some(n(0x520)),
                summary: Some(n(0x521))
            },
            Item::Response {
                nodes: vec![n(0x522)]
            },
            Item::Peer(n(0x523)),
        ]
    );
    assert_eq!(
        turns[6].items,
        [
            Item::Owner {
                node: n(0x524),
                form: OwnerForm::Queued
            },
            Item::Response {
                nodes: vec![n(0x525)]
            },
        ]
    );
}

/// ´test:crate:agents-attach-to-main-calls-and-to-their-parent-thread´
#[test]
fn agents_attach_to_main_calls_and_to_their_parent_thread() {
    let Gamma { heads, agents, .. } = gamma();
    let found: Vec<_> = agents
        .iter()
        .map(|agent| {
            (
                agent.id.as_str(),
                agent.spawn,
                agent.meta_file,
                agent.heads.nodes.len(),
            )
        })
        .collect();
    let nested_call = agents[0]
        .heads
        .nodes
        .iter()
        .position(|head| {
            head.calls
                .iter()
                .any(|call| call.as_deref() == Some("TOOL-USE-ID-T5"))
        })
        .expect("the nested call");
    assert_eq!(
        found,
        [
            (
                "0123456789abcdef0",
                Spawn::Main {
                    node: node(&heads, 0x508)
                },
                MetaFile::Read,
                4
            ),
            (
                "0123456789abcdef1",
                Spawn::Agent {
                    parent: 0,
                    node: nested_call
                },
                MetaFile::Read,
                2
            ),
            ("0123456789abcdef2", Spawn::Unattached, MetaFile::Absent, 1),
        ]
    );
    assert_eq!(
        agents[1].meta.parent_agent_id.as_deref(),
        Some("0123456789abcdef0")
    );
    assert_eq!(agents[1].meta.spawn_depth, Some(2));
}

/// Turns of the given numbers of records, laid end to end.
fn turns(records: &[usize]) -> Vec<Turn> {
    let mut start = 0;
    records
        .iter()
        .map(|&count| {
            let turn = Turn {
                positions: start..start + count,
                owner: None,
                items: Vec::new(),
                bytes: 0,
                slots: Vec::new(),
            };
            start += count;
            turn
        })
        .collect()
}

const fn part(turns: std::ops::Range<usize>, positions: std::ops::Range<usize>) -> Part {
    Part { turns, positions }
}

/// ´test:crate:pages-take-whole-turns-until-the-budget-and-cut-a-turn-at-the-limit´
#[test]
fn pages_take_whole_turns_until_the_budget_and_cut_a_turn_at_the_limit() {
    let one = |_| 1;
    assert_eq!(
        pack(&turns(&[3, 3, 3]), &one, 5, 10),
        [part(0..2, 0..6), part(2..3, 6..9)]
    );
    assert_eq!(pack(&turns(&[1, 1, 1]), &one, 5, 10), [part(0..3, 0..3)]);
    assert_eq!(
        pack(&turns(&[12, 1]), &one, 5, 10),
        [part(0..1, 0..10), part(0..2, 10..13)]
    );
    let sizes = |position: usize| [1, 20, 1][position];
    assert_eq!(
        pack(&turns(&[3]), &sizes, 5, 10),
        [part(0..1, 0..1), part(0..1, 1..2), part(0..1, 2..3)]
    );
    assert_eq!(pack(&turns(&[]), &one, 5, 10), Vec::<Part>::new());
    let Gamma { heads, tree, .. } = gamma();
    let pages = plan(&heads, &tree, &[], 1);
    let main: Vec<&PagePlan> = pages
        .iter()
        .filter(|page| page.kind == PageKind::Main && page.conversation == Some(0))
        .collect();
    assert_eq!(main.len(), tree.conversations[0].main.len());
    for page in main {
        assert_eq!(page.positions.len(), 1, "{}", page.path);
    }
}

/// ´test:crate:appended-records-only-extend-the-last-page´
#[test]
fn appended_records_only_extend_the_last_page() {
    let lines: Vec<&[u8]> = GAMMA_A.split_inclusive(|&byte| byte == b'\n').collect();
    for budget in [1, 2_000, PAGE_BUDGET] {
        let full_heads = load(&[("SESSION-ID-A", GAMMA_A)]);
        let full = plan(&full_heads, &Tree::build(&full_heads), &[], budget);
        for cut in 1..lines.len() {
            let prefix = lines[..cut].concat();
            let heads = load(&[("SESSION-ID-A", &prefix)]);
            let pages: Vec<PagePlan> = plan(&heads, &Tree::build(&heads), &[], budget);
            let (last, settled) = pages.split_last().expect("a page");
            assert_eq!(settled, &full[..settled.len()], "budget {budget} cut {cut}");
            let grown = &full[settled.len()];
            assert_eq!(
                (&last.path, last.positions.start, last.turns.start),
                (&grown.path, grown.positions.start, grown.turns.start),
                "budget {budget} cut {cut}"
            );
            assert!(last.positions.end <= grown.positions.end);
        }
    }
}

/// ´test:crate:the-plan-covers-every-record-once´
#[test]
fn the_plan_covers_every_record_once() {
    let Gamma {
        heads,
        agents,
        tree,
    } = gamma();
    let pages = plan(&heads, &tree, &agents, PAGE_BUDGET);
    let paths: Vec<_> = pages.iter().map(|page| page.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "p0001.html",
            "p0002.html",
            "p0003.html",
            "p0004.html",
            "branches/SESSION-ID-B-01.html",
            "c2/p0001.html",
            "agents/0123456789abcdef0-01.html",
            "agents/0123456789abcdef1-01.html",
            "agents/0123456789abcdef2-01.html",
        ]
    );
    let mut seen: BTreeMap<usize, usize> = BTreeMap::new();
    for page in &pages {
        let sequence = match (page.kind, page.conversation, page.branch) {
            (PageKind::Main, Some(conversation), None) => &tree.conversations[conversation].main,
            (PageKind::Branch, Some(conversation), Some(branch)) => {
                &tree.conversations[conversation].branches[branch].nodes
            }
            _ => continue,
        };
        for &node in &sequence[page.positions.clone()] {
            *seen.entry(node).or_default() += 1;
        }
    }
    assert_eq!(seen.len(), heads.nodes.len());
    assert!(seen.values().all(|&count| count == 1));
    let mut digests: Vec<_> = pages.iter().map(|page| page.digest).collect();
    digests.sort_unstable();
    digests.dedup();
    assert_eq!(digests.len(), pages.len());
}

/// ´test:crate:the-summary-and-the-dump-report-the-tree´
#[test]
fn the_summary_and_the_dump_report_the_tree() {
    let Gamma {
        heads,
        agents,
        tree,
    } = gamma();
    let pages = plan(&heads, &tree, &agents, PAGE_BUDGET);
    assert_eq!(
        Summary::of(&heads, &tree, &agents, &pages).to_string(),
        "conversations=2 segments=5 turns=10 prompts=7 pages=9 branches=1 agents=3 agents_nested=1 agents_unattached=1 held_back=0 missing_logical_parents=2 links=parent:26,logical:1,tail:1,previous:1,root:2,dangling:0 exchanges=4 groups=3 unanswered=1"
    );
    let mut dump = Vec::new();
    write_dump(&mut dump, &heads, &tree, &agents, &pages).expect("dump");
    let lines: Vec<serde_json::Value> = String::from_utf8(dump)
        .expect("UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON line"))
        .collect();
    assert_eq!(lines.len(), 9);
    let listed = |kind: &str| -> usize {
        lines
            .iter()
            .filter(|line| line["kind"] != kind)
            .map(|line| line["nodes"].as_array().map_or(0, Vec::len))
            .sum()
    };
    assert_eq!(listed("agent"), heads.nodes.len());
    let agent_records: usize = agents.iter().map(|agent| agent.heads.nodes.len()).sum();
    assert_eq!(listed("") - listed("agent"), agent_records);
    assert_eq!(lines[0]["nodes"][0][0], id(0x501).to_string());
    assert_eq!(lines[0]["nodes"][0][1], serde_json::Value::Null);
    assert_eq!(lines[0]["nodes"][1][1], id(0x501).to_string());
    assert_eq!(lines[7]["agent"], "0123456789abcdef1");
    assert_eq!(lines[7]["spawn"], "agent");
    assert_eq!(lines[7]["records"], 2);
    assert_eq!(lines[7]["nodes"].as_array().map_or(0, Vec::len), 2);
}
