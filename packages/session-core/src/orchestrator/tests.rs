use std::collections::HashSet;
use std::time::Instant;

use petgraph::Direction;
use petgraph::visit::{Dfs, EdgeRef as _};
use serde_json::{Map, Value};

use super::{
    Context, Effect, EventClass, Guard, SessionInput, State, Transition, injection_graph,
    marker_text, prompt_ids, safe_session_id,
};
use crate::sha256::digest_hex;

/// ´test:unit:graph-is-the-direct-petgraph-type-required-by-the-specification´
#[test]
fn graph_is_the_direct_petgraph_type_required_by_the_specification() {
    let graph: petgraph::graph::DiGraph<State, Transition> = injection_graph();
    assert_eq!(graph.node_count(), State::ALL.len());
    assert!(graph.edge_count() > graph.node_count());
}

/// ´test:unit:every-spec-named-state-is-present-once´
#[test]
fn every_spec_named_state_is_present_once() {
    let graph = injection_graph();
    let actual = graph.node_weights().copied().collect::<HashSet<_>>();
    let expected = State::ALL.into_iter().collect::<HashSet<_>>();

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), graph.node_count());
}

/// ´test:unit:every-spec-named-state-is-reachable-from-entry´
#[test]
fn every_spec_named_state_is_reachable_from_entry() {
    let graph = injection_graph();
    let entry = graph
        .node_indices()
        .find(|index| graph[*index] == State::Entry)
        .expect("entry node");
    let mut depth_first = Dfs::new(&graph, entry);
    let mut reached = HashSet::new();
    while let Some(index) = depth_first.next(&graph) {
        reached.insert(graph[index]);
    }

    assert_eq!(reached, State::ALL.into_iter().collect());
}

/// ´test:unit:every-nonterminal-state-has-total-event-class-edge-coverage´
#[test]
fn every_nonterminal_state_has_total_event_class_edge_coverage() {
    let graph = injection_graph();
    for index in graph.node_indices() {
        let state = graph[index];
        let outgoing = graph
            .edges_directed(index, Direction::Outgoing)
            .map(|edge| edge.weight())
            .collect::<Vec<_>>();
        if state.is_terminal() {
            assert!(outgoing.is_empty(), "terminal {state:?}");
            continue;
        }
        assert!(!outgoing.is_empty(), "state {state:?}");
        for event in EventClass::ALL {
            assert!(
                outgoing.iter().any(|edge| edge.covers(event)),
                "state {state:?} lacks {event:?} edge coverage"
            );
        }
    }
}

/// ´test:unit:each-fallible-state-has-an-explicit-internal-error-edge´
#[test]
fn each_fallible_state_has_an_explicit_internal_error_edge() {
    let graph = injection_graph();
    for index in graph.node_indices() {
        let state = graph[index];
        if state.is_terminal()
            || matches!(
                state,
                State::Entry | State::FailOpen | State::LogClassIfPossible
            )
        {
            continue;
        }
        let internal = graph
            .edges(index)
            .filter(|edge| edge.weight().guard == Guard::InternalError)
            .collect::<Vec<_>>();
        assert_eq!(internal.len(), 1, "state {state:?}");
        assert_eq!(graph[internal[0].target()], State::FailOpen);
    }
}

/// ´test:unit:effect-edges-preserve-full-and-notice-persistence-order´
#[test]
fn effect_edges_preserve_full_and_notice_persistence_order() {
    let graph = injection_graph();
    let edges = graph
        .edge_references()
        .map(|edge| {
            (
                graph[edge.source()],
                graph[edge.target()],
                edge.weight().effects,
            )
        })
        .collect::<Vec<_>>();

    assert!(edges.contains(&(
        State::Fresh,
        State::InjectFull,
        &[Effect::PrepareFull] as &[Effect]
    )));
    assert!(edges.contains(&(
        State::Rotate,
        State::Snapshot,
        &[Effect::RotateSnapshot] as &[Effect]
    )));
    assert!(edges.contains(&(
        State::Snapshot,
        State::StateWrite,
        &[Effect::WriteSnapshot] as &[Effect]
    )));
    assert!(edges.contains(&(
        State::StateWrite,
        State::Notice,
        &[Effect::WriteState] as &[Effect]
    )));
    assert!(edges.contains(&(
        State::Log,
        State::AllowContext,
        &[Effect::AppendPlannedLog] as &[Effect]
    )));
}

/// ´test:unit:sha256-matches-standard-short-and-multiblock-vectors´
#[test]
fn sha256_matches_standard_short_and_multiblock_vectors() {
    assert_eq!(
        digest_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        digest_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        digest_hex(&vec![b'a'; 1_000]),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    );
}

/// ´test:unit:marker-inserts-exactly-one-line-feed-before-end-sentinel´
#[test]
fn marker_inserts_exactly_one_line_feed_before_end_sentinel() {
    let without_lf = marker_text("digest", 17, "rules");
    let with_lf = marker_text("digest", 17, "rules\n");

    assert_eq!(
        without_lf,
        "ORCHESTRATION_SCOPE_MARKER v1 sha256=digest mtime=17\nrules\nORCHESTRATION_SCOPE_MARKER_END v1 sha256=digest"
    );
    assert_eq!(without_lf, with_lf);
}

/// ´test:unit:session-keys-preserve-compatible-partitioning´
#[test]
fn session_keys_preserve_compatible_partitioning() {
    assert_eq!(safe_session_id(""), "unknown");
    assert_eq!(safe_session_id("one/two"), "one-two");
    assert_eq!(safe_session_id("one\0two"), "one-two");
    assert_eq!(safe_session_id("ordinary id"), "ordinary id");
}

/// ´test:unit:prompt-history-moves-hits-to-newest-and-evicts-to-sixty-four´
#[test]
fn prompt_history_moves_hits_to_newest_and_evicts_to_sixty_four() {
    let mut context = Context::from_input(
        &SessionInput {
            event_class: EventClass::Tracked,
            prompt_id: Some(String::from("prompt-64")),
            ..SessionInput::default()
        },
        Instant::now(),
        |_, _| false,
    );
    context.state = Map::from_iter([(
        String::from("emitted_prompt_ids"),
        Value::Array(
            (0..64)
                .map(|index| Value::String(format!("prompt-{index}")))
                .collect(),
        ),
    )]);

    context.record_prompt();

    let ids = prompt_ids(&context.state);
    assert_eq!(ids.len(), 64);
    assert_eq!(ids.first().map(String::as_str), Some("prompt-1"));
    assert_eq!(ids.last().map(String::as_str), Some("prompt-64"));
}

/// ´test:unit:prompt-history-ignores-empty-and-nonstring-identities´
#[test]
fn prompt_history_ignores_empty_and_nonstring_identities() {
    for prompt_id in [Some(String::new()), None] {
        let mut context = Context::from_input(
            &SessionInput {
                event_class: EventClass::Tracked,
                prompt_id,
                ..SessionInput::default()
            },
            Instant::now(),
            |_, _| false,
        );
        context.record_prompt();
        assert_eq!(prompt_ids(&context.state), [] as [String; 0]);
    }
}
