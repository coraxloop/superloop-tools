use std::collections::{HashMap, HashSet};

use petgraph::algo::has_path_connecting;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef as _;
use superloop_claude_hook::heartbeat::{Effect, Guard, State, heartbeat_graph};

type Graph = petgraph::graph::DiGraph<State, superloop_claude_hook::heartbeat::Transition>;

fn nodes() -> (Graph, HashMap<State, NodeIndex>) {
    let graph = heartbeat_graph();
    let indexes = graph
        .node_indices()
        .map(|index| (graph[index], index))
        .collect();
    (graph, indexes)
}

/// ´test:integration:every-declared-state-occurs-once-and-is-reachable´
#[test]
fn every_declared_state_occurs_once_and_is_reachable() {
    let (graph, indexes) = nodes();
    assert_eq!(graph.node_count(), State::ALL.len());
    assert_eq!(indexes.len(), State::ALL.len());
    for state in State::ALL {
        assert!(indexes.contains_key(&state), "missing state {state:?}");
        assert!(
            has_path_connecting(&graph, indexes[&State::Entry], indexes[&state], None),
            "unreachable state {state:?}"
        );
    }
}

/// ´test:integration:all-sixteen-verdict-paths-are-explicit-terminal-nodes´
#[test]
fn all_sixteen_verdict_paths_are_explicit_terminal_nodes() {
    let (graph, indexes) = nodes();
    assert_eq!(State::VERDICTS.len(), 16);
    for verdict in State::VERDICTS {
        assert!(verdict.is_terminal());
        assert_eq!(graph.edges(indexes[&verdict]).count(), 0);
    }
    assert_eq!(
        State::ALL
            .into_iter()
            .filter(|state| state.is_terminal())
            .collect::<HashSet<_>>(),
        State::VERDICTS.into_iter().collect()
    );
}

/// ´test:integration:resolution-is-total-over-the-six-configuration-classes´
#[test]
fn resolution_is_total_over_the_six_configuration_classes() {
    let (graph, indexes) = nodes();
    let guards = graph
        .edges(indexes[&State::Resolve])
        .map(|edge| edge.weight().guard)
        .collect::<HashSet<_>>();
    assert_eq!(
        guards,
        HashSet::from([
            Guard::InternalError,
            Guard::Armed,
            Guard::Prompt,
            Guard::Lapse,
            Guard::UnpromptedArmed,
            Guard::UnpromptedPrompt,
            Guard::UnpromptedLapse,
        ])
    );
}

/// ´test:integration:warning-phases-are-graph-edges-not-hidden-switches´
#[test]
fn warning_phases_are_graph_edges_not_hidden_switches() {
    let (graph, indexes) = nodes();
    for state in [
        State::ExceptionUnpromptedArmed,
        State::ExceptionUnpromptedUnarmed,
        State::ExceptionUnpromptedLapse,
    ] {
        let guards = graph
            .edges(indexes[&state])
            .map(|edge| edge.weight().guard)
            .collect::<HashSet<_>>();
        assert_eq!(
            guards,
            HashSet::from([
                Guard::InternalError,
                Guard::WarningFresh,
                Guard::WarningRecorded,
            ])
        );
    }
}

/// ´test:integration:every-prompting-verdict-records-the-prompt-marker´
#[test]
fn every_prompting_verdict_records_the_prompt_marker() {
    let (graph, indexes) = nodes();
    for verdict in [State::ComposePrompt, State::ComposeViolationAndPrompt] {
        for edge in graph.edges_directed(indexes[&verdict], petgraph::Direction::Incoming) {
            assert!(
                edge.weight().effects.contains(&Effect::RecordPromptMarker),
                "prompt edge from {:?} omits its prompt marker",
                graph[edge.source()]
            );
        }
    }
}

/// ´test:integration:every-nonterminal-has-an-outgoing-edge-and-every-edge-has-a-named-guard´
#[test]
fn every_nonterminal_has_an_outgoing_edge_and_every_edge_has_a_named_guard() {
    let graph = heartbeat_graph();
    for index in graph.node_indices() {
        let state = graph[index];
        if !state.is_terminal() {
            assert!(
                graph.edges(index).next().is_some(),
                "no edge from {state:?}"
            );
        }
    }
    assert!(graph.edge_weights().all(|edge| matches!(
        edge.guard,
        Guard::Malformed
            | Guard::LettersEmpty
            | Guard::LettersUnread
            | Guard::LettersFailed
            | Guard::NoLettersFeedback
            | Guard::LettersMayBlock
            | Guard::LettersNotify
            | Guard::Accepted
            | Guard::InternalError
            | Guard::FlagAbsent
            | Guard::FlagPresent
            | Guard::RetryNeeded
            | Guard::TranscriptReady
            | Guard::Armed
            | Guard::Prompt
            | Guard::Lapse
            | Guard::UnpromptedArmed
            | Guard::UnpromptedPrompt
            | Guard::UnpromptedLapse
            | Guard::WarningFresh
            | Guard::WarningRecorded
            | Guard::Always
    )));
}

/// ´test:integration:letters-branches-rejoin-the-unchanged-heartbeat-decision´
#[test]
fn letters_branches_rejoin_the_unchanged_heartbeat_decision() {
    let (graph, indexes) = nodes();
    assert_eq!(graph.edges(indexes[&State::Letters]).count(), 3);
    for state in [
        State::LettersEmpty,
        State::LettersUnread,
        State::LettersFailed,
    ] {
        let edges = graph.edges(indexes[&state]).collect::<Vec<_>>();
        assert_eq!(edges.len(), 1);
        assert_eq!(graph[edges[0].target()], State::Toggle);
        assert_eq!(edges[0].weight().effects, []);
    }
}

/// ´test:integration:composition-lapse-has-no-letters-block-edge-and-blocks-record-count´
#[test]
fn composition_lapse_has_no_letters_block_edge_and_blocks_record_count() {
    let (graph, indexes) = nodes();
    for state in [State::ComposeLapse, State::ComposeLapseAndViolation] {
        assert!(
            graph
                .edges(indexes[&state])
                .all(|edge| edge.weight().guard != Guard::LettersMayBlock)
        );
    }
    for state in [
        State::ComposeSilent,
        State::ComposePrompt,
        State::ComposeViolation,
        State::ComposeViolationAndPrompt,
    ] {
        let edges = graph
            .edges(indexes[&state])
            .filter(|edge| edge.weight().guard == Guard::LettersMayBlock)
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].weight().effects, [Effect::RecordLettersCount]);
        assert!(graph[edges[0].target()].is_terminal());
    }
}
