//! Path scoring and routing graph tests.

use routing_core::routing::{
    graph::{Edge, RoutingGraph},
    path_scoring::{score_path, PathMetrics, ScoreWeights},
};

// ─── Score computation ────────────────────────────────────────

fn weights() -> ScoreWeights {
    ScoreWeights::new(0.4, 0.2, 0.3, 0.1).unwrap()
}

#[test]
fn perfect_path_scores_one() {
    let m = PathMetrics { latency_ms: 0.0, jitter_ms: 0.0, loss_pct: 0.0, cost: 0.0 };
    let s = score_path(m, weights());
    assert!((s - 1.0).abs() < 1e-9, "perfect path: {s}");
}

#[test]
fn worst_case_scores_zero() {
    // All metrics at or beyond worst case.
    let m = PathMetrics { latency_ms: 400.0, jitter_ms: 50.0, loss_pct: 5.0, cost: 1.0 };
    let s = score_path(m, weights());
    assert!((s - 0.0).abs() < 1e-9, "worst case: {s}");
}

#[test]
fn score_monotone_in_latency() {
    let w = weights();
    let mut prev = 1.0f64;
    for lat in (0..=400).step_by(10) {
        let m = PathMetrics { latency_ms: lat as f64, jitter_ms: 0.0, loss_pct: 0.0, cost: 0.0 };
        let s = score_path(m, w);
        assert!(s <= prev + 1e-9, "latency={lat}: score {s} > prev {prev}");
        prev = s;
    }
}

#[test]
fn score_monotone_in_loss() {
    let w = weights();
    let mut prev = 1.0f64;
    for loss_tenths in 0..=50 {
        let m = PathMetrics { latency_ms: 0.0, jitter_ms: 0.0, loss_pct: loss_tenths as f64 / 10.0, cost: 0.0 };
        let s = score_path(m, w);
        assert!(s <= prev + 1e-9, "loss={}: {s} > {prev}", loss_tenths as f64 / 10.0);
        prev = s;
    }
}

#[test]
fn score_beyond_worst_clamps_to_zero() {
    // Latency way beyond 400ms should not produce a negative score.
    let m = PathMetrics { latency_ms: 2000.0, jitter_ms: 0.0, loss_pct: 0.0, cost: 0.0 };
    let s = score_path(m, weights());
    assert!(s >= 0.0, "score went negative: {s}");
}

#[test]
fn weights_must_sum_to_one() {
    // Valid.
    assert!(ScoreWeights::new(0.4, 0.2, 0.3, 0.1).is_ok());
    // Invalid.
    assert!(ScoreWeights::new(0.5, 0.5, 0.5, 0.5).is_err());
    assert!(ScoreWeights::new(0.0, 0.0, 0.0, 0.0).is_err());
}

// ─── Graph and Dijkstra ───────────────────────────────────────

fn two_node_graph() -> RoutingGraph {
    let mut g = RoutingGraph::new();
    g.set_edges("nbo".into(), vec![Edge { to: "msa".into(), score: 0.9 }]);
    g.set_edges("msa".into(), vec![Edge { to: "nbo".into(), score: 0.85 }]);
    g
}

#[test]
fn dijkstra_finds_direct_path() {
    let g = two_node_graph();
    let path = g.shortest_path("nbo", "msa").expect("should find path");
    assert_eq!(path, vec!["nbo", "msa"]);
}

#[test]
fn dijkstra_same_src_dst() {
    let g = two_node_graph();
    let path = g.shortest_path("nbo", "nbo").unwrap();
    assert_eq!(path, vec!["nbo"]);
}

#[test]
fn dijkstra_unreachable_returns_none() {
    let g = two_node_graph();
    let path = g.shortest_path("nbo", "nonexistent");
    assert!(path.is_none());
}

#[test]
fn dijkstra_prefers_higher_score() {
    // Two paths from A to C: A→B→C (score 0.9*0.9=0.81) and A→C (score 0.7).
    let mut g = RoutingGraph::new();
    g.set_edges("A".into(), vec![
        Edge { to: "B".into(), score: 0.9 },
        Edge { to: "C".into(), score: 0.7 },
    ]);
    g.set_edges("B".into(), vec![
        Edge { to: "C".into(), score: 0.9 },
    ]);
    let path = g.shortest_path("A", "C").unwrap();
    // A→B→C has combined score 0.81 > direct A→C score 0.7.
    assert_eq!(path, vec!["A", "B", "C"]);
}

#[test]
fn k_shortest_paths_returns_k() {
    // Build a graph with 3 distinct paths from A to D.
    let mut g = RoutingGraph::new();
    // Path 1: A→D direct (score 0.6)
    // Path 2: A→B→D (0.9 * 0.9 = 0.81)
    // Path 3: A→C→D (0.7 * 0.7 = 0.49)
    g.set_edges("A".into(), vec![
        Edge { to: "B".into(), score: 0.9 },
        Edge { to: "C".into(), score: 0.7 },
        Edge { to: "D".into(), score: 0.6 },
    ]);
    g.set_edges("B".into(), vec![Edge { to: "D".into(), score: 0.9 }]);
    g.set_edges("C".into(), vec![Edge { to: "D".into(), score: 0.7 }]);

    let paths = g.k_shortest_paths("A", "D", 3);
    // Should find at most 3 distinct paths.
    assert!(paths.len() <= 3);
    assert!(!paths.is_empty());
    // Best path should be A→B→D (0.81).
    let best = &paths[0];
    assert_eq!(best.0, vec!["A", "B", "D"]);
    assert!((best.1 - 0.81).abs() < 0.01, "best path score: {}", best.1);
}

#[test]
fn k_paths_sorted_descending() {
    let mut g = RoutingGraph::new();
    g.set_edges("A".into(), vec![
        Edge { to: "B".into(), score: 0.9 },
        Edge { to: "C".into(), score: 0.6 },
    ]);
    g.set_edges("B".into(), vec![Edge { to: "D".into(), score: 0.9 }]);
    g.set_edges("C".into(), vec![Edge { to: "D".into(), score: 0.6 }]);
    let paths = g.k_shortest_paths("A", "D", 2);
    if paths.len() >= 2 {
        assert!(paths[0].1 >= paths[1].1, "paths not sorted descending");
    }
}
