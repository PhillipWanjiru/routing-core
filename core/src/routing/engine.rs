//! The routing engine.
//!
//! Accepts `RouteRequest` messages from the IPC bus (via the B2BUA),
//! applies Erlang B admission control, scores paths using the link-state
//! database, and returns an ordered list of `RouteResult` candidates.
//!
//! The engine runs a recompute loop every `Config.routing.recompute_interval_s`
//! seconds, rebuilding the `RoutingGraph` from the `LinkStateDb` so that
//! Yen's k-shortest-paths precomputation is always fresh.

use crate::routing::{
    erlang::{erlang_b, erlang_b_inverse},
    graph::{Edge, NodeId, RoutingGraph},
    link_state::LinkStateDb,
    path_scoring::{score_path, ScoreWeights},
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::time;

/// A call routing request from a protocol adapter module.
#[derive(Debug, Clone)]
pub struct RouteRequest {
    /// Trace ID of the originating call (ULID string).
    pub trace_id:    String,
    /// Originating party (E.164 or SIP URI).
    pub from_party:  String,
    /// Destination party.
    pub to_party:    String,
    /// Paths to exclude (e.g. already tried and failed).
    pub exclude:     Vec<String>,
    /// Maximum number of results to return.
    pub max_results: usize,
}

/// One path candidate returned by the engine.
#[derive(Debug, Clone)]
pub struct RouteResult {
    pub path_id: String,
    pub score:   f64,
    pub hops:    Vec<NodeId>,
}

/// Live admission state — how many calls are currently on each path.
#[derive(Debug, Default)]
struct AdmissionState {
    /// active_calls[path_id] = current active call count
    active_calls: HashMap<String, u32>,
}

/// The routing engine.
pub struct RoutingEngine {
    lsdb:      Arc<LinkStateDb>,
    graph:     Arc<RwLock<RoutingGraph>>,
    admission: Arc<RwLock<AdmissionState>>,
    weights:   ScoreWeights,
    /// Target Erlang B blocking probability (e.g. 0.01 = 1 %).
    target_blocking: f64,
    /// Backup path count per route (Yen's k).
    k_paths: usize,
    /// Score below which a path is marked degraded.
    degraded_threshold: f64,
    /// Paths removed from topology due to maintenance.
    excluded_paths: Arc<RwLock<Vec<String>>>,
}

impl RoutingEngine {
    /// Construct a new routing engine with the given link-state database.
    pub fn new(
        lsdb:               Arc<LinkStateDb>,
        weights:            ScoreWeights,
        target_blocking:    f64,
        k_paths:            usize,
        degraded_threshold: f64,
    ) -> Arc<Self> {
        Arc::new(RoutingEngine {
            lsdb,
            graph:     Arc::new(RwLock::new(RoutingGraph::new())),
            admission: Arc::new(RwLock::new(AdmissionState::default())),
            weights,
            target_blocking,
            k_paths,
            degraded_threshold,
            excluded_paths: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Route a call request.
    ///
    /// Steps:
    /// 1. Query the graph for k-shortest paths to the destination.
    /// 2. Filter excluded and degraded paths.
    /// 3. Check Erlang B admission on the best path.
    /// 4. Return ordered candidates.
    pub fn route(&self, req: &RouteRequest) -> Vec<RouteResult> {
        let graph = self.graph.read().unwrap();
        let excluded = self.excluded_paths.read().unwrap();

        // Resolve destination to a graph node.
        // Phase 2 simplification: use to_party directly as the node ID.
        // Phase 3 will add E.164 → node-ID resolution via the registrar.
        let dst = &req.to_party;

        // Try each known source node as a potential ingress.
        let mut candidates: Vec<RouteResult> = Vec::new();

        for src in graph.nodes() {
            if src == dst { continue; }
            let paths = graph.k_shortest_paths(src, dst, self.k_paths);
            for (hops, score) in paths {
                let path_id = hops.join(" → ");
                if req.exclude.contains(&path_id) { continue; }
                if excluded.contains(&path_id)    { continue; }
                if score < self.degraded_threshold { continue; }
                if !self.admit(&path_id)           { continue; }
                candidates.push(RouteResult { path_id, score, hops });
            }
        }

        // Sort best-score first.
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        candidates.truncate(req.max_results);
        candidates
    }

    /// Increment active call count on a path. Returns `true` if admitted.
    fn admit(&self, path_id: &str) -> bool {
        let mut adm = self.admission.write().unwrap();
        let active = *adm.active_calls.get(path_id).unwrap_or(&0);
        // Use inverse Erlang B to get the trunk count at which blocking
        // hits the target. If we're already at that count, reject.
        let a = active as f64 + 1.0; // offered traffic if we admit this call
        let n = erlang_b_inverse(a, self.target_blocking);
        let blocking = erlang_b(a, n);
        if blocking > self.target_blocking {
            return false; // Would exceed blocking target.
        }
        *adm.active_calls.entry(path_id.to_owned()).or_insert(0) += 1;
        true
    }

    /// Release a call from a path (on teardown).
    pub fn release(&self, path_id: &str) {
        let mut adm = self.admission.write().unwrap();
        if let Some(count) = adm.active_calls.get_mut(path_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Rebuild the `RoutingGraph` from the current `LinkStateDb` snapshot.
    ///
    /// Called by the recompute loop and on explicit topology change notification.
    pub fn recompute(&self) {
        let snapshot = self.lsdb.snapshot();
        let mut graph = RoutingGraph::new();

        for (path_id, metrics) in snapshot {
            let score = score_path(metrics, self.weights);
            // Parse "src → dst" path IDs into edges.
            if let Some((from, to)) = path_id.split_once(" → ") {
                let existing = graph.edges_from(from).to_vec();
                let mut edges = existing;
                edges.push(Edge {
                    to:    to.to_owned(),
                    score,
                });
                graph.set_edges(from.to_owned(), edges);
            }
        }

        *self.graph.write().unwrap() = graph;
        tracing::debug!("routing graph recomputed ({} paths)", self.lsdb.snapshot().len());
    }

    /// Exclude a path from routing (e.g. module entering maintenance).
    pub fn exclude_path(&self, path_id: String) {
        self.excluded_paths.write().unwrap().push(path_id);
    }

    /// Re-include a path (e.g. module resumed).
    pub fn include_path(&self, path_id: &str) {
        self.excluded_paths.write().unwrap().retain(|p| p != path_id);
    }

    /// Start the background recompute loop.
    pub async fn run_recompute_loop(self: Arc<Self>, interval_secs: u64) {
        let mut tick = time::interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            self.recompute();
        }
    }
}
