//! Link-state graph and Yen's k-shortest-paths algorithm.
//!
//! The graph is a directed weighted graph where nodes are module endpoints
//! (e.g. "nbo-edge-01", "mombasa-relay") and edge weights are composite
//! path scores computed by `path_scoring::score_path`.
//!
//! Yen's algorithm precomputes the k best loop-free paths between any two
//! nodes. Precomputing on topology change means failover does not require
//! recomputation at call time — the backup paths are already ranked.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::cmp::Ordering;

/// A node in the routing graph.
pub type NodeId = String;

/// One directed edge in the graph.
#[derive(Debug, Clone)]
pub struct Edge {
    pub to:    NodeId,
    /// Score in [0, 1]. Higher is better.
    /// We convert to cost = 1 - score for Dijkstra's min-heap.
    pub score: f64,
}

/// The routing graph.
#[derive(Debug, Clone, Default)]
pub struct RoutingGraph {
    /// adjacency list: from_node → list of edges
    edges: HashMap<NodeId, Vec<Edge>>,
}

impl RoutingGraph {
    pub fn new() -> Self { RoutingGraph::default() }

    /// Add or replace all edges from `from`.
    pub fn set_edges(&mut self, from: NodeId, edges: Vec<Edge>) {
        self.edges.insert(from, edges);
    }

    /// All nodes that have at least one outbound edge.
    pub fn nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.edges.keys()
    }

    /// Outbound edges from `node`.
    pub fn edges_from(&self, node: &str) -> &[Edge] {
        self.edges.get(node).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Dijkstra's shortest path (highest score) from `src` to `dst`.
    /// Returns the path as a sequence of node IDs, or None if unreachable.
    pub fn shortest_path(&self, src: &str, dst: &str) -> Option<Vec<NodeId>> {
        if src == dst { return Some(vec![src.to_owned()]); }

        // best_score[node] = best composite score found so far to reach node.
        let mut best:   HashMap<&str, f64>        = HashMap::new();
        let mut prev:   HashMap<&str, &str>        = HashMap::new();
        let mut heap:   BinaryHeap<HeapEntry>      = BinaryHeap::new();

        best.insert(src, 1.0);
        heap.push(HeapEntry { score: 1.0, node: src });

        while let Some(HeapEntry { score, node }) = heap.pop() {
            if node == dst {
                // Reconstruct path.
                let mut path = Vec::new();
                let mut cur = dst;
                while cur != src {
                    path.push(cur.to_owned());
                    cur = prev[cur];
                }
                path.push(src.to_owned());
                path.reverse();
                return Some(path);
            }
            if score < *best.get(node).unwrap_or(&0.0) {
                continue; // Stale entry.
            }
            for edge in self.edges_from(node) {
                // Combined score: product of scores along the path.
                let new_score = score * edge.score;
                let to = edge.to.as_str();
                if new_score > *best.get(to).unwrap_or(&0.0) {
                    best.insert(to, new_score);
                    prev.insert(to, node);
                    heap.push(HeapEntry { score: new_score, node: to });
                }
            }
        }
        None
    }

    /// Yen's k-shortest loop-free paths from `src` to `dst`.
    ///
    /// Returns up to `k` paths sorted by descending composite score.
    /// Call this on topology change to precompute failover candidates.
    pub fn k_shortest_paths(
        &self,
        src: &str,
        dst: &str,
        k: usize,
    ) -> Vec<(Vec<NodeId>, f64)> {
        // A path and its composite score.
        let mut result: Vec<(Vec<NodeId>, f64)> = Vec::new();

        // Candidate heap.
        let mut candidates: BinaryHeap<ScoredPath> = BinaryHeap::new();

        // Seed with the shortest path.
        if let Some(path) = self.shortest_path(src, dst) {
            let score = path_score(&path, self);
            candidates.push(ScoredPath { score, path });
        }

        let mut seen: HashSet<Vec<NodeId>> = HashSet::new();

        while result.len() < k {
            let Some(ScoredPath { score, path }) = candidates.pop() else {
                break;
            };

            if seen.contains(&path) { continue; }
            seen.insert(path.clone());
            result.push((path.clone(), score));

            // Generate spur paths from each node in the current path.
            for spur_idx in 0..path.len().saturating_sub(1) {
                let spur_node  = &path[spur_idx];
                let root_path  = &path[..=spur_idx];

                // Build a temporary graph that removes edges used by
                // already-found paths that share the same root.
                let mut removed_edges: HashSet<(&str, &str)> = HashSet::new();
                for (found_path, _) in &result {
                    if found_path.len() > spur_idx
                        && &found_path[..=spur_idx] == root_path
                    {
                        if let Some(next) = found_path.get(spur_idx + 1) {
                            removed_edges.insert((spur_node, next.as_str()));
                        }
                    }
                }
                // Also remove root path interior nodes from the graph.
                let removed_nodes: HashSet<&str> =
                    root_path[..spur_idx].iter().map(|s| s.as_str()).collect();

                // Find spur path on the pruned graph.
                if let Some(spur) = self.shortest_path_pruned(
                    spur_node,
                    dst,
                    &removed_edges,
                    &removed_nodes,
                ) {
                    let mut full = root_path.to_vec();
                    full.extend_from_slice(&spur[1..]);
                    if !seen.contains(&full) {
                        let s = path_score(&full, self);
                        candidates.push(ScoredPath { score: s, path: full });
                    }
                }
            }
        }

        result
    }

    /// Dijkstra on a pruned graph (edges and nodes excluded).
    fn shortest_path_pruned<'a>(
        &'a self,
        src: &'a str,
        dst: &'a str,
        removed_edges: &HashSet<(&str, &str)>,
        removed_nodes: &HashSet<&str>,
    ) -> Option<Vec<NodeId>> {
        if src == dst { return Some(vec![src.to_owned()]); }

        let mut best: HashMap<&str, f64> = HashMap::new();
        let mut prev: HashMap<&str, &str> = HashMap::new();
        let mut heap: BinaryHeap<HeapEntry> = BinaryHeap::new();

        best.insert(src, 1.0);
        heap.push(HeapEntry { score: 1.0, node: src });

        while let Some(HeapEntry { score, node }) = heap.pop() {
            if node == dst {
                let mut path = Vec::new();
                let mut cur = dst;
                while cur != src {
                    path.push(cur.to_owned());
                    cur = prev[cur];
                }
                path.push(src.to_owned());
                path.reverse();
                return Some(path);
            }
            if score < *best.get(node).unwrap_or(&0.0) { continue; }
            for edge in self.edges_from(node) {
                let to = edge.to.as_str();
                if removed_nodes.contains(to) { continue; }
                if removed_edges.contains(&(node, to)) { continue; }
                let new_score = score * edge.score;
                if new_score > *best.get(to).unwrap_or(&0.0) {
                    best.insert(to, new_score);
                    prev.insert(to, node);
                    heap.push(HeapEntry { score: new_score, node: to });
                }
            }
        }
        None
    }
}

// ─── Heap helpers ─────────────────────────────────────────────

#[derive(Debug)]
struct HeapEntry<'a> {
    score: f64,
    node:  &'a str,
}

impl PartialEq for HeapEntry<'_> {
    fn eq(&self, other: &Self) -> bool { self.score == other.score }
}
impl Eq for HeapEntry<'_> {}
impl PartialOrd for HeapEntry<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.score.partial_cmp(&other.score)
    }
}
impl Ord for HeapEntry<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

#[derive(Debug)]
struct ScoredPath {
    score: f64,
    path:  Vec<NodeId>,
}

impl PartialEq for ScoredPath {
    fn eq(&self, o: &Self) -> bool { self.score == o.score && self.path == o.path }
}
impl Eq for ScoredPath {}
impl PartialOrd for ScoredPath {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> { self.score.partial_cmp(&o.score) }
}
impl Ord for ScoredPath {
    fn cmp(&self, o: &Self) -> Ordering { self.partial_cmp(o).unwrap_or(Ordering::Equal) }
}

/// Composite score for a path = product of edge scores.
fn path_score(path: &[NodeId], graph: &RoutingGraph) -> f64 {
    let mut score = 1.0_f64;
    for i in 0..path.len().saturating_sub(1) {
        let from = &path[i];
        let to   = &path[i + 1];
        if let Some(edge) = graph.edges_from(from).iter().find(|e| &e.to == to) {
            score *= edge.score;
        } else {
            return 0.0; // Edge removed or graph changed.
        }
    }
    score
}
