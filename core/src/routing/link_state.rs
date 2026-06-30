//! Link-state metric flooding.
//!
//! Each module floods a `LinkStateUpdate` whenever its measured path
//! metrics change significantly.  The routing engine subscribes to these
//! updates and recomputes path scores on receipt.
//!
//! This is the same principle as OSPF's link-state advertisements —
//! every node in the routing domain knows the current metric of every
//! path, not just the paths it directly owns.

use crate::routing::path_scoring::PathMetrics;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// A metric update broadcast by one module for one of its paths.
#[derive(Debug, Clone)]
pub struct LinkStateUpdate {
    /// Module that owns this path (e.g. "voip-sip").
    pub origin:  String,
    /// Human-readable path ID (e.g. "nbo-edge-01 → internet").
    pub path_id: String,
    /// Current measured metrics.
    pub metrics: PathMetrics,
    /// Monotonic sequence number — discard updates with lower seq.
    pub seq:     u64,
}

/// Stored state for one path.
#[derive(Debug, Clone)]
struct PathState {
    metrics:      PathMetrics,
    seq:          u64,
    last_updated: Instant,
}

/// The link-state database.  Shared across the routing engine and the
/// IPC bus receive loop.
#[derive(Debug, Default)]
pub struct LinkStateDb {
    // path_id → current state
    inner: RwLock<HashMap<String, PathState>>,
}

impl LinkStateDb {
    pub fn new() -> Arc<Self> {
        Arc::new(LinkStateDb::default())
    }

    /// Apply an incoming update.  Returns `true` if the update was accepted
    /// (seq was higher than what we had), `false` if it was stale.
    pub fn apply(&self, update: LinkStateUpdate) -> bool {
        let mut db = self.inner.write().unwrap();
        let entry = db.entry(update.path_id.clone()).or_insert(PathState {
            metrics:      update.metrics,
            seq:          0,
            last_updated: Instant::now(),
        });
        if update.seq <= entry.seq {
            return false; // Stale — discard.
        }
        entry.metrics      = update.metrics;
        entry.seq          = update.seq;
        entry.last_updated = Instant::now();
        true
    }

    /// Get current metrics for a path, or None if unknown.
    pub fn get(&self, path_id: &str) -> Option<PathMetrics> {
        self.inner.read().unwrap()
            .get(path_id)
            .map(|s| s.metrics)
    }

    /// Snapshot all known path metrics.
    pub fn snapshot(&self) -> Vec<(String, PathMetrics)> {
        self.inner.read().unwrap()
            .iter()
            .map(|(id, s)| (id.clone(), s.metrics))
            .collect()
    }

    /// Remove paths not updated within `max_age` seconds.
    pub fn evict_stale(&self, max_age_secs: u64) {
        let mut db = self.inner.write().unwrap();
        let threshold = std::time::Duration::from_secs(max_age_secs);
        db.retain(|_, v| v.last_updated.elapsed() < threshold);
    }
}
