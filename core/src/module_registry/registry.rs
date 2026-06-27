//! In-memory module registry backed by a lock-free concurrent hashmap.

use super::{
    health::{transition, HealthEvent, ModuleStatus},
};
use dashmap::DashMap;
use std::time::Instant;

/// A registered module entry.
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub status:           ModuleStatus,
    pub last_heartbeat:   Instant,
    pub heartbeat_seq:    u64,
    pub missed_beats:     u32,
}

/// The live module registry.  Thread-safe; clone the Arc to share.
pub struct ModuleRegistry {
    inner: DashMap<String, ModuleEntry>,
    /// How many consecutive missed heartbeats trigger Degraded.
    degraded_threshold: u32,
}

impl ModuleRegistry {
    pub fn new(degraded_threshold: u32) -> Self {
        ModuleRegistry {
            inner: DashMap::new(),
            degraded_threshold,
        }
    }

    /// Register a module as Online.
    pub fn register(&self, name: String, status: ModuleStatus) {
        self.inner.insert(name, ModuleEntry {
            status,
            last_heartbeat: Instant::now(),
            heartbeat_seq:  0,
            missed_beats:   0,
        });
    }

    /// Remove a module (typically on disconnect).
    pub fn deregister(&self, name: &str) {
        self.inner.remove(name);
        tracing::info!("module deregistered: {name}");
    }

    /// Update the status of a module.
    pub fn update_status(&self, name: &str, status: ModuleStatus) {
        if let Some(mut entry) = self.inner.get_mut(name) {
            entry.status = status;
        }
    }

    /// Apply a health event to a module and update its state.
    pub fn apply_event(&self, name: &str, event: HealthEvent) {
        if let Some(mut entry) = self.inner.get_mut(name) {
            match transition(name, &entry.status, event) {
                Ok(next) => entry.status = next,
                Err(e)   => tracing::warn!("{e}"),
            }
        }
    }

    /// Record a heartbeat from a module.
    pub fn heartbeat(&self, name: &str, seq: u64) {
        if let Some(mut entry) = self.inner.get_mut(name) {
            entry.last_heartbeat = Instant::now();
            entry.heartbeat_seq  = seq;
            let was_degraded = entry.status == ModuleStatus::Degraded;
            entry.missed_beats = 0;
            if was_degraded {
                drop(entry); // release borrow before apply_event
                self.apply_event(name, HealthEvent::HeartbeatRecovered);
            }
        }
    }

    /// Called by the watchdog when a heartbeat period elapses without a ping.
    pub fn record_missed_beat(&self, name: &str) {
        if let Some(mut entry) = self.inner.get_mut(name) {
            entry.missed_beats += 1;
            if entry.missed_beats >= self.degraded_threshold {
                let _ = transition(name, &entry.status, HealthEvent::HeartbeatMissed)
                    .map(|s| entry.status = s);
            }
        }
    }

    /// Get a snapshot of all module statuses.
    pub fn snapshot(&self) -> Vec<(String, ModuleStatus)> {
        self.inner
            .iter()
            .map(|e| (e.key().clone(), e.value().status.clone()))
            .collect()
    }

    /// Is the given module currently accepting traffic?
    pub fn is_online(&self, name: &str) -> bool {
        self.inner
            .get(name)
            .map(|e| e.status == ModuleStatus::Online)
            .unwrap_or(false)
    }
}
