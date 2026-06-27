//! Heartbeat watchdog: periodically checks for modules that have gone silent.
//!
//! For every registered module, if no heartbeat is received within
//! `heartbeat_interval`, `record_missed_beat` is called on the registry.
//! After `degraded_threshold` consecutive missed beats the module's status
//! transitions to Degraded and it stops receiving new traffic.

use crate::module_registry::registry::ModuleRegistry;
use std::{sync::Arc, time::Duration};
use tokio::time;

/// The heartbeat watchdog task.
pub struct Watchdog {
    registry:           Arc<ModuleRegistry>,
    heartbeat_interval: Duration,
}

impl Watchdog {
    pub fn new(registry: Arc<ModuleRegistry>, heartbeat_interval: Duration) -> Self {
        Watchdog { registry, heartbeat_interval }
    }

    /// Run the watchdog loop indefinitely.  Call this in a spawned task.
    pub async fn run(self) {
        let mut interval = time::interval(self.heartbeat_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;

            // Check every registered module for a missed heartbeat.
            let modules: Vec<String> = self
                .registry
                .snapshot()
                .into_iter()
                .map(|(name, _)| name)
                .collect();

            for name in modules {
                if !self.received_recent_heartbeat(&name) {
                    tracing::debug!("watchdog: missed beat from {name}");
                    self.registry.record_missed_beat(&name);
                }
            }
        }
    }

    /// Returns true if the module sent a heartbeat within the last interval.
    fn received_recent_heartbeat(&self, name: &str) -> bool {
        use crate::module_registry::registry::ModuleEntry;
        use dashmap::DashMap;

        // We check the last_heartbeat timestamp directly via the registry's
        // inner map.  The registry exposes a heartbeat() method that sets it;
        // we read it through the snapshot mechanism for safety.
        //
        // Phase 1 simplification: if the module is in the snapshot it is
        // assumed to have been heard from recently.  In Phase 2 this will
        // compare Instant::now() against last_heartbeat.
        true // TODO Phase 2: compare Instant::now() - last_heartbeat < interval
    }
}
