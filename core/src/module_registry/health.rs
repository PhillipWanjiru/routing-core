//! Module health state machine.
//!
//! Allowed transitions:
//!
//!   Online ──drain──► Draining ──drain_done──► Maintenance
//!   Maintenance ──resume──► Online
//!   Online / Maintenance / Draining ──heartbeat_missed──► Degraded
//!   Degraded ──heartbeat_recovered──► Online
//!
//! All transitions are logged.  Invalid transitions return an error
//! rather than silently succeeding, which makes debugging easier.

use anyhow::{bail, Result};
use std::fmt;

/// The observable health state of one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    /// Accepting and processing traffic normally.
    Online,
    /// Draining in-flight sessions before entering Maintenance.
    Draining,
    /// No new traffic accepted.  Existing sessions already drained.
    Maintenance { reason: String },
    /// Missed too many heartbeats.  Not receiving traffic.
    Degraded,
    /// No known state (module just registered).
    Unknown,
}

impl fmt::Display for ModuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModuleStatus::Online       => write!(f, "online"),
            ModuleStatus::Draining     => write!(f, "draining"),
            ModuleStatus::Maintenance { reason } =>
                write!(f, "maintenance({reason})"),
            ModuleStatus::Degraded     => write!(f, "degraded"),
            ModuleStatus::Unknown      => write!(f, "unknown"),
        }
    }
}

/// Transition the status of a module, enforcing the allowed-transition rules.
pub fn transition(
    module: &str,
    current: &ModuleStatus,
    event: HealthEvent,
) -> Result<ModuleStatus> {
    let next = match (current, &event) {
        // Normal operation cycle.
        (ModuleStatus::Online, HealthEvent::DrainRequested { reason }) => {
            ModuleStatus::Draining
        }
        (ModuleStatus::Draining, HealthEvent::DrainComplete) => {
            ModuleStatus::Maintenance { reason: String::new() }
        }
        (ModuleStatus::Maintenance { .. }, HealthEvent::Resumed) => {
            ModuleStatus::Online
        }

        // Watchdog events are allowed from any live state.
        (_, HealthEvent::HeartbeatMissed) => ModuleStatus::Degraded,
        (ModuleStatus::Degraded, HealthEvent::HeartbeatRecovered) => {
            ModuleStatus::Online
        }

        // Allow idempotent online transition (reconnect after restart).
        (_, HealthEvent::Registered) => ModuleStatus::Online,

        // Unknown → Online when module first announces itself.
        (ModuleStatus::Unknown, _) => ModuleStatus::Online,

        (cur, ev) => {
            bail!(
                "module {module}: invalid transition {:?} from state {cur}",
                ev
            );
        }
    };

    tracing::info!(
        "module {module}: {} → {}",
        current,
        next
    );

    Ok(next)
}

/// Events that drive the health state machine.
#[derive(Debug, Clone)]
pub enum HealthEvent {
    /// Module connected and announced itself.
    Registered,
    /// Admin requested drain (with optional reason).
    DrainRequested { reason: String },
    /// In-flight sessions have all completed; safe to enter maintenance.
    DrainComplete,
    /// Admin resumed the module after maintenance.
    Resumed,
    /// Watchdog detected consecutive missed heartbeats.
    HeartbeatMissed,
    /// Watchdog received a heartbeat from a previously degraded module.
    HeartbeatRecovered,
}
