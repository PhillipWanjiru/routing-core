//! Module registry: tracks running modules, health state, and heartbeats.

pub mod health;
pub mod registry;
pub mod watchdog;

pub use health::ModuleStatus;
pub use registry::ModuleRegistry;
pub use watchdog::Watchdog;
