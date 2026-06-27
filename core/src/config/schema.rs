//! Configuration schema — every tuneable in the system, with defaults.

use anyhow::{bail, Result};

// ─── Top-level ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub node:     NodeConfig,
    pub ipc:      IpcConfig,
    pub routing:  RoutingConfig,
    pub logging:  LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            node:    NodeConfig::default(),
            ipc:     IpcConfig::default(),
            routing: RoutingConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// Validate cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        if self.routing.weight_latency + self.routing.weight_jitter
            + self.routing.weight_loss + self.routing.weight_cost
            - 1.0_f64
            > 1e-6
        {
            bail!("routing weights must sum to 1.0");
        }
        if self.routing.target_blocking <= 0.0 || self.routing.target_blocking > 1.0 {
            bail!("target_blocking must be in (0, 1]");
        }
        Ok(())
    }
}

// ─── Node ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Human-readable name, shown in admin dashboard.
    pub name:   String,
    /// Geographic tag (e.g. "nbo-edge-01").
    pub region: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            name:   "routing-core".into(),
            region: "unknown".into(),
        }
    }
}

// ─── IPC ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpcConfig {
    /// Base directory for Unix domain sockets.
    pub socket_dir:    String,
    /// Read timeout in milliseconds.
    pub read_timeout_ms: u64,
    /// Maximum frame size in bytes.  Frames larger than this are rejected.
    pub max_frame_bytes: usize,
}

impl Default for IpcConfig {
    fn default() -> Self {
        IpcConfig {
            socket_dir:       "/run/routing-core".into(),
            read_timeout_ms:  5_000,
            max_frame_bytes:  1_048_576, // 1 MiB
        }
    }
}

// ─── Routing ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Recompute path scores every N seconds.
    pub recompute_interval_s: u64,
    /// Path score weight for latency (must sum to 1.0 with siblings).
    pub weight_latency: f64,
    /// Path score weight for jitter.
    pub weight_jitter: f64,
    /// Path score weight for packet loss.
    pub weight_loss: f64,
    /// Path score weight for monetary cost.
    pub weight_cost: f64,
    /// Erlang B target blocking probability.  E.g. 0.01 = 1 %.
    pub target_blocking: f64,
    /// How many backup paths to precompute per route (Yen's algorithm).
    pub backup_path_count: usize,
    /// Paths scoring below this are marked Degraded.
    pub degraded_threshold: f64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        RoutingConfig {
            recompute_interval_s: 5,
            weight_latency:  0.4,
            weight_jitter:   0.2,
            weight_loss:     0.3,
            weight_cost:     0.1,
            target_blocking: 0.01,
            backup_path_count: 3,
            degraded_threshold: 0.7,
        }
    }
}

// ─── Logging ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level: error | warn | info | debug | trace
    pub level:          String,
    /// Optional path.  None → stderr only.
    pub file:           Option<String>,
    pub retention_days: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level:          "info".into(),
            file:           None,
            retention_days: 90,
        }
    }
}
