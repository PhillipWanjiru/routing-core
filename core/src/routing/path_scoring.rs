//! Composite path scoring.
//!
//! Score = Σ(weight_i × normalised_metric_i), result in [0, 1].
//! Higher is better. Every metric is normalised against a worst-case reference
//! so that the weights control relative importance, not units.
//!
//! # Worst-case references
//! | Metric      | Worst case | Source                     |
//! |-------------|------------|----------------------------|
//! | Latency     | 400 ms     | ITU-T G.114 absolute limit  |
//! | Jitter      | 50 ms      | practical RTCP threshold    |
//! | Packet loss | 5 %        | call quality floor          |
//! | Cost        | 1.0        | normalised monetary unit    |

/// Measured path quality at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathMetrics {
    /// One-way latency in milliseconds.
    pub latency_ms: f64,
    /// Inter-arrival jitter in milliseconds.
    pub jitter_ms: f64,
    /// Packet loss percentage (0–100).
    pub loss_pct: f64,
    /// Normalised monetary cost (0–1).
    pub cost: f64,
}

/// Per-metric weights. Must sum to 1.0 (enforced by `ScoreWeights::new`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreWeights {
    pub latency: f64,
    pub jitter:  f64,
    pub loss:    f64,
    pub cost:    f64,
}

impl ScoreWeights {
    /// Construct weights, returning an error if they do not sum to 1.0.
    pub fn new(latency: f64, jitter: f64, loss: f64, cost: f64)
        -> Result<Self, String>
    {
        let sum = latency + jitter + loss + cost;
        if (sum - 1.0).abs() > 1e-6 {
            return Err(format!(
                "weights must sum to 1.0, got {:.6}", sum
            ));
        }
        Ok(ScoreWeights { latency, jitter, loss, cost })
    }

    /// Default weights (matches config/schema.rs defaults).
    pub fn default_weights() -> Self {
        ScoreWeights { latency: 0.4, jitter: 0.2, loss: 0.3, cost: 0.1 }
    }
}

// Worst-case reference values for normalisation.
const WORST_LATENCY_MS: f64 = 400.0;
const WORST_JITTER_MS:  f64 =  50.0;
const WORST_LOSS_PCT:   f64 =   5.0;
const WORST_COST:       f64 =   1.0;

/// Compute a composite path score in [0, 1].
///
/// A score of 1.0 is a perfect path (zero latency, jitter, loss, cost).
/// A score of 0.0 means every metric is at or beyond its worst-case limit.
/// Metrics beyond worst-case are clamped to 0.0 contribution rather than
/// going negative.
pub fn score_path(m: PathMetrics, w: ScoreWeights) -> f64 {
    let s_lat  = normalise(m.latency_ms, WORST_LATENCY_MS);
    let s_jit  = normalise(m.jitter_ms,  WORST_JITTER_MS);
    let s_loss = normalise(m.loss_pct,   WORST_LOSS_PCT);
    let s_cost = normalise(m.cost,       WORST_COST);

    (w.latency * s_lat + w.jitter * s_jit + w.loss * s_loss + w.cost * s_cost)
        .clamp(0.0, 1.0)
}

/// Normalise `value` against `worst`: 1.0 when value=0, 0.0 when value≥worst.
#[inline]
fn normalise(value: f64, worst: f64) -> f64 {
    if worst <= 0.0 { return 1.0; }
    (1.0 - value / worst).clamp(0.0, 1.0)
}
