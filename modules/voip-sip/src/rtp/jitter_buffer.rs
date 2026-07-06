//! Adaptive jitter buffer with Kalman filter state estimation.
//!
//! # Why Kalman and not a moving average
//!
//! A moving average lags behind sudden jitter changes — it takes N packets
//! to converge to the new level.  A Kalman filter tracks two state
//! variables (estimated jitter and rate of change), which lets it
//! anticipate sustained trends rather than only reacting after packets
//! are already late.
//!
//! # State model
//!
//! State vector x = [jitter_ms, jitter_rate]
//!
//! Prediction:  x_pred = F * x_prev          (constant-velocity model)
//! Measurement: z      = measured_jitter_ms  (scalar)
//!
//! F = [[1, dt], [0, 1]]  where dt ≈ 1 (one packet interval)
//! H = [1, 0]             (we observe jitter directly, not rate)
//!
//! # Buffer depth
//!
//! depth_ms = K_safety × estimated_jitter_ms
//!
//! K_safety (default 1.5) adds headroom above the Kalman estimate.
//! Depth is clamped to [min_depth_ms, max_depth_ms].
//!
//! # Late-packet policy
//!
//! A packet is "too late" if its playout time has already passed.
//! Late packets are counted but NOT delivered — delivering a late packet
//! causes an audible glitch worse than the concealment of a lost packet.

use std::collections::BinaryHeap;
use std::cmp::Reverse;

/// A packet held in the buffer, ordered by its playout sequence number.
#[derive(Debug, Eq, PartialEq)]
struct Slot {
    /// Extended sequence number — used as the sort key in the min-heap.
    seq_ext: u32,
    /// Arrival time relative to session start, in milliseconds.
    arrival_ms: u64,
    /// Raw payload bytes (post-header RTP payload).
    payload: Vec<u8>,
}

impl Ord for Slot {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max-heap; Reverse gives us min-heap behaviour.
        Reverse(self.seq_ext).cmp(&Reverse(other.seq_ext))
    }
}
impl PartialOrd for Slot {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ─── Kalman filter ─────────────────────────────────────────────

/// Scalar Kalman filter tracking jitter and its rate of change.
struct KalmanJitter {
    /// Estimated jitter in ms.
    x_jitter: f64,
    /// Estimated rate of change of jitter (ms per packet interval).
    x_rate:   f64,
    /// Covariance matrix stored as [p00, p01, p10, p11].
    p:        [f64; 4],
}

impl KalmanJitter {
    fn new(initial_jitter_ms: f64) -> Self {
        KalmanJitter {
            x_jitter: initial_jitter_ms,
            x_rate:   0.0,
            // Initial covariance — large diagonal values mean "we don't know yet."
            p: [10.0, 0.0, 0.0, 10.0],
        }
    }

    /// Update with a new jitter measurement. Returns updated jitter estimate.
    ///
    /// `measured_jitter_ms`: absolute inter-arrival jitter measured for this
    /// packet against the previous one.
    fn update(&mut self, measured_jitter_ms: f64) -> f64 {
        // Process noise (how much the true jitter can change per step).
        // Q controls how fast the filter adapts: large Q = fast adaptation
        // but noisy; small Q = smooth but slow. Tuned empirically.
        const Q00: f64 = 0.5;  // jitter variance
        const Q11: f64 = 0.1;  // rate variance
        // Measurement noise: how noisy the individual measurement is.
        const R: f64   = 4.0;

        // ── Predict ──────────────────────────────────────────────
        // x_pred = F * x  (F = [[1,1],[0,1]], dt=1 packet interval)
        let x_jit_pred = self.x_jitter + self.x_rate;
        let x_rate_pred = self.x_rate;

        // P_pred = F * P * F^T + Q
        let p00_pred = self.p[0] + self.p[1] + self.p[2] + self.p[3] + Q00;
        let p01_pred = self.p[1] + self.p[3];
        let p10_pred = self.p[2] + self.p[3];
        let p11_pred = self.p[3] + Q11;

        // ── Update ───────────────────────────────────────────────
        // Innovation: z - H * x_pred  (H = [1, 0])
        let innov = measured_jitter_ms - x_jit_pred;
        // Innovation covariance: S = H * P_pred * H^T + R
        let s = p00_pred + R;
        // Kalman gain: K = P_pred * H^T / S
        let k0 = p00_pred / s;  // gain for jitter state
        let k1 = p10_pred / s;  // gain for rate state

        self.x_jitter = x_jit_pred + k0 * innov;
        self.x_rate   = x_rate_pred + k1 * innov;
        // Keep rate bounded to prevent runaway estimates.
        self.x_rate   = self.x_rate.clamp(-20.0, 20.0);
        // Jitter is non-negative.
        self.x_jitter = self.x_jitter.max(0.0);

        // P_est = (I - K * H) * P_pred
        self.p[0] = (1.0 - k0) * p00_pred;
        self.p[1] = (1.0 - k0) * p01_pred;
        self.p[2] = -k1 * p00_pred + p10_pred;
        self.p[3] = -k1 * p01_pred + p11_pred;

        self.x_jitter
    }

    fn estimated_jitter_ms(&self) -> f64 { self.x_jitter }
}

// ─── Jitter buffer ─────────────────────────────────────────────

/// Adaptive jitter buffer with Kalman-estimated depth.
pub struct JitterBuffer {
    heap:           BinaryHeap<Slot>,
    /// Current depth setting in milliseconds.
    depth_ms:       f64,
    /// Configurable bounds.
    min_depth_ms:   f64,
    max_depth_ms:   f64,
    /// Safety factor: depth = k_safety × estimated_jitter.
    k_safety:       f64,
    kalman:         KalmanJitter,
    /// Packet rate in packets/second (determines ms-per-packet).
    ptime_ms:       f64,
    /// Last arrival time for inter-arrival delta calculation.
    last_arrival_ms: Option<u64>,
    /// Statistics.
    pub packets_received: u64,
    pub packets_late:     u64,
    pub packets_played:   u64,
    /// Next expected extended sequence number.
    next_seq_ext:   Option<u32>,
}

impl JitterBuffer {
    /// Create a new jitter buffer.
    ///
    /// - `ptime_ms`: packetisation time in milliseconds (20ms for G.711 @ 8kHz)
    /// - `min_depth_ms` / `max_depth_ms`: depth clamps
    /// - `k_safety`: multiplier on Kalman estimate (1.5 is a good default)
    pub fn new(ptime_ms: f64, min_depth_ms: f64, max_depth_ms: f64, k_safety: f64) -> Self {
        JitterBuffer {
            heap:             BinaryHeap::new(),
            depth_ms:         min_depth_ms,
            min_depth_ms,
            max_depth_ms,
            k_safety,
            kalman:           KalmanJitter::new(min_depth_ms / k_safety),
            ptime_ms,
            last_arrival_ms:  None,
            packets_received: 0,
            packets_late:     0,
            packets_played:   0,
            next_seq_ext:     None,
        }
    }

    /// Insert a received packet. `seq_ext` is the 32-bit extended sequence
    /// number (computed by `RtpRecvSession`). `arrival_ms` is the arrival
    /// wall-clock time in milliseconds since session start.
    pub fn insert(&mut self, seq_ext: u32, payload: Vec<u8>, arrival_ms: u64) {
        self.packets_received += 1;

        // Measure inter-arrival jitter and update the Kalman filter.
        if let Some(last) = self.last_arrival_ms {
            let delta_ms = arrival_ms.saturating_sub(last) as f64;
            let expected_delta = self.ptime_ms;
            let jitter_sample = (delta_ms - expected_delta).abs();
            let new_estimate = self.kalman.update(jitter_sample);
            // Recompute depth from the updated estimate.
            let target = (new_estimate * self.k_safety).clamp(
                self.min_depth_ms, self.max_depth_ms
            );
            // Smooth depth changes: move 10% toward target per packet.
            // This prevents sudden depth jumps that cause audible artefacts.
            self.depth_ms += (target - self.depth_ms) * 0.10;
        }
        self.last_arrival_ms = Some(arrival_ms);

        self.heap.push(Slot { seq_ext, arrival_ms, payload });
    }

    /// Pop the next packet ready for playout, if its playout time has arrived.
    ///
    /// `now_ms`: current time in milliseconds since session start.
    ///
    /// The packet is "ready" when `now_ms ≥ arrival_ms + depth_ms` — i.e.
    /// enough time has passed for late packets with this sequence number
    /// to have arrived.
    ///
    /// Returns `None` if the next packet is not yet due, or `Some(payload)`
    /// when it is. If the expected sequence was never received, returns
    /// `Some(vec![])` as a loss indication (the codec should apply PLC).
    pub fn pop_due(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        // Peek at the minimum-sequence packet.
        let ready = self.heap.peek().map(|s| {
            now_ms >= s.arrival_ms + self.depth_ms as u64
        }).unwrap_or(false);

        if ready {
            let slot = self.heap.pop().unwrap();

            // Check for discontinuity in sequence numbers.
            if let Some(expected) = self.next_seq_ext {
                if slot.seq_ext > expected {
                    // Gap — packets were lost. Signal loss for each missing seq.
                    // (Caller is responsible for PLC on empty payload.)
                    self.next_seq_ext = Some(slot.seq_ext + 1);
                    self.packets_late += (slot.seq_ext - expected) as u64;
                    self.packets_played += 1;
                    return Some(slot.payload);
                }
            }

            self.next_seq_ext = Some(slot.seq_ext + 1);
            self.packets_played += 1;
            Some(slot.payload)
        } else {
            None
        }
    }

    /// Current estimated jitter in milliseconds.
    pub fn estimated_jitter_ms(&self) -> f64 {
        self.kalman.estimated_jitter_ms()
    }

    /// Current adaptive buffer depth in milliseconds.
    pub fn current_depth_ms(&self) -> f64 { self.depth_ms }

    /// Number of packets currently held in the buffer.
    pub fn queued(&self) -> usize { self.heap.len() }
}
