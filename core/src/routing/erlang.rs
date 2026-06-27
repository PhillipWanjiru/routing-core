//! Erlang B and Erlang C traffic engineering calculations.
//!
//! These are the mathematical foundation of call admission control.
//! A.K. Erlang derived these formulae for telephone networks in 1917;
//! they remain the standard tool for trunk capacity planning.
//!
//! # Definitions
//!
//! - **Offered traffic `a`** — mean number of calls arriving per mean call
//!   duration, in Erlangs.  E.g. 20 calls/hour × 3 min average = 1 Erlang.
//! - **Trunk count `n`** — number of simultaneous call slots.
//! - **Erlang B** — models loss systems (no queue; call is rejected if all
//!   trunks are busy).  Returns the blocking probability.
//! - **Erlang C** — models delay systems (callers queue).  Returns the
//!   probability that an arriving call must wait.
//!
//! # Numerical stability
//!
//! The naive factorial form overflows for n > ~20.  This implementation uses
//! the iterative Jagerman recursion which is numerically stable for any n:
//!
//! ```text
//! B(A, 0) = 1
//! B(A, n) = (A × B(A, n-1)) / (n + A × B(A, n-1))
//! ```

/// Erlang B blocking probability for `n` circuits under offered traffic `a` Erlangs.
///
/// Returns a probability in [0, 1].
///
/// # Examples
///
/// ```rust
/// use routing_core::routing::erlang::erlang_b;
/// // 10 Erlang offered load, 15 trunks → ~1.47% blocking.
/// let b = erlang_b(10.0, 15);
/// assert!((b - 0.0365).abs() < 0.001);
/// ```
pub fn erlang_b(a: f64, n: u32) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    // Jagerman iterative form — avoids factorial overflow.
    let mut b = 1.0_f64;
    for i in 1..=n {
        b = (a * b) / (i as f64 + a * b);
    }
    b
}

/// Minimum trunk count such that Erlang B blocking probability ≤ `target`.
///
/// Uses a simple linear search; for typical traffic levels (< 1000 Erlangs)
/// this terminates in < 2000 iterations.
///
/// # Panics
///
/// Panics if `target` is not in (0, 1].
pub fn erlang_b_inverse(a: f64, target: f64) -> u32 {
    assert!(
        target > 0.0 && target <= 1.0,
        "target blocking must be in (0, 1], got {target}"
    );
    if a <= 0.0 {
        return 0;
    }
    let mut n = 1u32;
    while erlang_b(a, n) > target {
        n += 1;
        // Guard against pathological inputs.
        if n > 100_000 {
            panic!("erlang_b_inverse: did not converge for a={a}, target={target}");
        }
    }
    n
}

/// Erlang C: probability that an arriving call must queue (delay system).
///
/// A delay system never rejects calls; instead they wait.  Returns the
/// probability that a caller will not find a free agent immediately.
///
/// If `a >= n` (offered load ≥ number of agents) the system is unstable
/// and the queue grows without bound; this function returns `1.0` in that case.
pub fn erlang_c(a: f64, n: u32) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    if a >= n as f64 {
        return 1.0;
    }
    let b = erlang_b(a, n);
    // Erlang C in terms of Erlang B:
    // C(A, N) = N × B(A, N) / (N - A × (1 - B(A, N)))
    let numerator   = n as f64 * b;
    let denominator = n as f64 - a * (1.0 - b);
    if denominator <= 0.0 {
        return 1.0;
    }
    (numerator / denominator).min(1.0)
}

/// Expected waiting time for Erlang C queue (in the same time unit as `service_time`).
///
/// `service_time` is the mean time to serve one call (e.g. in seconds).
/// Returns the mean waiting time for calls that arrive when the system is busy.
pub fn erlang_c_wait_time(a: f64, n: u32, service_time: f64) -> f64 {
    if a <= 0.0 || service_time <= 0.0 {
        return 0.0;
    }
    let c = erlang_c(a, n);
    let mu = 1.0 / service_time;            // service rate per agent
    let intensity = n as f64 * mu - a * mu; // net service rate above arrival rate
    if intensity <= 0.0 {
        return f64::INFINITY;
    }
    c / intensity
}

/// Traffic intensity in Erlangs for `calls_per_hour` calls with `mean_duration_minutes`.
///
/// Convenience helper: Erlangs = (calls/hour × duration_minutes) / 60.
pub fn offered_traffic(calls_per_hour: f64, mean_duration_minutes: f64) -> f64 {
    (calls_per_hour * mean_duration_minutes) / 60.0
}
