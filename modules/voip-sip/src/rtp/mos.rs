//! ITU-T G.107 E-model — transmission quality R-value and MOS scoring.
//!
//! This is the mathematical foundation documented in
//! ROUTING_CORE_TECHNICAL_DOCUMENTATION.md §4.8. It converts network-level
//! measurements (one-way latency, packet loss, codec impairment) into a
//! single quality score that matches how a human listener actually
//! perceives the call — this is the same model ITU-T uses to certify
//! carrier-grade voice equipment.
//!
//! # R-value
//!
//! ```text
//! R = R0 - Id - Ie
//! ```
//!
//! - `R0 = 94.2`   — basic signal-to-noise ratio for digital PSTN-quality audio.
//! - `Id`          — impairment due to one-way delay (mouth-to-ear latency).
//! - `Ie`          — equipment/codec impairment, dominated here by packet loss.
//!
//! # Delay impairment (Id)
//!
//! ```text
//! Id = 0.024*d + 0.11*(d - 177.3)*H(d - 177.3)
//! ```
//! where `H(x)` is the Heaviside step function (0 for x<0, 1 for x>=0).
//! Below ~177ms one-way delay, only the linear term applies — delay this
//! short doesn't yet disrupt conversational turn-taking. Beyond that
//! threshold, a much steeper penalty applies because talkers start
//! interrupting each other.
//!
//! # Equipment impairment (Ie)
//!
//! ```text
//! Ie = codec_ie + 2.5 * loss_pct
//! ```
//! `codec_ie` is the codec's own quality floor (G.711 ≈ 0, since it's
//! uncompressed toll-quality PCM; lossy codecs like a low-bitrate Opus
//! profile would use a higher published Ie value). The loss term uses
//! 2.5 points of impairment per percentage point of packet loss — this
//! is the standard simplified coefficient used when no packet-loss
//! concealment algorithm is modelled explicitly.
//!
//! # R-to-MOS mapping
//!
//! ```text
//! MOS = 1                                             for R <= 0
//! MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6            for 0 < R < 100
//! MOS = 4.5                                            for R >= 100
//! ```
//!
//! # Quality scale
//!
//! | MOS range   | Rating    |
//! |-------------|-----------|
//! | >= 4.3      | Excellent |
//! | 4.0 - 4.3   | Good      |
//! | 3.5 - 4.0   | Fair      |
//! | <  3.5      | Poor      |
//!
//! 3.5 is the acceptability floor referenced throughout the Phase 3-5
//! test plan (e.g. "MOS > 3.5 at 50ms/20ms/2% loss").

/// G.711's own codec impairment factor. G.711 is uncompressed toll-quality
/// PCM, so its equipment impairment beyond loss/delay is effectively zero.
pub const CODEC_IE_G711: f64 = 0.0;

/// Delay threshold (ms) above which the steeper conversational-disruption
/// penalty applies (ITU-T G.107).
const DELAY_KNEE_MS: f64 = 177.3;

/// Compute the E-model R-value from network parameters.
///
/// - `one_way_latency_ms`: mouth-to-ear one-way delay in milliseconds.
/// - `loss_pct`: packet loss percentage (0.0-100.0).
/// - `codec_ie`: codec-specific equipment impairment factor
///   (use [`CODEC_IE_G711`] for G.711).
///
/// Returns R in the range 0-100 (values are not clamped here; clamp at
/// the call site or rely on [`r_to_mos`], which clamps internally).
pub fn r_value(one_way_latency_ms: f64, loss_pct: f64, codec_ie: f64) -> f64 {
    const R0: f64 = 94.2;

    let excess_delay = (one_way_latency_ms - DELAY_KNEE_MS).max(0.0);
    let id = 0.024 * one_way_latency_ms + 0.11 * excess_delay;

    let ie = codec_ie + 2.5 * loss_pct;

    R0 - id - ie
}

/// Convert an R-value to a Mean Opinion Score (MOS), clamped to the
/// standard 1.0-4.5 MOS scale.
pub fn r_to_mos(r: f64) -> f64 {
    if r <= 0.0 {
        return 1.0;
    }
    if r >= 100.0 {
        return 4.5;
    }
    1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6
}

/// Human-readable quality rating for a MOS value.
pub fn mos_rating(mos: f64) -> &'static str {
    if mos >= 4.3 { "Excellent" }
    else if mos >= 4.0 { "Good" }
    else if mos >= 3.5 { "Fair" }
    else { "Poor" }
}

/// Convenience: compute MOS directly from network parameters in one call.
///
/// This is what `run_rtp_receiver` calls at the end of a session — it
/// takes the same measurements already extracted from RTCP (jitter,
/// loss) and estimated one-way latency, and returns the final MOS score.
pub fn estimate_mos(one_way_latency_ms: f64, loss_pct: f64, codec_ie: f64) -> f64 {
    r_to_mos(r_value(one_way_latency_ms, loss_pct, codec_ie))
}
