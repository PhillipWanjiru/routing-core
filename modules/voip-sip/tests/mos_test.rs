//! ITU-T G.107 E-model / MOS tests.
//!
//! Reference values are computed independently in Python before being
//! written here (same discipline as core/tests/erlang_test.rs) — never
//! "run the Rust code and copy the output."

use voip_sip::rtp::mos::{estimate_mos, mos_rating, r_to_mos, r_value, CODEC_IE_G711};

// ─── R-value reference cases ───────────────────────────────────

#[test]
fn r_value_zero_impairment() {
    // Zero latency, zero loss: R should equal R0 = 94.2 exactly.
    let r = r_value(0.0, 0.0, CODEC_IE_G711);
    assert!((r - 94.2).abs() < 1e-9, "R = {r}, expected 94.2");
}

#[test]
fn r_value_matches_documented_examples() {
    // Documentation §4.8 worked examples: "latency=0ms, jitter=0ms, loss=0%
    // -> MOS≈4.4" and "latency=400ms, loss=5% -> MOS≈2.5".
    let r_ideal = r_value(0.0, 0.0, CODEC_IE_G711);
    let mos_ideal = r_to_mos(r_ideal);
    assert!(
        (mos_ideal - 4.428).abs() < 0.01,
        "ideal-conditions MOS = {mos_ideal:.3}, expected ≈4.428 (docs say ≈4.4)"
    );

    let r_bad = r_value(400.0, 5.0, CODEC_IE_G711);
    let mos_bad = r_to_mos(r_bad);
    assert!(
        (mos_bad - 2.450).abs() < 0.01,
        "degraded-conditions MOS = {mos_bad:.3}, expected ≈2.450 (docs say ≈2.5)"
    );
}

#[test]
fn r_value_below_delay_knee_uses_linear_term_only() {
    // Below the 177.3ms knee, only the 0.024*d term applies — no excess
    // delay penalty. Verify with a value independently computed in Python.
    let r = r_value(50.0, 2.0, CODEC_IE_G711);
    assert!((r - 88.00).abs() < 0.01, "R = {r:.2}, expected ≈88.00");
}

#[test]
fn r_value_above_delay_knee_adds_steep_penalty() {
    // Above 177.3ms, the steeper Id term kicks in. At 400ms this should
    // be visibly worse than what the linear term alone would predict.
    let r_at_knee   = r_value(177.3, 0.0, CODEC_IE_G711);
    let r_past_knee = r_value(400.0, 0.0, CODEC_IE_G711);
    // Id must grow faster than linear past the knee — confirm a large
    // drop over just 222.7ms of additional delay.
    assert!(
        (r_at_knee - r_past_knee) > 5.0,
        "R should drop noticeably past the delay knee: {r_at_knee:.2} -> {r_past_knee:.2}"
    );
}

// ─── R-to-MOS boundary and clamping ─────────────────────────────

#[test]
fn r_to_mos_clamps_negative_r_to_one() {
    // Severe degradation drives R negative; MOS must clamp to 1.0, not
    // continue into negative or undefined territory.
    let r = r_value(1000.0, 50.0, CODEC_IE_G711);
    assert!(r < 0.0, "test setup: R should be negative here, got {r}");
    let mos = r_to_mos(r);
    assert!((mos - 1.0).abs() < 1e-9, "MOS = {mos}, expected exactly 1.0 (floor)");
}

#[test]
fn r_to_mos_clamps_high_r_to_four_point_five() {
    let mos = r_to_mos(150.0); // Above the valid R range.
    assert!((mos - 4.5).abs() < 1e-9, "MOS = {mos}, expected exactly 4.5 (ceiling)");
}

#[test]
fn r_to_mos_at_zero_is_one() {
    assert!((r_to_mos(0.0) - 1.0).abs() < 1e-9);
}

// ─── Monotonicity ────────────────────────────────────────────────

#[test]
fn mos_monotone_non_increasing_in_loss() {
    let mut prev = 5.0;
    for loss in 0..=20 {
        let mos = estimate_mos(20.0, loss as f64, CODEC_IE_G711);
        assert!(
            mos <= prev + 1e-9,
            "MOS increased with more loss at {loss}%: {mos} > {prev}"
        );
        prev = mos;
    }
}

#[test]
fn mos_monotone_non_increasing_in_latency() {
    let mut prev = 5.0;
    for lat_tens in 0..50 {
        let lat = lat_tens as f64 * 10.0;
        let mos = estimate_mos(lat, 0.0, CODEC_IE_G711);
        assert!(
            mos <= prev + 1e-9,
            "MOS increased with more latency at {lat}ms: {mos} > {prev}"
        );
        prev = mos;
    }
}

// ─── Quality rating labels ───────────────────────────────────────

#[test]
fn mos_rating_boundaries() {
    assert_eq!(mos_rating(4.5), "Excellent");
    assert_eq!(mos_rating(4.3), "Excellent");
    assert_eq!(mos_rating(4.29), "Good");
    assert_eq!(mos_rating(4.0), "Good");
    assert_eq!(mos_rating(3.99), "Fair");
    assert_eq!(mos_rating(3.5), "Fair");
    assert_eq!(mos_rating(3.49), "Poor");
    assert_eq!(mos_rating(1.0), "Poor");
}

// ─── The acceptability floor used throughout the test plan ───────

#[test]
fn loopback_conditions_exceed_acceptability_floor() {
    // The documentation's own quality bar: "MOS > 3.5 at 50ms/20ms/2% loss".
    // Loopback conditions (near-zero latency, the 0.00% loss actually
    // measured in the Phase 3 live run) must clear this floor by a wide
    // margin — this is the number `run_rtp_receiver` will now print.
    let mos = estimate_mos(1.0, 0.0, CODEC_IE_G711);
    assert!(
        mos > 3.5,
        "loopback MOS {mos:.3} does not clear the 3.5 acceptability floor"
    );
    assert_eq!(mos_rating(mos), "Excellent");
}

#[test]
fn documented_test_plan_reference_point() {
    // Exactly the condition named in the Phase 3-5 test plan gate:
    // "MOS > 3.5 at 50ms/20ms jitter/2% loss."
    let mos = estimate_mos(50.0, 2.0, CODEC_IE_G711);
    assert!(
        mos > 3.5,
        "MOS {mos:.3} at 50ms/2% loss does not clear the documented 3.5 floor"
    );
}
