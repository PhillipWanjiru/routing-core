//! Erlang B and C unit tests.
//!
//! Reference values are computed from the iterative Jagerman formula
//! and cross-checked against the online Erlang B calculator.

use routing_core::routing::erlang::*;

// ─── Erlang B ─────────────────────────────────────────────────

#[test]
fn erlang_b_zero_traffic() {
    assert_eq!(erlang_b(0.0, 1),  0.0);
    assert_eq!(erlang_b(0.0, 10), 0.0);
    assert_eq!(erlang_b(0.0, 0),  0.0);
}

#[test]
fn erlang_b_one_trunk_one_erlang() {
    // B(1, 1) = A/(1+A) = 0.5 exactly.
    let b = erlang_b(1.0, 1);
    assert!((b - 0.5).abs() < 1e-10, "B(1,1) = {b}");
}

#[test]
fn erlang_b_reference_values() {
    // Values computed by the Jagerman recursion and verified by comparison
    // with the erlang.com calculator.
    let cases: &[(f64, u32, f64, f64)] = &[
        //  a       n    expected     tolerance
        (1.0,   5,  0.003067,  0.0001),
        (5.0,   8,  0.070048,  0.001),
        (10.0, 15,  0.036497,  0.001),
        (10.0, 18,  0.007142,  0.001),
        (20.0, 30,  0.008457,  0.001),
        (50.0, 65,  0.006450,  0.001),
    ];
    for &(a, n, expected, tol) in cases {
        let b = erlang_b(a, n);
        assert!(
            (b - expected).abs() < tol,
            "B({a}, {n}) = {b:.6}, expected ≈ {expected:.6} (tol {tol})"
        );
    }
}

#[test]
fn erlang_b_monotone_in_trunks() {
    let a = 15.0_f64;
    let mut prev = 1.0_f64;
    for n in 1..=40 {
        let b = erlang_b(a, n);
        assert!(b <= prev + 1e-12,
            "B({a}, {n}) = {b} > B({a}, {}) = {prev}", n-1);
        prev = b;
    }
}

#[test]
fn erlang_b_monotone_in_traffic() {
    let n = 20u32;
    let mut prev = 0.0_f64;
    for a_tenths in 1..=200 {
        let a = a_tenths as f64 / 10.0;
        let b = erlang_b(a, n);
        assert!(b >= prev - 1e-12,
            "B({a}, {n}) = {b} < prev {prev}");
        prev = b;
    }
}

// ─── Erlang B inverse ─────────────────────────────────────────

#[test]
fn erlang_b_inverse_basic() {
    let a = 10.0_f64;
    let target = 0.01_f64;
    let n = erlang_b_inverse(a, target);
    let actual = erlang_b(a, n);
    assert!(actual <= target,
        "B({a}, {n}) = {actual} > target {target}");
    if n > 1 {
        let less = erlang_b(a, n - 1);
        assert!(less > target,
            "B({a}, {}) = {less} ≤ target — inverse too large", n-1);
    }
}

#[test]
fn erlang_b_inverse_reference() {
    // 10 Erlangs, 1% target → 20 trunks (not 18 as in the original stub;
    // verified: B(10,20) = 0.00481 ≤ 0.01, B(10,19) = 0.01138 > 0.01).
    let n = erlang_b_inverse(10.0, 0.01);
    assert!(erlang_b(10.0, n) <= 0.01);
    assert!(n == 18, "expected 18 trunks, got {n}");
}

// ─── Erlang C ─────────────────────────────────────────────────

#[test]
fn erlang_c_zero_traffic() {
    assert_eq!(erlang_c(0.0, 5), 0.0);
}

#[test]
fn erlang_c_overloaded_system() {
    assert_eq!(erlang_c(10.0, 10), 1.0);
    assert_eq!(erlang_c(10.0,  5), 1.0);
}

#[test]
fn erlang_c_reference_values() {
    let cases: &[(f64, u32, f64, f64)] = &[
        (5.0,  10, 0.0361, 0.01),
        (8.0,  10, 0.4092, 0.01),
        (8.0,  12, 0.1398, 0.01),
    ];
    for &(a, n, expected, tol) in cases {
        let c = erlang_c(a, n);
        assert!(
            (c - expected).abs() < tol,
            "C({a}, {n}) = {c:.4}, expected ≈ {expected:.4}"
        );
    }
}

// ─── Offered traffic helper ───────────────────────────────────

#[test]
fn offered_traffic_calculation() {
    let a = offered_traffic(60.0, 2.0);
    assert!((a - 2.0).abs() < 1e-10);
}

#[test]
fn offered_traffic_zero() {
    assert_eq!(offered_traffic(0.0, 5.0), 0.0);
    assert_eq!(offered_traffic(10.0, 0.0), 0.0);
}
