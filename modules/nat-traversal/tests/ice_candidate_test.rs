//! ICE candidate priority and foundation tests.
//!
//! Priority values referenced here match, exactly, the independent
//! Python verification run before `candidate.rs` was written — not
//! recomputed from the Rust implementation and then asserted against
//! itself.

use nat_traversal::ice::{Candidate, CandidateType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn addr(ip_last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip_last)), port)
}

fn candidate(ctype: CandidateType, local_pref: u16, component: u8) -> Candidate {
    let a = addr(1, 5000);
    Candidate::new(ctype, a, a, local_pref, component)
}

// ─── Priority: exact values from the Python verification ─────────

#[test]
fn priority_host_local_pref_100_matches_python_verification() {
    let c = candidate(CandidateType::Host, 100, 1);
    assert_eq!(c.priority(), 2_113_955_071);
}

#[test]
fn priority_host_local_pref_200_matches_python_verification() {
    let c = candidate(CandidateType::Host, 200, 1);
    assert_eq!(c.priority(), 2_113_980_671);
}

#[test]
fn priority_higher_local_preference_wins_within_same_type() {
    let low = candidate(CandidateType::Host, 100, 1);
    let high = candidate(CandidateType::Host, 200, 1);
    assert!(high.priority() > low.priority());
}

#[test]
fn priority_component_1_matches_python_verification() {
    let c = candidate(CandidateType::Host, 100, 1);
    assert_eq!(c.priority(), 2_113_955_071);
}

#[test]
fn priority_component_2_matches_python_verification() {
    let c = candidate(CandidateType::Host, 100, 2);
    assert_eq!(c.priority(), 2_113_955_070);
}

#[test]
fn priority_lower_component_id_wins_within_same_type_and_local_pref() {
    let c1 = candidate(CandidateType::Host, 100, 1);
    let c2 = candidate(CandidateType::Host, 100, 2);
    assert!(c1.priority() > c2.priority(), "component 1 (e.g. RTP) must outrank component 2 (RTCP)");
}

#[test]
fn priority_maximum_value_matches_python_verification_and_fits_u32() {
    let c = candidate(CandidateType::Host, 65535, 1);
    assert_eq!(c.priority(), 2_130_706_431);
    assert!(c.priority() < u32::MAX);
}

#[test]
fn priority_host_worst_case_beats_peer_reflexive_best_case() {
    let host_worst = candidate(CandidateType::Host, 0, 255);
    let peer_reflexive_best = candidate(CandidateType::PeerReflexive, 65535, 1);

    assert_eq!(host_worst.priority(), 2_113_929_217);
    assert_eq!(peer_reflexive_best.priority(), 1_862_270_975);
    assert!(host_worst.priority() > peer_reflexive_best.priority());
}

#[test]
fn priority_full_tier_ordering_at_identical_local_pref_and_component() {
    let host = candidate(CandidateType::Host, 30000, 1);
    let peer_reflexive = candidate(CandidateType::PeerReflexive, 30000, 1);
    let server_reflexive = candidate(CandidateType::ServerReflexive, 30000, 1);
    let relayed = candidate(CandidateType::Relayed, 30000, 1);

    assert!(host.priority() > peer_reflexive.priority());
    assert!(peer_reflexive.priority() > server_reflexive.priority());
    assert!(server_reflexive.priority() > relayed.priority());
}

#[test]
fn priority_relayed_is_never_zero_even_at_minimum_parameters() {
    let relayed_min = candidate(CandidateType::Relayed, 0, 255);
    assert_eq!(relayed_min.priority(), 1, "256 - 255 = 1, the component term alone");
}

// ─── Foundation ────────────────────────────────────────────────────

#[test]
fn foundation_same_type_and_base_ip_produces_same_foundation() {
    let base = addr(1, 5000);
    let c1 = Candidate::new(CandidateType::Host, base, base, 100, 1);
    let c2 = Candidate::new(CandidateType::Host, addr(1, 6000), base, 200, 1);
    assert_eq!(c1.foundation, c2.foundation);
}

#[test]
fn foundation_different_type_produces_different_foundation() {
    let base = addr(1, 5000);
    let host = Candidate::new(CandidateType::Host, base, base, 100, 1);
    let relayed = Candidate::new(CandidateType::Relayed, base, base, 100, 1);
    assert_ne!(host.foundation, relayed.foundation);
}

#[test]
fn foundation_different_base_ip_produces_different_foundation() {
    let base_a = addr(1, 5000);
    let base_b = addr(2, 5000);
    let c1 = Candidate::new(CandidateType::Host, base_a, base_a, 100, 1);
    let c2 = Candidate::new(CandidateType::Host, base_b, base_b, 100, 1);
    assert_ne!(c1.foundation, c2.foundation);
}

#[test]
fn foundation_ignores_base_port_by_design() {
    let base_port_a = addr(1, 5000);
    let base_port_b = addr(1, 6000);
    let c1 = Candidate::new(CandidateType::ServerReflexive, addr(9, 1000), base_port_a, 100, 1);
    let c2 = Candidate::new(CandidateType::ServerReflexive, addr(9, 1000), base_port_b, 100, 1);
    assert_eq!(c1.foundation, c2.foundation, "foundation must key on base IP, not base port");
}

#[test]
fn foundation_cannot_drift_from_the_candidate_that_produced_it() {
    let base = addr(1, 5000);
    let c = Candidate::new(CandidateType::Host, base, base, 100, 1);
    let expected = format!("{:?}-{}", CandidateType::Host, base.ip());
    assert_eq!(c.foundation, expected);
}
