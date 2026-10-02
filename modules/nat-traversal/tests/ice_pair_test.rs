//! ICE candidate pairing tests.
//!
//! `compute_priority` is a private method — the test surface here is
//! `form_candidate_pairs`, the actual public API. Rather than reverse-
//! engineer candidate parameters to force exact small priority values
//! (fragile, and exactly the kind of arithmetic transcription risk this
//! project has hit before), these tests verify the same four properties
//! confirmed in Python against real `Candidate::priority()` outputs:
//! the tie-bit distinguishing role swap, monotonicity, the equal-
//! priority edge case, and (implicitly, since `CandidatePair::priority`
//! is `u64` — compiler-enforced, not something a runtime test can fail
//! to catch) the bit-width fitting.

use nat_traversal::ice::{form_candidate_pairs, Candidate, CandidateType, IceRole};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn v4(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, last)), port)
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()), port)
}

fn host(addr: SocketAddr, local_pref: u16, component: u8) -> Candidate {
    Candidate::new(CandidateType::Host, addr, addr, local_pref, component)
}

// ─── Basic pairing / filtering ─────────────────────────────────────

#[test]
fn forms_the_full_cross_product_of_compatible_candidates() {
    let local = vec![host(v4(1, 5000), 100, 1), host(v4(1, 5001), 200, 1)];
    let remote = vec![host(v4(2, 6000), 100, 1), host(v4(2, 6001), 200, 1), host(v4(2, 6002), 50, 1)];

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    assert_eq!(pairs.len(), 6, "2 local x 3 remote, all compatible, must yield 6 pairs");
}

#[test]
fn empty_local_or_remote_produces_no_pairs() {
    let local = vec![host(v4(1, 5000), 100, 1)];
    let empty: Vec<Candidate> = vec![];

    assert!(form_candidate_pairs(&local, &empty, IceRole::Controlling).is_empty());
    assert!(form_candidate_pairs(&empty, &local, IceRole::Controlling).is_empty());
    assert!(form_candidate_pairs(&empty, &empty, IceRole::Controlling).is_empty());
}

#[test]
fn different_component_ids_never_pair() {
    let local = vec![host(v4(1, 5000), 100, 1)];  // component 1 (RTP)
    let remote = vec![host(v4(2, 6000), 100, 2)]; // component 2 (RTCP)

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    assert!(pairs.is_empty(), "mismatched component IDs must never be paired");
}

#[test]
fn matching_component_ids_do_pair() {
    let local = vec![host(v4(1, 5000), 100, 1)];
    let remote = vec![host(v4(2, 6000), 100, 1)];

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    assert_eq!(pairs.len(), 1);
}

#[test]
fn cross_address_family_candidates_never_pair() {
    let local_v4 = vec![host(v4(1, 5000), 100, 1)];
    let remote_v6 = vec![host(v6(6000), 100, 1)];

    let pairs = form_candidate_pairs(&local_v4, &remote_v6, IceRole::Controlling);
    assert!(pairs.is_empty(), "IPv4 must not pair with IPv6, regardless of matching component");
}

#[test]
fn same_address_family_pairs_normally_alongside_family_filtering() {
    // Mixed-family candidate lists: only the same-family combinations
    // should survive, not zero pairs and not the full cross product.
    let local = vec![host(v4(1, 5000), 100, 1), host(v6(5001), 100, 1)];
    let remote = vec![host(v4(2, 6000), 100, 1), host(v6(6001), 100, 1)];

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    assert_eq!(pairs.len(), 2, "only the v4-v4 and v6-v6 combinations should survive, not all 4");
    for p in &pairs {
        let local_is_v4 = matches!(p.local.transport_addr.ip(), IpAddr::V4(_));
        let remote_is_v4 = matches!(p.remote.transport_addr.ip(), IpAddr::V4(_));
        assert_eq!(local_is_v4, remote_is_v4, "each surviving pair must be same-family");
    }
}

// ─── Sort order ─────────────────────────────────────────────────────

#[test]
fn pairs_are_sorted_by_priority_descending() {
    let local = vec![
        host(v4(1, 5000), 0, 1),
        host(v4(1, 5001), 30000, 1),
        host(v4(1, 5002), 65535, 1),
    ];
    let remote = vec![host(v4(2, 6000), 100, 1)];

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    assert_eq!(pairs.len(), 3);

    for window in pairs.windows(2) {
        assert!(
            window[0].priority >= window[1].priority,
            "check list must be sorted highest-priority-first"
        );
    }
    // The candidate with local_preference=65535 must be first.
    assert_eq!(pairs[0].local.local_preference, 65535);
}

// ─── Foundation ─────────────────────────────────────────────────────

#[test]
fn pair_foundation_is_local_colon_remote() {
    let local = vec![host(v4(1, 5000), 100, 1)];
    let remote = vec![host(v4(2, 6000), 100, 1)];

    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    let expected = format!("{}:{}", pairs[0].local.foundation, pairs[0].remote.foundation);
    assert_eq!(pairs[0].foundation, expected);
}

// ─── The four properties verified independently in Python ─────────

#[test]
fn tie_bit_distinguishes_controlling_from_controlled_for_the_same_pair() {
    // Same two candidates, opposite roles -- mirrors the Python check
    // that swapping which raw value is G vs D changes the tie-bit
    // outcome (the two resulting priorities must differ, and by exactly
    // 1 when the two candidates' raw priorities themselves differ).
    let local_cand = host(v4(1, 5000), 30000, 1);
    let remote_cand = host(v4(2, 6000), 100, 1);
    assert_ne!(
        local_cand.priority(), remote_cand.priority(),
        "test setup requires genuinely different raw priorities"
    );

    let as_controlling = form_candidate_pairs(&[local_cand.clone()], &[remote_cand.clone()], IceRole::Controlling);
    let as_controlled  = form_candidate_pairs(&[local_cand], &[remote_cand], IceRole::Controlled);

    assert_ne!(
        as_controlling[0].priority, as_controlled[0].priority,
        "role must affect pair priority when the two raw priorities differ"
    );
    let diff = as_controlling[0].priority.abs_diff(as_controlled[0].priority);
    assert_eq!(diff, 1, "the only difference between the two roles should be the tie bit");
}

#[test]
fn higher_candidate_priorities_on_both_sides_yield_higher_pair_priority() {
    // Monotonicity: a strictly-better pair on both candidates must never
    // score lower than a strictly-worse pair.
    let low_local = host(v4(1, 5000), 0, 1);
    let low_remote = host(v4(2, 6000), 0, 1);
    let high_local = host(v4(1, 5001), 65535, 1);
    let high_remote = host(v4(2, 6001), 65535, 1);

    let low_pair = form_candidate_pairs(&[low_local], &[low_remote], IceRole::Controlling);
    let high_pair = form_candidate_pairs(&[high_local], &[high_remote], IceRole::Controlling);

    assert!(high_pair[0].priority > low_pair[0].priority);
}

#[test]
fn equal_raw_priorities_on_both_sides_still_produce_a_well_defined_result() {
    // G == D case: two candidates with identical type/local_pref/component
    // (different IP so they're still distinct candidates) must pair
    // without panicking and without needing special-case handling.
    let local_cand = host(v4(1, 5000), 12345, 1);
    let remote_cand = host(v4(2, 6000), 12345, 1);
    assert_eq!(local_cand.priority(), remote_cand.priority(), "test setup requires equal raw priorities");

    let pairs = form_candidate_pairs(&[local_cand], &[remote_cand], IceRole::Controlling);
    assert_eq!(pairs.len(), 1);
    // No assertion on the exact value beyond "it computed something" --
    // the point of this test is the absence of a panic/special case,
    // which a plain successful pairing already demonstrates.
}

#[test]
fn priority_field_type_is_u64_not_u32() {
    // This is somewhat definitionally guaranteed by the struct's field
    // type at compile time, but asserting it here documents the
    // intentional width difference from Candidate::priority()'s u32 --
    // RFC 8445 specifies pair priority as a wider field than individual
    // candidate priority, and a future refactor that accidentally
    // narrowed CandidatePair::priority back to u32 would be a silent
    // regression this test would catch immediately via a compile error,
    // not a runtime failure.
    let local = vec![host(v4(1, 5000), 65535, 1)];
    let remote = vec![host(v4(2, 6000), 65535, 1)];
    let pairs = form_candidate_pairs(&local, &remote, IceRole::Controlling);
    let _: u64 = pairs[0].priority; // compile-time width assertion
}
