//! ICE check-list tests (pruning, ordering, freezing, re-prioritisation), plus
//! the small additions this slice made to `Candidate` and `CandidatePair`, and
//! the randomness source.

use nat_traversal::ice::random::{random_bytes, random_u64, weak_fallback_bytes};
use nat_traversal::ice::{
    form_candidate_pairs, Candidate, CandidatePair, CandidateType, CheckList, IceRole, PairState,
};
use std::net::SocketAddr;

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn host(s: &str, pref: u16) -> Candidate {
    let x = a(s);
    Candidate::new(CandidateType::Host, x, x, pref, 1)
}
fn srflx(public: &str, base: &str, pref: u16) -> Candidate {
    Candidate::new(CandidateType::ServerReflexive, a(public), a(base), pref, 1)
}
fn build(local: &[Candidate], remote: &[Candidate], role: IceRole) -> CheckList {
    CheckList::build(form_candidate_pairs(local, remote, role))
}

// ─── Pruning ───────────────────────────────────────────────────────

#[test]
fn prunes_the_server_reflexive_pair_redundant_with_its_host_base() {
    let h = host("192.168.1.10:5000", 65535);
    let s = srflx("203.0.113.5:40000", "192.168.1.10:5000", 65535);
    let r = host("198.51.100.7:6000", 65535);

    let pairs = form_candidate_pairs(&[h.clone(), s], &[r], IceRole::Controlling);
    assert_eq!(pairs.len(), 2, "the cross product has both pairs");
    let list = CheckList::build(pairs);

    assert_eq!(list.len(), 1, "H->R and S->R send the same packet; only one may remain");
    assert_eq!(list.entries()[0].pair.local, h, "the higher-priority (host) pair survives");
}

#[test]
fn pruning_keeps_the_higher_priority_pair_regardless_of_input_order() {
    let h = host("192.168.1.10:5000", 65535);
    let s = srflx("203.0.113.5:40000", "192.168.1.10:5000", 65535);
    let r = host("198.51.100.7:6000", 65535);

    let mut pairs = form_candidate_pairs(&[h.clone(), s], &[r], IceRole::Controlling);
    pairs.reverse(); // lowest priority first
    let list = CheckList::build(pairs);

    assert_eq!(list.len(), 1);
    assert_eq!(list.entries()[0].pair.local, h);
}

#[test]
fn distinct_remote_addresses_are_not_pruned() {
    let list = build(
        &[host("192.168.1.10:5000", 65535)],
        &[host("198.51.100.7:6000", 65535), host("198.51.100.8:6000", 65535)],
        IceRole::Controlling,
    );
    assert_eq!(list.len(), 2);
}

#[test]
fn distinct_host_ports_on_one_interface_are_not_pruned() {
    let list = build(
        &[host("192.168.1.10:5000", 65535), host("192.168.1.10:5001", 65535)],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    );
    assert_eq!(list.len(), 2, "different ports are different sources, not redundant");
}

#[test]
fn remote_server_reflexive_candidates_are_not_collapsed() {
    // We cannot know a remote candidate's base, so a remote host and a remote
    // server-reflexive candidate are distinct destinations.
    let list = build(
        &[host("192.168.1.10:5000", 65535)],
        &[host("198.51.100.7:6000", 65535), srflx("203.0.113.9:7000", "198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    );
    assert_eq!(list.len(), 2);
}

#[test]
fn empty_input_builds_an_empty_list() {
    let list = CheckList::build(Vec::new());
    assert!(list.is_empty());
    assert!(!list.has_pending());
    assert_eq!(list.next_waiting(), None);
}

// ─── Ordering and identity ─────────────────────────────────────────

#[test]
fn entries_are_sorted_by_priority_descending() {
    let list = build(
        &[host("192.168.1.10:5000", 100), host("192.168.1.11:5000", 65535), host("192.168.1.12:5000", 30000)],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    );
    for w in list.entries().windows(2) {
        assert!(w[0].pair.priority >= w[1].pair.priority);
    }
}

#[test]
fn entry_ids_are_unique_and_lookup_works() {
    let list = build(
        &[host("192.168.1.10:5000", 100), host("192.168.1.11:5000", 200)],
        &[host("198.51.100.7:6000", 65535), host("198.51.100.8:6000", 65535)],
        IceRole::Controlling,
    );
    let mut ids: Vec<usize> = list.entries().iter().map(|e| e.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), list.len());
    for e in list.entries() {
        assert_eq!(list.entry(e.id).unwrap().pair, e.pair);
    }
    assert!(list.entry(9999).is_none());
}

// ─── Freezing ──────────────────────────────────────────────────────

/// Two sockets on one interface share a foundation (type + base IP), so
/// against one remote they form two pairs with the same pair foundation.
fn same_foundation_list(pref_first: u16, pref_second: u16) -> CheckList {
    build(
        &[host("192.168.1.10:5000", pref_first), host("192.168.1.10:5001", pref_second)],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    )
}

#[test]
fn only_one_pair_per_foundation_starts_waiting() {
    let list = same_foundation_list(65535, 100);
    assert_eq!(list.count(PairState::Waiting), 1);
    assert_eq!(list.count(PairState::Frozen), 1);
}

#[test]
fn the_waiting_pair_is_the_highest_priority_in_its_foundation() {
    let list = same_foundation_list(100, 65535); // second socket is the better one
    let waiting = list.entries().iter().find(|e| e.state == PairState::Waiting).unwrap();
    assert_eq!(waiting.pair.local.local_preference, 65535);
}

#[test]
fn distinct_foundations_all_start_waiting() {
    let list = build(
        &[host("192.168.1.10:5000", 65535), host("192.168.1.11:5000", 65535), host("192.168.1.12:5000", 65535)],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    );
    assert_eq!(list.count(PairState::Waiting), 3);
    assert_eq!(list.count(PairState::Frozen), 0);
}

/// Two foundations, two pairs each: A:5000/A:5001 and B:5000/B:5001.
fn two_foundation_list() -> CheckList {
    build(
        &[
            host("192.168.1.10:5000", 65535), host("192.168.1.10:5001", 100),
            host("192.168.1.11:5000", 65534), host("192.168.1.11:5001", 99),
        ],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    )
}

#[test]
fn unfreeze_foundation_releases_only_frozen_pairs_of_that_foundation() {
    let mut list = two_foundation_list();
    assert_eq!(list.count(PairState::Waiting), 2);
    assert_eq!(list.count(PairState::Frozen), 2);

    // Pretend the best A pair is mid-check.
    let a_best = list.entries().iter().find(|e| {
        e.state == PairState::Waiting && e.pair.local.transport_addr == a("192.168.1.10:5000")
    }).unwrap().id;
    let a_foundation = list.entry(a_best).unwrap().pair.foundation.clone();
    list.entry_mut(a_best).unwrap().state = PairState::InProgress;

    list.unfreeze_foundation(&a_foundation);

    let state = |addr: &str| list.entries().iter()
        .find(|e| e.pair.local.transport_addr == a(addr)).unwrap().state;
    assert_eq!(state("192.168.1.10:5000"), PairState::InProgress, "a non-frozen pair must not be touched");
    assert_eq!(state("192.168.1.10:5001"), PairState::Waiting, "same foundation: released");
    assert_eq!(state("192.168.1.11:5001"), PairState::Frozen, "different foundation: still frozen");
}

#[test]
fn unfreeze_highest_releases_the_best_frozen_pair() {
    let mut list = two_foundation_list();
    // Settle every Waiting pair so only Frozen ones remain.
    let waiting: Vec<usize> = list.entries().iter().filter(|e| e.state == PairState::Waiting).map(|e| e.id).collect();
    for id in waiting {
        list.entry_mut(id).unwrap().state = PairState::InProgress;
    }
    let best_frozen = list.entries().iter().find(|e| e.state == PairState::Frozen).unwrap().id;

    assert_eq!(list.unfreeze_highest(), Some(best_frozen));
    assert_eq!(list.entry(best_frozen).unwrap().state, PairState::Waiting);
}

#[test]
fn unfreeze_highest_returns_none_when_nothing_is_frozen() {
    let mut list = build(&[host("192.168.1.10:5000", 1)], &[host("198.51.100.7:6000", 1)], IceRole::Controlling);
    assert_eq!(list.unfreeze_highest(), None);
}

#[test]
fn next_waiting_returns_the_highest_priority_waiting_pair() {
    let list = build(
        &[host("192.168.1.10:5000", 100), host("192.168.1.11:5000", 65535)],
        &[host("198.51.100.7:6000", 65535)],
        IceRole::Controlling,
    );
    let id = list.next_waiting().unwrap();
    assert_eq!(list.entry(id).unwrap().pair.local.local_preference, 65535);
}

#[test]
fn has_pending_tracks_unsettled_pairs() {
    let mut list = build(&[host("192.168.1.10:5000", 1)], &[host("198.51.100.7:6000", 1)], IceRole::Controlling);
    assert!(list.has_pending());
    list.entry_mut(0).unwrap().state = PairState::InProgress;
    assert!(list.has_pending());
    list.entry_mut(0).unwrap().state = PairState::Failed;
    assert!(!list.has_pending());
    list.entry_mut(0).unwrap().state = PairState::Succeeded;
    assert!(!list.has_pending());
}

// ─── Role switch: re-prioritisation ────────────────────────────────

#[test]
fn recompute_priorities_matches_fresh_pairs_and_reorders_when_roles_swap() {
    // L1 and R2 have the higher priority `a`; L2 and R1 the lower `b`. The two
    // "crossed" pairs (L1,R1) and (L2,R2) share min/max, so their priorities
    // differ only by the tie bit — which role decides. A role switch must
    // therefore swap their order.
    let l1 = host("192.168.1.10:5000", 60000);
    let l2 = host("192.168.1.11:5000", 100);
    let r1 = host("198.51.100.1:6000", 100);
    let r2 = host("198.51.100.2:6000", 60000);

    let mut list = build(&[l1.clone(), l2.clone()], &[r1.clone(), r2.clone()], IceRole::Controlling);
    let pos = |list: &CheckList, l: &Candidate, r: &Candidate| list.entries().iter()
        .position(|e| e.pair.local == *l && e.pair.remote == *r).unwrap();

    assert!(pos(&list, &l1, &r1) < pos(&list, &l2, &r2), "as Controlling, (L1,R1) has the tie bit and ranks first");

    list.recompute_priorities(IceRole::Controlled);

    assert!(pos(&list, &l2, &r2) < pos(&list, &l1, &r1), "as Controlled the order must flip");
    for w in list.entries().windows(2) {
        assert!(w[0].pair.priority >= w[1].pair.priority, "still sorted after recompute");
    }
    for e in list.entries() {
        let fresh = CandidatePair::new(e.pair.local.clone(), e.pair.remote.clone(), IceRole::Controlled);
        assert_eq!(e.pair.priority, fresh.priority, "priority must equal a freshly formed pair under the new role");
    }
}

// ─── Candidate / CandidatePair additions ───────────────────────────

#[test]
fn peer_reflexive_priority_best_case_matches_the_python_derivation() {
    assert_eq!(host("192.168.1.10:5000", 65535).peer_reflexive_priority(), 1_862_270_975);
}

#[test]
fn peer_reflexive_priority_uses_own_local_preference_and_component() {
    let c = Candidate::new(CandidateType::Host, a("192.168.1.10:5000"), a("192.168.1.10:5000"), 100, 2);
    assert_eq!(c.peer_reflexive_priority(), 1_845_519_614);
}

#[test]
fn peer_reflexive_priority_equals_a_real_peer_reflexive_candidates_priority() {
    let h = host("192.168.1.10:5000", 4242);
    let prflx = Candidate::new(CandidateType::PeerReflexive, a("203.0.113.9:1"), a("192.168.1.10:5000"), 4242, 1);
    assert_eq!(h.peer_reflexive_priority(), prflx.priority());
}

#[test]
fn peer_reflexive_priority_ignores_the_candidates_own_type() {
    let h = host("192.168.1.10:5000", 7);
    let s = srflx("203.0.113.5:40000", "192.168.1.10:5000", 7);
    assert_eq!(h.peer_reflexive_priority(), s.peer_reflexive_priority());
}

#[test]
fn pair_new_matches_form_candidate_pairs() {
    let l = host("192.168.1.10:5000", 30000);
    let r = host("198.51.100.7:6000", 100);
    for role in [IceRole::Controlling, IceRole::Controlled] {
        let formed = form_candidate_pairs(&[l.clone()], &[r.clone()], role);
        assert_eq!(formed[0], CandidatePair::new(l.clone(), r.clone(), role));
    }
}

#[test]
fn recompute_priority_equals_a_pair_formed_under_the_new_role() {
    let l = host("192.168.1.10:5000", 30000);
    let r = host("198.51.100.7:6000", 100);
    let mut p = CandidatePair::new(l.clone(), r.clone(), IceRole::Controlling);
    p.recompute_priority(IceRole::Controlled);
    assert_eq!(p, CandidatePair::new(l, r, IceRole::Controlled));
}

#[test]
fn recompute_priority_is_idempotent_for_the_same_role() {
    let mut p = CandidatePair::new(host("192.168.1.10:5000", 30000), host("198.51.100.7:6000", 100), IceRole::Controlling);
    let before = p.priority;
    p.recompute_priority(IceRole::Controlling);
    assert_eq!(p.priority, before);
}

// ─── Randomness ────────────────────────────────────────────────────

#[test]
fn random_bytes_have_the_requested_length() {
    assert_eq!(random_bytes::<12>().len(), 12);
    assert_eq!(random_bytes::<1>().len(), 1);
    assert_eq!(random_bytes::<33>().len(), 33);
}

#[test]
fn two_random_draws_differ() {
    assert_ne!(random_bytes::<12>(), random_bytes::<12>());
}

#[test]
fn random_bytes_are_not_constant() {
    assert_ne!(random_bytes::<12>(), [0u8; 12]);
}

#[test]
fn random_u64_draws_are_all_distinct() {
    let draws: std::collections::HashSet<u64> = (0..64).map(|_| random_u64()).collect();
    assert_eq!(draws.len(), 64);
}

#[test]
fn weak_fallback_fills_any_length_and_differs_across_calls() {
    assert_ne!(weak_fallback_bytes::<12>(), weak_fallback_bytes::<12>());
    // Lengths that are not a multiple of 8 exercise the partial final chunk.
    assert_eq!(weak_fallback_bytes::<1>().len(), 1);
    assert_eq!(weak_fallback_bytes::<9>().len(), 9);
    assert_eq!(weak_fallback_bytes::<33>().len(), 33);
}
