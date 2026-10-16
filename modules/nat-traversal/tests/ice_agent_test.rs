//! ICE connectivity-check agent tests — initiator side.
//!
//! Time is virtual: every call passes an explicit `Instant` (`t0 + n ms`), so
//! timing assertions are exact and nothing sleeps. The "remote peer" is
//! scripted from the already-verified check codec (`parse_check_request` /
//! `build_check_*_response`), so these tests exercise the agent against
//! messages the codec tests proved byte-exact.

use nat_traversal::ice::{
    build_check_error_response, build_check_success_response, parse_check_request, Candidate,
    CandidatePair, CandidateType, ChecklistState, IceAction, IceAgent, IceConfig, IceCredentials,
    IceRole, Nomination, PairState, ParsedCheckRequest,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const L_UFRAG: &str = "lfrg";
const L_PWD: &str = "local-password-0123456789";
const R_UFRAG: &str = "rfrg";
const R_PWD: &str = "remote-password-0123456789";
const TIE: u64 = 0x0102_0304_0506_0708;

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
fn host(s: &str, pref: u16) -> Candidate {
    let x = a(s);
    Candidate::new(CandidateType::Host, x, x, pref, 1)
}
fn srflx(public: &str, base: &str, pref: u16) -> Candidate {
    Candidate::new(CandidateType::ServerReflexive, a(public), a(base), pref, 1)
}
fn cfg(ta: u64, rto: u64, rc: u32, rm: u32) -> IceConfig {
    IceConfig {
        ta: ms(ta), min_rto: ms(rto), max_transmissions: rc, final_wait_multiplier: rm,
        nomination: Nomination::Never,
    }
}

struct Rig {
    agent: IceAgent,
    t0: Instant,
    /// The last time passed to `poll`, used as "now" for deliveries.
    now_ms: u64,
}
impl Rig {
    fn at(&self, n: u64) -> Instant {
        self.t0 + ms(n)
    }
    fn poll(&mut self, n: u64) -> Vec<IceAction> {
        self.now_ms = n;
        let t = self.at(n);
        self.agent.poll(t)
    }
    fn deliver(&mut self, from: &str, to: &str, raw: &[u8]) -> Vec<IceAction> {
        let t = self.at(self.now_ms);
        self.agent.handle_datagram(a(from), a(to), raw, t)
    }
}

fn rig_with(local: Vec<Candidate>, remote: Vec<Candidate>, role: IceRole, config: IceConfig) -> Rig {
    let t0 = Instant::now();
    let agent = IceAgent::new(
        config,
        role,
        TIE,
        IceCredentials { ufrag: L_UFRAG.into(), password: L_PWD.into() },
        IceCredentials { ufrag: R_UFRAG.into(), password: R_PWD.into() },
        local,
        remote,
        t0,
    );
    Rig { agent, t0, now_ms: 0 }
}

/// A one-pair rig with timers short enough to reason about: Ta 10, RTO 100.
fn single() -> Rig {
    rig_with(vec![host("192.168.1.10:5000", 65535)], vec![host("198.51.100.7:6000", 65535)],
             IceRole::Controlling, cfg(10, 100, 7, 16))
}

/// Two local hosts on different interfaces (so different foundations) against
/// one remote. A is the higher-priority one.
fn two_pairs() -> Rig {
    rig_with(
        vec![host("192.168.1.10:5000", 65535), host("192.168.1.11:5000", 100)],
        vec![host("198.51.100.7:6000", 100)],
        IceRole::Controlling, cfg(10, 100, 7, 16),
    )
}

const A_ADDR: &str = "192.168.1.10:5000";
const B_ADDR: &str = "192.168.1.11:5000";
const R_ADDR: &str = "198.51.100.7:6000";

fn parts(act: &IceAction) -> (SocketAddr, SocketAddr, &[u8]) {
    let IceAction::Send { from, to, data } = act;
    (*from, *to, data.as_slice())
}
fn data_of(acts: &[IceAction]) -> Vec<u8> {
    parts(&acts[0]).2.to_vec()
}
/// Validate a datagram the agent emitted exactly as a real peer would.
fn parse_check(data: &[u8]) -> ParsedCheckRequest {
    parse_check_request(data, R_UFRAG, R_PWD.as_bytes()).expect("the agent must emit a valid check")
}
fn success_for(data: &[u8], observed: &str) -> Vec<u8> {
    build_check_success_response(&parse_check(data).txn_id, a(observed), R_PWD.as_bytes())
}
fn conflict_for(data: &[u8]) -> Vec<u8> {
    build_check_error_response(&parse_check(data).txn_id, 487, "Role Conflict", Some(R_PWD.as_bytes()))
}
fn state_of(agent: &IceAgent, local: &str) -> PairState {
    agent.checklist().entries().iter()
        .find(|e| e.pair.local.transport_addr == a(local))
        .expect("entry for that local address")
        .state
}

// ─── Starting checks ───────────────────────────────────────────────

#[test]
fn first_poll_sends_a_valid_check_for_the_best_pair() {
    let mut r = single();
    let acts = r.poll(0);
    assert_eq!(acts.len(), 1);
    let (from, to, data) = parts(&acts[0]);
    assert_eq!(from, a(A_ADDR), "a check leaves from the local candidate's base");
    assert_eq!(to, a(R_ADDR));
    let p = parse_check(data);
    assert_eq!(p.remote_ufrag, L_UFRAG, "the check identifies its sender by our ufrag");
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
}

#[test]
fn check_advertises_peer_reflexive_priority_role_and_tie_breaker() {
    let mut r = single();
    let p = parse_check(&data_of(&r.poll(0)));
    assert_eq!(p.priority, 1_862_270_975, "host, local preference 65535 -> peer-reflexive priority");
    assert_eq!(p.sender_role, IceRole::Controlling);
    assert_eq!(p.tie_breaker, TIE);
    assert!(!p.use_candidate, "nomination is a later slice; ordinary checks never set USE-CANDIDATE");
}

#[test]
fn a_controlled_agent_sends_the_controlled_role() {
    let mut r = rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlled, cfg(10, 100, 7, 16));
    let p = parse_check(&data_of(&r.poll(0)));
    assert_eq!(p.sender_role, IceRole::Controlled);
    assert!(!p.use_candidate);
}

#[test]
fn every_check_gets_a_distinct_transaction_id() {
    let mut r = two_pairs();
    let t1 = parse_check(&data_of(&r.poll(0))).txn_id;
    let t2 = parse_check(&data_of(&r.poll(10))).txn_id;
    assert_ne!(t1, t2);
}

#[test]
fn new_checks_are_paced_by_ta() {
    let mut r = two_pairs();
    assert_eq!(r.poll(0).len(), 1);
    assert!(r.poll(9).is_empty(), "one millisecond early: no new check");
    assert_eq!(r.poll(10).len(), 1, "exactly Ta later: the next check");
}

#[test]
fn checks_follow_pair_priority_order() {
    let mut r = rig_with(
        vec![host("192.168.1.10:5000", 100), host("192.168.1.11:5000", 30000), host("192.168.1.12:5000", 65535)],
        vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16),
    );
    let order: Vec<SocketAddr> = (0..3).map(|i| parts(&r.poll(i * 10)[0]).0).collect();
    assert_eq!(order, vec![a("192.168.1.12:5000"), a("192.168.1.11:5000"), a("192.168.1.10:5000")]);
}

#[test]
fn a_frozen_pair_is_released_when_nothing_is_waiting() {
    // Two sockets on one interface share a foundation: one Waiting, one Frozen.
    let mut r = rig_with(
        vec![host("192.168.1.10:5000", 65535), host("192.168.1.10:5001", 100)],
        vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16),
    );
    assert_eq!(parts(&r.poll(0)[0]).0, a("192.168.1.10:5000"));
    assert_eq!(state_of(&r.agent, "192.168.1.10:5001"), PairState::Frozen);
    // No Waiting pair remains and the first has not succeeded: the Frozen one
    // is released rather than leaving the list stuck.
    assert_eq!(parts(&r.poll(10)[0]).0, a("192.168.1.10:5001"));
}

#[test]
fn no_new_checks_start_once_every_pair_has_started() {
    let mut r = two_pairs();
    r.poll(0);
    r.poll(10);
    for t in [20, 30, 40, 50] {
        assert!(r.poll(t).is_empty(), "nothing left to start and no retransmit due before RTO ({t}ms)");
    }
}

#[test]
fn an_empty_check_list_fails_immediately() {
    let mut r = rig_with(vec![], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16));
    assert_eq!(r.agent.state(), ChecklistState::Failed);
    assert!(r.poll(0).is_empty());
}

#[test]
fn garbage_datagrams_are_ignored() {
    let mut r = single();
    r.poll(0);
    assert!(r.deliver(R_ADDR, A_ADDR, &[0xFF; 3]).is_empty());
    assert!(r.deliver(R_ADDR, A_ADDR, &[]).is_empty());
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
}

// ─── next_wakeup ───────────────────────────────────────────────────

#[test]
fn next_wakeup_before_any_poll_is_the_start_instant() {
    let r = single();
    assert_eq!(r.agent.next_wakeup(), Some(r.at(0)));
}

#[test]
fn next_wakeup_after_the_only_check_is_its_retransmission() {
    let mut r = single();
    r.poll(0);
    assert_eq!(r.agent.next_wakeup(), Some(r.at(100)));
}

#[test]
fn next_wakeup_is_the_earliest_of_pacing_and_retransmission() {
    let mut r = two_pairs();
    r.poll(0);
    assert_eq!(r.agent.next_wakeup(), Some(r.at(10)), "the next check (Ta) comes before the RTO");
}

#[test]
fn next_wakeup_is_none_when_idle() {
    let mut r = single();
    let acts = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&acts), A_ADDR));
    assert_eq!(r.agent.next_wakeup(), None);
}

// ─── Retransmission and timeout ────────────────────────────────────

#[test]
fn retransmits_identical_bytes_with_exponential_backoff() {
    let mut r = single(); // RTO 100
    let first = data_of(&r.poll(0));
    assert!(r.poll(99).is_empty());
    for (due, quiet_until) in [(100, 299), (300, 699), (700, 1499)] {
        let acts = r.poll(due);
        assert_eq!(acts.len(), 1, "retransmission due at {due}ms");
        assert_eq!(parts(&acts[0]).2, &first[..], "a retransmission must be byte-identical");
        assert!(r.poll(quiet_until).is_empty(), "interval must have doubled: quiet until {quiet_until}ms");
    }
}

#[test]
fn default_timers_follow_the_rfc_5389_schedule() {
    // Sends at 0, 500, 1500, 3500, 7500, 15500, 31500 ms; failure at 39500 ms.
    // Both lists were derived independently in Python from the doubling rule.
    let mut r = rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, IceConfig::default());
    let first = data_of(&r.poll(0));
    for t in [500u64, 1500, 3500, 7500, 15_500, 31_500] {
        assert!(r.poll(t - 1).is_empty(), "no send at {}ms", t - 1);
        let acts = r.poll(t);
        assert_eq!(acts.len(), 1, "send at {t}ms");
        assert_eq!(parts(&acts[0]).2, &first[..]);
    }
    assert!(r.poll(39_499).is_empty());
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress, "still waiting one ms before the deadline");
    assert!(r.poll(39_500).is_empty(), "no seventh retransmission: Rc = 7 total");
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
    assert_eq!(r.agent.state(), ChecklistState::Failed);
}

#[test]
fn the_final_transmission_is_followed_by_a_wait_then_failure() {
    // Rc=3, Rm=4, RTO=100: sends at 0, 100, 300; then wait 4*100 -> fail at 700.
    let mut r = rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 3, 4));
    r.poll(0);
    assert_eq!(r.poll(100).len(), 1);
    assert_eq!(r.poll(300).len(), 1);
    assert!(r.poll(699).is_empty());
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
    r.poll(700);
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
}

#[test]
fn rto_scales_with_the_number_of_pending_pairs() {
    // 12 pairs pending, Ta 100 ms -> RTO = max(500, 100*12) = 1200 ms. Without
    // the scaling the first check would retransmit at 500 ms.
    let local: Vec<Candidate> = (1..=12u16)
        .map(|i| host(&format!("192.168.1.{}:5000", 10 + i), 65535 - i))
        .collect();
    let mut r = rig_with(local, vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(100, 500, 7, 16));

    let first = data_of(&r.poll(0));
    for t in (100..=1100).step_by(100) {
        let acts = r.poll(t);
        assert!(
            acts.iter().all(|x| parts(x).2 != &first[..]),
            "first check retransmitted early at {t}ms: RTO was not scaled"
        );
    }
    let acts = r.poll(1200);
    assert_eq!(acts.iter().filter(|x| parts(x).2 == &first[..]).count(), 1, "retransmit exactly at 1200ms");
}

#[test]
fn a_timeout_fails_only_that_pair_and_the_list_fails_when_all_settle() {
    // Rc=1, Rm=1, RTO=100: A starts at 0 and times out at 100; B starts at 10, times out at 110.
    let mut r = rig_with(
        vec![host(A_ADDR, 65535), host(B_ADDR, 100)], vec![host(R_ADDR, 100)],
        IceRole::Controlling, cfg(10, 100, 1, 1),
    );
    r.poll(0);
    r.poll(10);
    r.poll(100);
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
    assert_eq!(r.agent.state(), ChecklistState::Running, "B is still pending, so the list has not failed");
    r.poll(110);
    assert_eq!(state_of(&r.agent, B_ADDR), PairState::Failed);
    assert_eq!(r.agent.state(), ChecklistState::Failed);
}

// ─── Success handling ──────────────────────────────────────────────

#[test]
fn success_creates_a_valid_pair_and_stops_retransmission() {
    let mut r = single();
    let acts = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&acts), A_ADDR));

    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Succeeded);
    let valid = r.agent.valid_pairs();
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0].pair.local.transport_addr, a(A_ADDR));
    assert_eq!(valid[0].pair.remote.transport_addr, a(R_ADDR));
    assert!(r.poll(100).is_empty(), "no retransmission after the answer");
    assert!(r.poll(10_000).is_empty());
    assert_eq!(r.agent.state(), ChecklistState::Running, "awaiting nomination, not failed");
}

#[test]
fn success_releases_pairs_sharing_the_foundation() {
    let mut r = rig_with(
        vec![host("192.168.1.10:5000", 65535), host("192.168.1.10:5001", 100)],
        vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16),
    );
    let acts = r.poll(0);
    assert_eq!(state_of(&r.agent, "192.168.1.10:5001"), PairState::Frozen);
    r.deliver(R_ADDR, "192.168.1.10:5000", &success_for(&data_of(&acts), "192.168.1.10:5000"));
    assert_eq!(state_of(&r.agent, "192.168.1.10:5001"), PairState::Waiting);
    assert_eq!(parts(&r.poll(10)[0]).0, a("192.168.1.10:5001"));
}

#[test]
fn a_mapped_address_matching_another_known_candidate_uses_that_candidate() {
    // H and its server-reflexive S: pruning leaves only the H pair. The peer
    // sees us as S (the NAT mapping we already knew), so the valid pair is
    // (S, R) — no new candidate invented.
    let h = host(A_ADDR, 65535);
    let s = srflx("203.0.113.5:40000", A_ADDR, 65535);
    let mut r = rig_with(vec![h, s.clone()], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16));
    assert_eq!(r.agent.checklist().len(), 1);

    let acts = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&acts), "203.0.113.5:40000"));

    assert_eq!(r.agent.valid_pairs()[0].pair.local, s);
    assert_eq!(r.agent.local_candidates().len(), 2, "no peer-reflexive candidate should be added");
}

#[test]
fn an_unknown_mapped_address_becomes_a_peer_reflexive_candidate() {
    let mut r = single();
    let acts = r.poll(0);
    let sent = parse_check(&data_of(&acts));
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&acts), "203.0.113.99:41000"));

    let local = &r.agent.valid_pairs()[0].pair.local;
    assert_eq!(local.candidate_type, CandidateType::PeerReflexive);
    assert_eq!(local.transport_addr, a("203.0.113.99:41000"));
    assert_eq!(local.base_addr, a(A_ADDR), "based on the socket the check left from");
    assert_eq!(local.priority(), sent.priority, "its priority must equal the PRIORITY the check advertised");
    assert_eq!(r.agent.local_candidates().len(), 2);
}

#[test]
fn repeat_mappings_reuse_the_learned_peer_reflexive_candidate() {
    // Two sockets whose checks are both mapped to the same public address: the
    // first learns a peer-reflexive candidate, the second must find and reuse
    // it, and the two valid pairs are the same path — so there is only one.
    let mut r = rig_with(
        vec![host("192.168.1.10:5000", 65535), host("192.168.1.10:5001", 100)],
        vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16),
    );
    let first = r.poll(0);
    r.deliver(R_ADDR, "192.168.1.10:5000", &success_for(&data_of(&first), "203.0.113.99:41000"));
    let second = r.poll(10);
    r.deliver(R_ADDR, "192.168.1.10:5001", &success_for(&data_of(&second), "203.0.113.99:41000"));

    assert_eq!(r.agent.valid_pairs().len(), 1, "identical paths must not be listed twice");
    let prflx = r.agent.local_candidates().iter().filter(|c| c.candidate_type == CandidateType::PeerReflexive).count();
    assert_eq!(prflx, 1, "the second mapping must reuse the first learned candidate");
}

#[test]
fn valid_pairs_are_ordered_best_first() {
    let mut r = two_pairs();
    let a_check = r.poll(0);
    let b_check = r.poll(10);
    // Answer the lower-priority pair first, to prove ordering is by priority and not arrival.
    r.deliver(R_ADDR, B_ADDR, &success_for(&data_of(&b_check), B_ADDR));
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&a_check), A_ADDR));
    let valid = r.agent.valid_pairs();
    assert_eq!(valid.len(), 2);
    assert_eq!(valid[0].pair.local.transport_addr, a(A_ADDR));
    assert!(valid[0].pair.priority >= valid[1].pair.priority);
}

// ─── Responses that must not be believed ───────────────────────────

#[test]
fn a_response_from_the_wrong_source_fails_the_pair() {
    let mut r = single();
    let acts = r.poll(0);
    r.deliver("198.51.100.8:6000", A_ADDR, &success_for(&data_of(&acts), A_ADDR));
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
    assert!(r.agent.valid_pairs().is_empty(), "an asymmetric response must not create a valid pair");
    assert_eq!(r.agent.state(), ChecklistState::Failed);
}

#[test]
fn a_response_to_the_wrong_local_address_fails_the_pair() {
    let mut r = single();
    let acts = r.poll(0);
    r.deliver(R_ADDR, "192.168.1.10:5999", &success_for(&data_of(&acts), A_ADDR));
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
    assert!(r.agent.valid_pairs().is_empty());
}

#[test]
fn a_response_with_bad_integrity_is_ignored_and_the_transaction_continues() {
    let mut r = single();
    let acts = r.poll(0);
    let txn = parse_check(&data_of(&acts)).txn_id;
    let forged = build_check_success_response(&txn, a(A_ADDR), b"attacker-guess-0123456789");

    assert!(r.deliver(R_ADDR, A_ADDR, &forged).is_empty());
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress, "a forged response must not end the check");
    assert!(r.agent.valid_pairs().is_empty());
    assert_eq!(r.poll(100).len(), 1, "it keeps retransmitting");

    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&acts), A_ADDR));
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Succeeded, "and the genuine answer still works");
}

#[test]
fn a_response_with_a_bad_fingerprint_is_ignored() {
    let mut r = single();
    let acts = r.poll(0);
    let mut bad = success_for(&data_of(&acts), A_ADDR);
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    r.deliver(R_ADDR, A_ADDR, &bad);
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
}

#[test]
fn a_response_for_an_unknown_transaction_is_ignored() {
    let mut r = single();
    r.poll(0);
    let stray = build_check_success_response(&[9u8; 12], a(A_ADDR), R_PWD.as_bytes());
    assert!(r.deliver(R_ADDR, A_ADDR, &stray).is_empty());
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
    assert!(r.agent.valid_pairs().is_empty());
}

#[test]
fn a_non_role_conflict_error_fails_the_pair() {
    let mut r = single();
    let acts = r.poll(0);
    let txn = parse_check(&data_of(&acts)).txn_id;
    r.deliver(R_ADDR, A_ADDR, &build_check_error_response(&txn, 401, "Unauthorized", None));
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Failed);
    assert_eq!(r.agent.state(), ChecklistState::Failed);
}

// ─── Role conflict (487) ───────────────────────────────────────────

#[test]
fn an_authenticated_role_conflict_switches_role_and_retries_the_pair() {
    let mut r = two_pairs();
    let first = r.poll(0); // check on A
    let txn1 = parse_check(&data_of(&first)).txn_id;
    assert_eq!(r.agent.role(), IceRole::Controlling);

    r.deliver(R_ADDR, A_ADDR, &conflict_for(&data_of(&first)));
    assert_eq!(r.agent.role(), IceRole::Controlled, "an authenticated 487 flips the role");
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Waiting, "and queues the pair for a retry");

    // The retry (a triggered check) goes ahead of the ordinary check for B.
    let retry = r.poll(10);
    assert_eq!(parts(&retry[0]).0, a(A_ADDR));
    let p = parse_check(&data_of(&retry));
    assert_eq!(p.sender_role, IceRole::Controlled, "retried under the new role");
    assert_eq!(p.tie_breaker, TIE, "the tie-breaker is not regenerated");
    assert_ne!(p.txn_id, txn1, "a retry is a new transaction");
}

#[test]
fn concurrent_role_conflicts_switch_the_role_only_once() {
    let mut r = two_pairs();
    let on_a = r.poll(0);
    let on_b = r.poll(10); // both in flight, both sent as Controlling

    r.deliver(R_ADDR, A_ADDR, &conflict_for(&data_of(&on_a)));
    assert_eq!(r.agent.role(), IceRole::Controlled);
    // B's 487 is the *same* collision, answering a request sent under the old
    // role. Switching again would flip back to Controlling and re-create it.
    r.deliver(R_ADDR, B_ADDR, &conflict_for(&data_of(&on_b)));
    assert_eq!(r.agent.role(), IceRole::Controlled, "a second 487 from the same collision must not switch back");

    assert_eq!(state_of(&r.agent, A_ADDR), PairState::Waiting);
    assert_eq!(state_of(&r.agent, B_ADDR), PairState::Waiting);
    let retry_a = parse_check(&data_of(&r.poll(20)));
    let retry_b = parse_check(&data_of(&r.poll(30)));
    assert_eq!(retry_a.sender_role, IceRole::Controlled);
    assert_eq!(retry_b.sender_role, IceRole::Controlled);
}

#[test]
fn a_forged_role_conflict_is_ignored_and_the_transaction_continues() {
    let mut r = single();
    let acts = r.poll(0);
    let txn = parse_check(&data_of(&acts)).txn_id;
    let forged = build_check_error_response(&txn, 487, "Role Conflict", Some(b"attacker-guess-0123456789"));

    r.deliver(R_ADDR, A_ADDR, &forged);
    assert_eq!(r.agent.role(), IceRole::Controlling, "an unauthenticated 487 must not flip our role");
    assert_eq!(state_of(&r.agent, A_ADDR), PairState::InProgress);
    assert_eq!(r.poll(100).len(), 1, "the real transaction is still retransmitting");
}

#[test]
fn a_role_switch_reprioritises_the_check_list_and_valid_pairs() {
    // A: pref 65535, B and R: pref 100, so G and D differ and role matters.
    let mut r = two_pairs();
    let on_a = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&on_a), A_ADDR)); // valid pair (A, R)
    let before = r.agent.valid_pairs()[0].pair.priority;

    let on_b = r.poll(10);
    r.deliver(R_ADDR, B_ADDR, &conflict_for(&data_of(&on_b))); // flips to Controlled
    assert_eq!(r.agent.role(), IceRole::Controlled);

    let valid = &r.agent.valid_pairs()[0].pair;
    let fresh = CandidatePair::new(valid.local.clone(), valid.remote.clone(), IceRole::Controlled);
    assert_eq!(valid.priority, fresh.priority, "valid pair priority must be recomputed for the new role");
    assert_ne!(valid.priority, before, "and it must actually have changed");

    for e in r.agent.checklist().entries() {
        let fresh = CandidatePair::new(e.pair.local.clone(), e.pair.remote.clone(), IceRole::Controlled);
        assert_eq!(e.pair.priority, fresh.priority, "every check-list entry must be recomputed too");
    }
}
