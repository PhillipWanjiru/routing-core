//! ICE agent, responder side: answering incoming checks, triggered checks,
//! remote peer-reflexive candidates, and role-conflict resolution.
//!
//! Virtual time and a scripted peer, as in `ice_agent_test`. Here the peer
//! *sends* checks to the agent, built with the codec whose tests proved it
//! byte-exact against an independent Python oracle.

use nat_traversal::ice::{
    build_check_request, build_check_success_response, parse_check_request, parse_check_response,
    Candidate, CandidatePair, CandidateType, CheckRequestParams, CheckResponse, ChecklistState,
    IceAction, IceAgent, IceConfig, IceCredentials, IceRole, Nomination, PairState, ParsedCheckRequest,
};
use nat_traversal::stun::{
    attributes::{ATTR_ICE_CONTROLLED, ATTR_USERNAME},
    builder::{build_attribute, build_message, encode_tie_breaker},
    fingerprint::append_fingerprint,
    integrity::append_integrity,
    parser::{MessageClass, Method},
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const L_UFRAG: &str = "lfrg";
const L_PWD: &str = "local-password-0123456789";
const R_UFRAG: &str = "rfrg";
const R_PWD: &str = "remote-password-0123456789";
const TIE: u64 = 0x0102_0304_0506_0708;
const PEER_PRIO: u32 = 1_862_270_975;

const A_ADDR: &str = "192.168.1.10:5000";
const B_ADDR: &str = "192.168.1.11:5000";
const R_ADDR: &str = "198.51.100.7:6000";
const R2_ADDR: &str = "198.51.100.8:6000";
const STRANGER: &str = "198.51.100.99:7000";

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
        config, role, TIE,
        IceCredentials { ufrag: L_UFRAG.into(), password: L_PWD.into() },
        IceCredentials { ufrag: R_UFRAG.into(), password: R_PWD.into() },
        local, remote, t0,
    );
    Rig { agent, t0, now_ms: 0 }
}

/// One pair, agent is Controlling: the usual subject.
fn single() -> Rig {
    rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 7, 16))
}
fn single_as(role: IceRole) -> Rig {
    rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], role, cfg(10, 100, 7, 16))
}
fn two_pairs() -> Rig {
    rig_with(
        vec![host(A_ADDR, 65535), host(B_ADDR, 100)], vec![host(R_ADDR, 100)],
        IceRole::Controlling, cfg(10, 100, 7, 16),
    )
}

fn parts(act: &IceAction) -> (SocketAddr, SocketAddr, &[u8]) {
    let IceAction::Send { from, to, data } = act;
    (*from, *to, data.as_slice())
}
fn data_of(acts: &[IceAction]) -> Vec<u8> {
    parts(&acts[0]).2.to_vec()
}
fn parse_check(data: &[u8]) -> ParsedCheckRequest {
    parse_check_request(data, R_UFRAG, R_PWD.as_bytes()).expect("the agent must emit a valid check")
}
fn state_of(agent: &IceAgent, local: &str, remote: &str) -> PairState {
    agent.checklist().entries().iter()
        .find(|e| e.pair.local.transport_addr == a(local) && e.pair.remote.transport_addr == a(remote))
        .expect("entry")
        .state
}
fn success_for(data: &[u8], observed: &str) -> Vec<u8> {
    build_check_success_response(&parse_check(data).txn_id, a(observed), R_PWD.as_bytes())
}

// The peer's checks to us: USERNAME is "<our ufrag>:<their ufrag>", signed with OUR password.
fn peer_request_with(role: IceRole, tie: u64, priority: u32, txn: [u8; 12], password: &[u8]) -> Vec<u8> {
    build_check_request(&CheckRequestParams {
        txn_id: txn, username: "lfrg:rfrg", password, priority, role, tie_breaker: tie, use_candidate: false,
    })
}
fn peer_request(role: IceRole, tie: u64, txn: [u8; 12]) -> Vec<u8> {
    peer_request_with(role, tie, PEER_PRIO, txn, L_PWD.as_bytes())
}
/// Parse what the agent sent back, with the key the peer would use (our password).
fn answer(acts: &[IceAction], txn: &[u8; 12]) -> CheckResponse {
    parse_check_response(parts(&acts[0]).2, txn, L_PWD.as_bytes()).expect("a well-formed reply")
}

// ─── Answering ─────────────────────────────────────────────────────

#[test]
fn a_valid_request_is_answered_with_a_signed_success_response() {
    let mut r = single();
    let txn = [0x11; 12];
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, txn));
    assert_eq!(acts.len(), 1);
    let (from, to, _) = parts(&acts[0]);
    assert_eq!(from, a(A_ADDR), "the reply leaves from the address the request arrived on");
    assert_eq!(to, a(R_ADDR), "and goes back to its source");
    assert!(matches!(answer(&acts, &txn), CheckResponse::Success { .. }));
}

#[test]
fn the_response_reports_the_requests_observed_source() {
    let mut r = single();
    let txn = [0x12; 12];
    let acts = r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlled, 5, txn));
    assert_eq!(answer(&acts, &txn), CheckResponse::Success { mapped: a(STRANGER) });
}

#[test]
fn a_request_with_the_wrong_password_gets_an_unsigned_401() {
    let mut r = single();
    let txn = [0x13; 12];
    let forged = peer_request_with(IceRole::Controlled, 5, PEER_PRIO, txn, b"attacker-guess-0123456789");
    let acts = r.deliver(R_ADDR, A_ADDR, &forged);
    assert_eq!(acts.len(), 1);
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 401, authenticated: false });
}

#[test]
fn a_request_addressed_to_another_ufrag_gets_401() {
    let mut r = single();
    let txn = [0x14; 12];
    let raw = build_check_request(&CheckRequestParams {
        txn_id: txn, username: "other:rfrg", password: L_PWD.as_bytes(), priority: PEER_PRIO,
        role: IceRole::Controlled, tie_breaker: 5, use_candidate: false,
    });
    let acts = r.deliver(R_ADDR, A_ADDR, &raw);
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 401, authenticated: false });
}

#[test]
fn an_authenticated_but_malformed_request_gets_a_signed_400() {
    // Valid username, integrity and fingerprint, but no PRIORITY attribute.
    let mut r = single();
    let txn = [0x15; 12];
    let mut attrs = build_attribute(ATTR_USERNAME, b"lfrg:rfrg");
    attrs.extend_from_slice(&build_attribute(ATTR_ICE_CONTROLLED, &encode_tie_breaker(5)));
    let mut raw = build_message(MessageClass::Request, Method::Binding, &txn, &attrs);
    append_integrity(&mut raw, L_PWD.as_bytes());
    append_fingerprint(&mut raw);

    let acts = r.deliver(R_ADDR, A_ADDR, &raw);
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 400, authenticated: true });
}

#[test]
fn traffic_that_is_not_ice_gets_no_reply() {
    let mut r = single();
    // A plain STUN Binding request: no fingerprint, so not STUN-for-ICE.
    let plain = build_message(MessageClass::Request, Method::Binding, &[0x16; 12], &[]);
    assert!(r.deliver(R_ADDR, A_ADDR, &plain).is_empty());
    // A different STUN method entirely.
    let alloc = build_message(MessageClass::Request, Method::Allocate, &[0x17; 12], &[]);
    assert!(r.deliver(R_ADDR, A_ADDR, &alloc).is_empty());
    assert!(r.deliver(R_ADDR, A_ADDR, &[0xFF; 4]).is_empty());
}

#[test]
fn a_request_with_a_bad_fingerprint_gets_no_reply() {
    let mut r = single();
    let mut raw = peer_request(IceRole::Controlled, 5, [0x18; 12]);
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    assert!(r.deliver(R_ADDR, A_ADDR, &raw).is_empty());
}

#[test]
fn an_unauthenticated_request_creates_nothing() {
    let mut r = single();
    let forged = peer_request_with(IceRole::Controlled, 5, PEER_PRIO, [0x19; 12], b"attacker-guess-0123456789");
    r.deliver(STRANGER, A_ADDR, &forged);

    assert_eq!(r.agent.remote_candidates().len(), 1, "no remote candidate may be learned from a forged request");
    assert_eq!(r.agent.checklist().len(), 1, "no pair may be created");
    assert_eq!(r.agent.role(), IceRole::Controlling);
    for t in [0, 10, 20, 30] {
        for act in r.poll(t) {
            assert_ne!(parts(&act).1, a(STRANGER), "a forged request must never steer a check to its source");
        }
    }
}

// ─── Triggered checks ──────────────────────────────────────────────

fn two_remotes() -> Rig {
    rig_with(
        vec![host(A_ADDR, 65535)],
        vec![host(R_ADDR, 100), host(R2_ADDR, 65535)], // R2's pair ranks higher
        IceRole::Controlling, cfg(10, 100, 7, 16),
    )
}

#[test]
fn a_request_from_a_known_candidate_triggers_a_check_ahead_of_better_pairs() {
    let mut control = two_remotes();
    assert_eq!(parts(&control.poll(0)[0]).1, a(R2_ADDR), "control: with no request the best pair goes first");

    let mut r = two_remotes();
    r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x21; 12]));
    assert_eq!(parts(&r.poll(0)[0]).1, a(R_ADDR), "the triggered pair jumps the queue");
    assert_eq!(parts(&r.poll(10)[0]).1, a(R2_ADDR), "then ordinary checking resumes");
}

#[test]
fn a_request_from_an_unknown_source_learns_a_remote_peer_reflexive_candidate() {
    let mut r = single();
    r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x22; 12]));

    assert_eq!(r.agent.remote_candidates().len(), 2);
    let learned = r.agent.remote_candidates().iter().find(|c| c.transport_addr == a(STRANGER)).unwrap();
    assert_eq!(learned.candidate_type, CandidateType::PeerReflexive);
    assert_eq!(learned.priority(), PEER_PRIO, "its priority is the exact PRIORITY the check advertised");
    assert_eq!(r.agent.checklist().len(), 2, "and it gets a pair of its own");
    assert_eq!(parts(&r.poll(0)[0]).1, a(STRANGER), "which is checked at once");
}

#[test]
fn a_remote_peer_reflexive_candidate_is_reused_not_duplicated() {
    let mut r = single();
    r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x23; 12]));
    r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x24; 12]));
    assert_eq!(r.agent.remote_candidates().len(), 2, "same source twice: still one learned candidate");
    assert_eq!(r.agent.checklist().len(), 2);
}

#[test]
fn a_retransmitted_request_is_answered_again_but_triggers_only_once() {
    let mut r = single();
    let raw = peer_request(IceRole::Controlled, 5, [0x25; 12]);
    assert_eq!(r.deliver(R_ADDR, A_ADDR, &raw).len(), 1);

    let first = r.poll(0);
    assert_eq!(first.len(), 1, "the triggered check");
    let first_bytes = data_of(&first);

    // The peer retransmits the *same* request (same transaction). It deserves
    // an answer — ours may have been lost — but must not cancel the check we
    // already have in flight and start another.
    assert_eq!(r.deliver(R_ADDR, A_ADDR, &raw).len(), 1, "answered again");
    assert!(r.poll(10).is_empty(), "no second triggered check");
    let retransmit = r.poll(100);
    assert_eq!(retransmit.len(), 1);
    assert_eq!(data_of(&retransmit), first_bytes, "the original check was not cancelled: it retransmits, identically");
}

#[test]
fn a_new_request_for_an_in_progress_pair_cancels_the_old_check_and_sends_a_new_one() {
    let mut r = single(); // RTO 100
    let check1 = r.poll(0);
    let txn1 = parse_check(&data_of(&check1)).txn_id;

    r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x26; 12]));
    let check2 = r.poll(10);
    assert_eq!(check2.len(), 1);
    let txn2 = parse_check(&data_of(&check2)).txn_id;
    assert_ne!(txn1, txn2, "a triggered check is a new transaction");

    // The superseded check no longer retransmits; the new one does, on its own schedule.
    assert!(r.poll(100).is_empty());
    let again = r.poll(110);
    assert_eq!(again.len(), 1);
    assert_eq!(data_of(&again), data_of(&check2));

    // But an answer to the superseded check is still honoured: it may just have been slow.
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&check1), A_ADDR));
    assert_eq!(state_of(&r.agent, A_ADDR, R_ADDR), PairState::Succeeded);
    assert_eq!(r.agent.valid_pairs().len(), 1);
}

#[test]
fn a_cancelled_transaction_timing_out_does_not_fail_the_pair() {
    let mut r = single(); // RTO 100, Rm 16: the cancelled check's final wait ends around 1610ms
    r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x27; 12]));
    r.poll(10); // the replacement check is now in flight
    r.poll(1700); // the cancelled transaction has expired by now
    assert_eq!(
        state_of(&r.agent, A_ADDR, R_ADDR), PairState::InProgress,
        "the pair's newer check is still running; the old one expiring must not fail it"
    );
}

#[test]
fn a_request_on_a_succeeded_pair_is_answered_but_not_rechecked() {
    let mut r = single();
    let check = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&check), A_ADDR));
    assert_eq!(state_of(&r.agent, A_ADDR, R_ADDR), PairState::Succeeded);

    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x28; 12]));
    assert_eq!(acts.len(), 1, "still answered");
    assert!(r.poll(10).is_empty(), "but a verified pair is not re-probed");
    assert_eq!(state_of(&r.agent, A_ADDR, R_ADDR), PairState::Succeeded);
}

#[test]
fn a_request_revives_a_failed_pair_and_its_check_list() {
    let mut r = rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 1, 1));
    r.poll(0);
    r.poll(100);
    assert_eq!(r.agent.state(), ChecklistState::Failed);

    r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x29; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Running, "a peer actively checking us proves connectivity is still possible");
    assert_eq!(state_of(&r.agent, A_ADDR, R_ADDR), PairState::Waiting);
    let acts = r.poll(110);
    assert_eq!(acts.len(), 1);
    assert_eq!(parts(&acts[0]).1, a(R_ADDR));
}

#[test]
fn a_request_from_a_new_address_after_failure_also_revives_the_list() {
    let mut r = rig_with(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(10, 100, 1, 1));
    r.poll(0);
    r.poll(100);
    assert_eq!(r.agent.state(), ChecklistState::Failed);

    r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlled, 5, [0x2A; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Running);
    assert_eq!(parts(&r.poll(110)[0]).1, a(STRANGER));
}

#[test]
fn a_request_on_an_unknown_local_address_is_answered_but_creates_no_pair() {
    let mut r = single();
    let acts = r.deliver(R_ADDR, "192.168.1.99:5000", &peer_request(IceRole::Controlled, 5, [0x2B; 12]));
    assert_eq!(acts.len(), 1);
    assert_eq!(r.agent.checklist().len(), 1);
    assert_eq!(r.agent.remote_candidates().len(), 1);
}

// ─── Role conflict ─────────────────────────────────────────────────
//
// Our tie-breaker is TIE = 0x0102030405060708. "Smaller" means the peer sent
// 1; "larger" means u64::MAX. In every case the larger value must end up
// controlling.

#[test]
fn controlling_with_the_larger_tiebreaker_answers_487_and_keeps_its_role() {
    let mut r = single_as(IceRole::Controlling);
    let txn = [0x31; 12];
    let acts = r.deliver(STRANGER, A_ADDR, &peer_request(IceRole::Controlling, 1, txn));

    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 487, authenticated: true });
    assert_eq!(r.agent.role(), IceRole::Controlling);
    assert_eq!(r.agent.remote_candidates().len(), 1, "a rejected request is discarded: nothing learned from it");
    assert_eq!(r.agent.checklist().len(), 1);
}

#[test]
fn the_487_is_signed_so_the_peer_can_tell_it_from_a_forgery() {
    let mut r = single_as(IceRole::Controlling);
    let txn = [0x32; 12];
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlling, 1, txn));
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 487, authenticated: true });
    // Checked with any other key it is unauthenticated: the signature is real.
    let wrong = parse_check_response(parts(&acts[0]).2, &txn, b"some-other-password-xyz").unwrap();
    assert_eq!(wrong, CheckResponse::Error { code: 487, authenticated: false });
}

#[test]
fn controlling_with_the_smaller_tiebreaker_switches_to_controlled_and_answers() {
    let mut r = single_as(IceRole::Controlling);
    let txn = [0x33; 12];
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlling, u64::MAX, txn));
    assert_eq!(r.agent.role(), IceRole::Controlled);
    assert!(matches!(answer(&acts, &txn), CheckResponse::Success { .. }), "after yielding, the request is processed normally");
}

#[test]
fn controlled_with_the_larger_tiebreaker_switches_to_controlling() {
    let mut r = single_as(IceRole::Controlled);
    let txn = [0x34; 12];
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, 1, txn));
    assert_eq!(r.agent.role(), IceRole::Controlling);
    assert!(matches!(answer(&acts, &txn), CheckResponse::Success { .. }));
}

#[test]
fn controlled_with_the_smaller_tiebreaker_answers_487_and_keeps_its_role() {
    let mut r = single_as(IceRole::Controlled);
    let txn = [0x35; 12];
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, u64::MAX, txn));
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 487, authenticated: true });
    assert_eq!(r.agent.role(), IceRole::Controlled);
}

#[test]
fn equal_tiebreakers_follow_the_greater_or_equal_rule_in_both_roles() {
    // RFC 8445 uses >= in both mirrored rules.
    let mut controlling = single_as(IceRole::Controlling);
    let txn = [0x36; 12];
    let acts = controlling.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlling, TIE, txn));
    assert_eq!(answer(&acts, &txn), CheckResponse::Error { code: 487, authenticated: true });
    assert_eq!(controlling.agent.role(), IceRole::Controlling);

    let mut controlled = single_as(IceRole::Controlled);
    controlled.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, TIE, [0x37; 12]));
    assert_eq!(controlled.agent.role(), IceRole::Controlling);
}

#[test]
fn no_conflict_when_the_roles_differ() {
    let mut controlling = single_as(IceRole::Controlling);
    let txn = [0x38; 12];
    let acts = controlling.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlled, u64::MAX, txn));
    assert!(matches!(answer(&acts, &txn), CheckResponse::Success { .. }));
    assert_eq!(controlling.agent.role(), IceRole::Controlling);

    let mut controlled = single_as(IceRole::Controlled);
    let txn = [0x39; 12];
    let acts = controlled.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlling, u64::MAX, txn));
    assert!(matches!(answer(&acts, &txn), CheckResponse::Success { .. }));
    assert_eq!(controlled.agent.role(), IceRole::Controlled);
}

#[test]
fn a_switch_forced_by_a_request_reprioritises_the_whole_check_list() {
    let mut r = two_pairs(); // Controlling; A is pref 65535, B and R are pref 100
    let before: Vec<u64> = r.agent.checklist().entries().iter().map(|e| e.pair.priority).collect();

    r.deliver(R_ADDR, A_ADDR, &peer_request(IceRole::Controlling, u64::MAX, [0x3A; 12]));
    assert_eq!(r.agent.role(), IceRole::Controlled);

    let after: Vec<u64> = r.agent.checklist().entries().iter().map(|e| e.pair.priority).collect();
    assert_ne!(before, after, "pair priority depends on role, so it must have been recomputed");
    for e in r.agent.checklist().entries() {
        let fresh = CandidatePair::new(e.pair.local.clone(), e.pair.remote.clone(), IceRole::Controlled);
        assert_eq!(e.pair.priority, fresh.priority);
    }
}
