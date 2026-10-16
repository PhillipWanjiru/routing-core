//! ICE nomination and completion (RFC 8445 §8) against a scripted peer, on a
//! virtual clock.

use nat_traversal::ice::{
    build_check_error_response, build_check_request, build_check_success_response,
    parse_check_request, Candidate, CandidateType, CheckRequestParams, ChecklistState, IceAction,
    IceAgent, IceConfig, IceCredentials, IceRole, Nomination, PairState, ParsedCheckRequest,
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
const R_ADDR: &str = "198.51.100.7:6000";
const R_DEAD: &str = "198.51.100.50:6000";
const R_HIGH: &str = "198.51.100.60:6000";

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
fn host_c(s: &str, pref: u16, component: u8) -> Candidate {
    let x = a(s);
    Candidate::new(CandidateType::Host, x, x, pref, component)
}
fn regular() -> Nomination {
    Nomination::Regular { delay: ms(100) }
}
fn cfg(rc: u32, rm: u32, nomination: Nomination) -> IceConfig {
    IceConfig { ta: ms(10), min_rto: ms(100), max_transmissions: rc, final_wait_multiplier: rm, nomination }
}

struct Rig {
    agent: IceAgent,
    t0: Instant,
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
    fn nominate_now(&mut self) -> Vec<IceAction> {
        let t = self.at(self.now_ms);
        self.agent.nominate_now(t)
    }
}

fn rig(local: Vec<Candidate>, remote: Vec<Candidate>, role: IceRole, config: IceConfig) -> Rig {
    let t0 = Instant::now();
    let agent = IceAgent::new(
        config, role, TIE,
        IceCredentials { ufrag: L_UFRAG.into(), password: L_PWD.into() },
        IceCredentials { ufrag: R_UFRAG.into(), password: R_PWD.into() },
        local, remote, t0,
    );
    Rig { agent, t0, now_ms: 0 }
}
fn single(role: IceRole, nomination: Nomination) -> Rig {
    rig(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], role, cfg(7, 16, nomination))
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
fn is_nomination(act: &IceAction) -> bool {
    parse_check(parts(act).2).use_candidate
}
fn nominations(acts: &[IceAction]) -> Vec<&IceAction> {
    acts.iter().filter(|x| is_nomination(x)).collect()
}
fn success_for(data: &[u8], observed: &str) -> Vec<u8> {
    build_check_success_response(&parse_check(data).txn_id, a(observed), R_PWD.as_bytes())
}
fn state_of(agent: &IceAgent, remote: &str) -> PairState {
    agent.checklist().entries().iter()
        .find(|e| e.pair.remote.transport_addr == a(remote))
        .expect("entry")
        .state
}
/// A check from the peer to us, signed with our password; the peer is controlling.
fn peer_request(use_candidate: bool, txn: [u8; 12]) -> Vec<u8> {
    build_check_request(&CheckRequestParams {
        txn_id: txn, username: "lfrg:rfrg", password: L_PWD.as_bytes(), priority: PEER_PRIO,
        role: IceRole::Controlling, tie_breaker: 5, use_candidate,
    })
}

// ─── Controlling agent ─────────────────────────────────────────────

#[test]
fn a_lone_valid_pair_is_nominated_as_soon_as_nothing_better_can_arrive() {
    let mut r = single(IceRole::Controlling, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));

    let acts = r.poll(1);
    assert_eq!(acts.len(), 1, "no reason to wait: the only pair is valid and nothing outranks it");
    let (from, to, _) = parts(&acts[0]);
    assert_eq!((from, to), (a(A_ADDR), a(R_ADDR)), "the nomination check goes out on the valid pair's path");
    let sent = parse_check(&data_of(&acts));
    assert!(sent.use_candidate);
    assert_eq!(sent.sender_role, IceRole::Controlling);
    assert_eq!(state_of(&r.agent, R_ADDR), PairState::Succeeded, "nominating must not disturb the pair's state");
    assert!(r.agent.selected_pair().is_none(), "not nominated until the check succeeds");
    assert_eq!(r.agent.state(), ChecklistState::Running);
}

#[test]
fn a_successful_nomination_check_nominates_the_pair_and_completes_ice() {
    let mut r = single(IceRole::Controlling, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    let nomination = r.poll(1);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&nomination), A_ADDR));

    assert_eq!(r.agent.state(), ChecklistState::Completed);
    let chosen = r.agent.selected_pair().expect("a nominated pair");
    assert!(chosen.nominated);
    assert_eq!(chosen.pair.local.transport_addr, a(A_ADDR));
    assert_eq!(chosen.pair.remote.transport_addr, a(R_ADDR));
    assert_eq!(r.agent.next_wakeup(), None, "a completed agent has nothing left to wake for");
    assert!(r.poll(5000).is_empty(), "and sends nothing more");
}

#[test]
fn nomination_waits_for_a_better_pair_that_is_still_being_checked() {
    // R_DEAD's pair outranks R_ADDR's but never answers. The working pair must
    // not be held up for the dead one's full timeout — only for the delay.
    let mut r = rig(
        vec![host(A_ADDR, 65535)], vec![host(R_DEAD, 65535), host(R_ADDR, 100)],
        IceRole::Controlling, cfg(7, 16, regular()),
    );
    r.poll(0); // check on R_DEAD (higher priority)
    let live = r.poll(10); // check on R_ADDR
    assert_eq!(parts(&live[0]).1, a(R_ADDR));
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&live), A_ADDR)); // first valid pair, at t=10

    let mut early = Vec::new();
    for t in [20, 50, 80, 109] {
        early.extend(r.poll(t));
    }
    assert!(nominations(&early).is_empty(), "a better pair is still being checked: wait");

    let due = r.poll(110);
    assert_eq!(nominations(&due).len(), 1, "100ms after the first valid pair, nominate what we have");
    assert_eq!(parts(nominations(&due)[0]).1, a(R_ADDR));
}

#[test]
fn nomination_chooses_the_best_valid_pair_available_at_the_time() {
    let mut r = rig(
        vec![host(A_ADDR, 65535)], vec![host(R_HIGH, 65535), host(R_ADDR, 100)],
        IceRole::Controlling, cfg(7, 16, regular()),
    );
    let on_high = r.poll(0);
    let on_low = r.poll(10);
    // The lower-priority pair is valid first, while the better one is still pending...
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&on_low), A_ADDR));
    assert!(nominations(&r.poll(15)).is_empty(), "so we hold off");
    // ...then the better one arrives, well inside the delay.
    r.poll(20);
    r.deliver(R_HIGH, A_ADDR, &success_for(&data_of(&on_high), A_ADDR));

    let acts = r.poll(21);
    assert_eq!(nominations(&acts).len(), 1);
    assert_eq!(parts(nominations(&acts)[0]).1, a(R_HIGH), "the better pair, not the first to succeed");
}

#[test]
fn manual_mode_never_nominates_until_asked() {
    let mut r = single(IceRole::Controlling, Nomination::Never);
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    for t in [1, 100, 1000, 10_000] {
        assert!(nominations(&r.poll(t)).is_empty(), "Nomination::Never must never nominate by itself ({t}ms)");
    }
    let asked = r.nominate_now();
    assert_eq!(asked.len(), 1);
    assert!(is_nomination(&asked[0]));
    assert!(r.nominate_now().is_empty(), "one nomination in flight at a time");
}

#[test]
fn a_controlled_agent_never_nominates_by_itself() {
    let mut r = single(IceRole::Controlled, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    for t in [1, 100, 1000] {
        assert!(nominations(&r.poll(t)).is_empty(), "only the controlling agent nominates");
    }
    assert!(r.nominate_now().is_empty());
    assert_eq!(r.agent.state(), ChecklistState::Running);
}

#[test]
fn a_nomination_check_that_times_out_is_retried() {
    let mut r = rig(vec![host(A_ADDR, 65535)], vec![host(R_ADDR, 65535)], IceRole::Controlling, cfg(1, 1, regular()));
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    let one = r.poll(1);
    assert_eq!(nominations(&one).len(), 1);
    assert!(nominations(&r.poll(100)).is_empty(), "the first attempt has not timed out yet");

    let two = r.poll(101); // Rc=1, Rm=1, RTO=100: the first attempt expires at 101
    assert_eq!(nominations(&two).len(), 1, "an unanswered nomination must be tried again");
    assert_ne!(parse_check(&data_of(&one)).txn_id, parse_check(&data_of(&two)).txn_id);
}

#[test]
fn a_role_conflict_on_the_nomination_check_ends_this_agents_nominating() {
    let mut r = single(IceRole::Controlling, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    let nomination = r.poll(1);
    let txn = parse_check(&data_of(&nomination)).txn_id;

    r.deliver(R_ADDR, A_ADDR, &build_check_error_response(&txn, 487, "Role Conflict", Some(R_PWD.as_bytes())));
    assert_eq!(r.agent.role(), IceRole::Controlled);
    for t in [10, 100, 1000] {
        assert!(nominations(&r.poll(t)).is_empty(), "a controlled agent must not nominate");
    }
}

#[test]
fn a_forged_success_to_the_nomination_check_nominates_nothing() {
    let mut r = single(IceRole::Controlling, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    let nomination = r.poll(1);
    let txn = parse_check(&data_of(&nomination)).txn_id;

    let forged = build_check_success_response(&txn, a(A_ADDR), b"attacker-guess-0123456789");
    r.deliver(R_ADDR, A_ADDR, &forged);
    assert!(r.agent.selected_pair().is_none());
    assert_eq!(r.agent.state(), ChecklistState::Running);
}

#[test]
fn a_peer_reflexive_valid_pair_is_nominated_as_that_pair() {
    let mut r = single(IceRole::Controlling, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), "203.0.113.99:41000"));
    let nomination = r.poll(1);
    assert_eq!(parts(&nomination[0]).0, a(A_ADDR), "still sent from the base socket");
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&nomination), "203.0.113.99:41000"));

    let chosen = r.agent.selected_pair().expect("nominated");
    assert_eq!(chosen.pair.local.candidate_type, CandidateType::PeerReflexive);
    assert_eq!(chosen.pair.local.transport_addr, a("203.0.113.99:41000"));
    assert_eq!(r.agent.valid_pairs().len(), 1, "the nomination answer is the same path, not a second pair");
    assert_eq!(r.agent.state(), ChecklistState::Completed);
}

// ─── Controlled agent ──────────────────────────────────────────────

#[test]
fn use_candidate_on_a_verified_pair_nominates_it_at_once() {
    let mut r = single(IceRole::Controlled, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR)); // our own check succeeded
    assert!(r.agent.selected_pair().is_none());

    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(true, [0x41; 12]));
    assert_eq!(acts.len(), 1, "still answered");
    assert!(r.agent.valid_pairs()[0].nominated);
    assert_eq!(r.agent.state(), ChecklistState::Completed);
}

#[test]
fn use_candidate_on_an_unverified_pair_waits_for_our_own_check() {
    // A controlled agent nominates only what it has verified in both
    // directions: the peer's USE-CANDIDATE alone is not enough.
    let mut r = single(IceRole::Controlled, regular());
    r.deliver(R_ADDR, A_ADDR, &peer_request(true, [0x42; 12]));
    assert!(r.agent.valid_pairs().is_empty());
    assert_eq!(r.agent.state(), ChecklistState::Running, "nothing is nominated yet");

    let check = r.poll(0); // the triggered check the request caused
    assert_eq!(check.len(), 1);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&check), A_ADDR));

    assert!(r.agent.valid_pairs()[0].nominated, "our own check succeeded: now it may be nominated");
    assert_eq!(r.agent.state(), ChecklistState::Completed);
}

#[test]
fn a_check_without_use_candidate_never_nominates() {
    let mut r = single(IceRole::Controlled, regular());
    let first = r.poll(0);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&first), A_ADDR));
    r.deliver(R_ADDR, A_ADDR, &peer_request(false, [0x43; 12]));
    assert!(!r.agent.valid_pairs()[0].nominated);
    assert_eq!(r.agent.state(), ChecklistState::Running);
}

// ─── Completion ────────────────────────────────────────────────────

#[test]
fn a_completed_agent_stops_checking_but_keeps_answering() {
    // Two pairs; the second is still being checked when the first is nominated.
    let mut r = rig(
        vec![host(A_ADDR, 65535), host("192.168.1.11:5000", 100)], vec![host(R_ADDR, 100)],
        IceRole::Controlled, cfg(7, 16, regular()),
    );
    let on_a = r.poll(0);
    r.poll(10); // a check on the second pair is now in flight
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&on_a), A_ADDR));
    r.deliver(R_ADDR, A_ADDR, &peer_request(true, [0x44; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Completed);

    for t in [20, 200, 5000] {
        assert!(r.poll(t).is_empty(), "no more checks, and no retransmissions of the abandoned one ({t}ms)");
    }
    assert_eq!(r.agent.next_wakeup(), None);

    // The peer may still be checking us; it must keep getting answers.
    let acts = r.deliver(R_ADDR, A_ADDR, &peer_request(false, [0x45; 12]));
    assert_eq!(acts.len(), 1, "a completed agent still answers the peer");
    assert!(r.poll(6000).is_empty(), "without starting any new check of its own");
}

#[test]
fn late_responses_after_completion_change_nothing() {
    let mut r = rig(
        vec![host(A_ADDR, 65535), host("192.168.1.11:5000", 100)], vec![host(R_ADDR, 100)],
        IceRole::Controlled, cfg(7, 16, regular()),
    );
    let on_a = r.poll(0);
    let on_b = r.poll(10);
    r.deliver(R_ADDR, A_ADDR, &success_for(&data_of(&on_a), A_ADDR));
    r.deliver(R_ADDR, A_ADDR, &peer_request(true, [0x46; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Completed);

    r.deliver(R_ADDR, "192.168.1.11:5000", &success_for(&data_of(&on_b), "192.168.1.11:5000"));
    assert_eq!(r.agent.valid_pairs().len(), 1, "an answer to an abandoned check must not add a pair");
    assert_eq!(r.agent.state(), ChecklistState::Completed);
}

#[test]
fn completion_requires_a_nominated_pair_for_every_component() {
    let mut r = rig(
        vec![host_c("192.168.1.10:5000", 65535, 1), host_c("192.168.1.10:5002", 65535, 2)],
        vec![host_c("198.51.100.7:6000", 65535, 1), host_c("198.51.100.7:6002", 65535, 2)],
        IceRole::Controlled, cfg(7, 16, regular()),
    );
    // Both components' own checks succeed (the second is released by the first).
    let rtp = r.poll(0);
    r.deliver("198.51.100.7:6000", "192.168.1.10:5000", &success_for(&data_of(&rtp), "192.168.1.10:5000"));
    let rtcp = r.poll(10);
    r.deliver("198.51.100.7:6002", "192.168.1.10:5002", &success_for(&data_of(&rtcp), "192.168.1.10:5002"));
    assert_eq!(r.agent.valid_pairs().len(), 2);

    r.deliver("198.51.100.7:6000", "192.168.1.10:5000", &peer_request(true, [0x47; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Running, "component 1 is nominated but component 2 is not");
    assert!(r.agent.selected_pair_for(1).is_some());
    assert!(r.agent.selected_pair_for(2).is_none());

    r.deliver("198.51.100.7:6002", "192.168.1.10:5002", &peer_request(true, [0x48; 12]));
    assert_eq!(r.agent.state(), ChecklistState::Completed);
    assert_eq!(r.agent.selected_pair_for(2).unwrap().pair.remote.transport_addr, a("198.51.100.7:6002"));
}
