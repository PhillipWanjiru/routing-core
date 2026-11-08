//! A relayed candidate must be its own base.
//!
//! The agent sends a pair's checks from the local candidate's `base_addr` and
//! prunes pairs that share a base and a remote. Both behaviours are right for
//! host and server-reflexive candidates and wrong for a relayed one given the
//! host socket as its base: checks would leave from the host socket and
//! bypass the relay, and the relayed pair would be pruned as a duplicate of the
//! host pair. These tests pin the rule and the failure it prevents.

use nat_traversal::ice::{
    Candidate, CandidateType, IceAction, IceAgent, IceConfig, IceCredentials, IceRole, Nomination,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
const HOST: &str = "192.168.1.10:5000";
const RELAY: &str = "203.0.113.10:50001";
const PEER: &str = "198.51.100.7:7000";

fn creds(tag: &str) -> IceCredentials {
    IceCredentials { ufrag: format!("{tag}frg"), password: format!("{tag}-password-0123456789abcd") }
}
fn config() -> IceConfig {
    IceConfig {
        ta: Duration::from_millis(20), min_rto: Duration::from_millis(100),
        max_transmissions: 7, final_wait_multiplier: 16, nomination: Nomination::Never,
    }
}
fn agent(local: Vec<Candidate>, remote: Vec<Candidate>, t0: Instant) -> IceAgent {
    IceAgent::new(config(), IceRole::Controlling, 100, creds("a"), creds("b"), local, remote, t0)
}
fn host(addr: &str) -> Candidate {
    Candidate::new(CandidateType::Host, a(addr), a(addr), 65535, 1)
}

#[test]
fn a_relayed_candidate_is_its_own_base() {
    let c = Candidate::relayed(a(RELAY), 65535, 1);
    assert_eq!(c.candidate_type, CandidateType::Relayed);
    assert_eq!(c.transport_addr, a(RELAY));
    assert_eq!(c.base_addr, a(RELAY), "sending from a relayed candidate means sending through the relay");
}

#[test]
fn a_relayed_pair_is_not_pruned_against_a_host_pair() {
    let ag = agent(vec![host(HOST), Candidate::relayed(a(RELAY), 65535, 1)], vec![host(PEER)], Instant::now());
    let bases: HashSet<SocketAddr> = ag.checklist().entries().iter().map(|e| e.pair.local.base_addr).collect();
    assert_eq!(ag.checklist().len(), 2, "one pair per local candidate: they send different packets");
    assert_eq!(bases, HashSet::from([a(HOST), a(RELAY)]));
}

#[test]
fn giving_a_relayed_candidate_the_host_base_gets_its_pair_pruned_away() {
    // The mistake `Candidate::relayed` exists to prevent, kept as a regression
    // lock: with the host's base, the relayed pair looks like a duplicate.
    let wrongly_based = Candidate::new(CandidateType::Relayed, a(RELAY), a(HOST), 65535, 1);
    let ag = agent(vec![host(HOST), wrongly_based], vec![host(PEER)], Instant::now());
    assert_eq!(ag.checklist().len(), 1, "the relayed pair vanished: the relay would never be tried");
}

#[test]
fn checks_for_a_relayed_pair_are_sent_from_the_relayed_address() {
    let t0 = Instant::now();
    let mut ag = agent(vec![host(HOST), Candidate::relayed(a(RELAY), 65535, 1)], vec![host(PEER)], t0);
    let mut sent_from = HashSet::new();
    for tick in 0..200u64 {
        for IceAction::Send { from, .. } in ag.poll(t0 + Duration::from_millis(tick * 10)) {
            sent_from.insert(from);
        }
    }
    assert!(sent_from.contains(&a(RELAY)), "a relayed pair must be addressed from the relayed address");
    assert!(sent_from.contains(&a(HOST)));
}

#[test]
fn a_relayed_candidate_ranks_below_every_other_type() {
    let (h, s, r) = (
        host(HOST),
        Candidate::new(CandidateType::ServerReflexive, a("203.0.113.1:4000"), a(HOST), 65535, 1),
        Candidate::relayed(a(RELAY), 65535, 1),
    );
    assert!(h.priority() > s.priority() && s.priority() > r.priority(), "relay is the last resort");
}
