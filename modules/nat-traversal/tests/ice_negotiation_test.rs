//! Two ICE agents negotiating with each other over an in-memory network.
//!
//! Each agent is the deterministic state machine from `ice::agent`; the
//! "network" is a virtual-time packet queue with a pluggable routing function,
//! so latency, loss and NATs are all just functions from `(from, to)` to
//! `Option<(from', to')>`. Nothing sleeps and nothing is random except the
//! agents' own transaction IDs, so every run is repeatable.

use nat_traversal::ice::{
    Candidate, CandidateType, ChecklistState, IceAction, IceAgent, IceConfig, IceCredentials, IceRole,
    Nomination,
};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

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
fn srflx(public: SocketAddr, base: &str, pref: u16) -> Candidate {
    Candidate::new(CandidateType::ServerReflexive, public, a(base), pref, 1)
}
fn creds(tag: &str) -> IceCredentials {
    IceCredentials { ufrag: format!("{tag}frg"), password: format!("{tag}-password-0123456789abcd") }
}
fn config() -> IceConfig {
    IceConfig {
        ta: ms(20), min_rto: ms(100), max_transmissions: 7, final_wait_multiplier: 16,
        nomination: Nomination::Never,
    }
}
#[allow(clippy::too_many_arguments)]
fn agent_with(
    cfg: IceConfig, local: &str, remote: &str, role: IceRole, tie: u64,
    local_cands: Vec<Candidate>, remote_cands: Vec<Candidate>, t0: Instant,
) -> IceAgent {
    IceAgent::new(cfg, role, tie, creds(local), creds(remote), local_cands, remote_cands, t0)
}

// ─── The virtual network ────────────────────────────────────────────

/// Maps a packet's (source, destination) to what actually arrives, or drops it.
type Route = Box<dyn FnMut(SocketAddr, SocketAddr) -> Option<(SocketAddr, SocketAddr)>>;

struct Packet {
    deliver_at: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

struct Sim {
    t0: Instant,
    now: u64,
    agents: [IceAgent; 2],
    /// Each agent's one (private) socket address — where packets for it arrive.
    owned: [SocketAddr; 2],
    queue: Vec<Packet>,
    latency: u64,
    route: Route,
    /// Every packet an agent asked to send, whether or not the network delivered it.
    sent: usize,
}

impl Sim {
    fn new(agents: [IceAgent; 2], owned: [SocketAddr; 2], t0: Instant, latency: u64, route: Route) -> Self {
        Sim { t0, now: 0, agents, owned, queue: Vec::new(), latency, route, sent: 0 }
    }

    fn enqueue(&mut self, actions: Vec<IceAction>) {
        for act in actions {
            let IceAction::Send { from, to, data } = act;
            self.sent += 1;
            if let Some((from, to)) = (self.route)(from, to) {
                self.queue.push(Packet { deliver_at: self.now + self.latency, from, to, data });
            }
        }
    }

    /// One millisecond: deliver what is due, then let each agent act.
    fn step(&mut self) {
        let now = self.now;
        let (due, later): (Vec<Packet>, Vec<Packet>) =
            std::mem::take(&mut self.queue).into_iter().partition(|p| p.deliver_at <= now);
        self.queue = later;
        for p in due {
            if let Some(i) = (0..2).find(|&i| self.owned[i] == p.to) {
                let t = self.t0 + ms(now);
                let out = self.agents[i].handle_datagram(p.from, p.to, &p.data, t);
                self.enqueue(out);
            }
        }
        let t = self.t0 + ms(now);
        for i in 0..2 {
            let out = self.agents[i].poll(t);
            self.enqueue(out);
        }
        self.now += 1;
    }

    fn run_until(&mut self, end_ms: u64) {
        while self.now <= end_ms {
            self.step();
        }
    }

    fn roles(&self) -> (IceRole, IceRole) {
        (self.agents[0].role(), self.agents[1].role())
    }

    fn both_have_valid_pairs(&self) -> bool {
        self.agents.iter().all(|ag| !ag.valid_pairs().is_empty())
    }
}

fn identity_route() -> Route {
    Box::new(|f, t| Some((f, t)))
}

const A_HOST: &str = "192.168.1.10:5000";
const B_HOST: &str = "192.168.1.20:6000";

/// Two hosts on one LAN, no NAT.
fn lan(role_a: IceRole, tie_a: u64, role_b: IceRole, tie_b: u64, latency: u64, route: Route) -> Sim {
    lan_with(config(), role_a, tie_a, role_b, tie_b, latency, route)
}

fn lan_with(cfg: IceConfig, role_a: IceRole, tie_a: u64, role_b: IceRole, tie_b: u64, latency: u64, route: Route) -> Sim {
    let t0 = Instant::now();
    let (ha, hb) = (host(A_HOST, 65535), host(B_HOST, 65535));
    let agent_a = agent_with(cfg.clone(), "a", "b", role_a, tie_a, vec![ha.clone()], vec![hb.clone()], t0);
    let agent_b = agent_with(cfg, "b", "a", role_b, tie_b, vec![hb], vec![ha], t0);
    Sim::new([agent_a, agent_b], [a(A_HOST), a(B_HOST)], t0, latency, route)
}

// ─── Plain negotiation ──────────────────────────────────────────────

#[test]
fn two_agents_with_complementary_roles_reach_valid_pairs() {
    let mut s = lan(IceRole::Controlling, 1, IceRole::Controlled, 2, 0, identity_route());
    s.run_until(500);

    assert_eq!(s.roles(), (IceRole::Controlling, IceRole::Controlled), "no conflict: no role may change");
    assert!(s.both_have_valid_pairs());
    let (va, vb) = (&s.agents[0].valid_pairs()[0].pair, &s.agents[1].valid_pairs()[0].pair);
    assert_eq!(va.local.transport_addr, vb.remote.transport_addr, "A's local end is B's remote end");
    assert_eq!(va.remote.transport_addr, vb.local.transport_addr, "and vice versa");
}

#[test]
fn negotiation_works_with_network_latency() {
    let mut s = lan(IceRole::Controlling, 1, IceRole::Controlled, 2, 40, identity_route());
    s.run_until(2000);
    assert!(s.both_have_valid_pairs(), "40ms each way must not break the timers");
}

#[test]
fn negotiation_survives_initial_packet_loss() {
    // Lose everything A sends for a while — its checks *and* its replies.
    let a_addr = a(A_HOST);
    let mut dropped = 0u32;
    let route: Route = Box::new(move |f, t| {
        if f == a_addr && dropped < 6 {
            dropped += 1;
            None
        } else {
            Some((f, t))
        }
    });
    let mut s = lan(IceRole::Controlling, 1, IceRole::Controlled, 2, 0, route);
    s.run_until(6000);
    assert!(s.both_have_valid_pairs(), "retransmission must recover from early loss");
}

// ─── Role conflict ──────────────────────────────────────────────────

fn expected_roles(ra: IceRole, rb: IceRole, ta: u64, tb: u64) -> (IceRole, IceRole) {
    // When both claim the same role, the larger tie-breaker ends up controlling;
    // otherwise nothing changes. (Tie-breakers here are never equal.)
    match (ra, rb) {
        (IceRole::Controlling, IceRole::Controlling) | (IceRole::Controlled, IceRole::Controlled) => {
            if ta > tb { (IceRole::Controlling, IceRole::Controlled) } else { (IceRole::Controlled, IceRole::Controlling) }
        }
        other => other,
    }
}

#[test]
fn every_role_and_tie_breaker_combination_ends_with_exactly_one_controlling() {
    let roles = [IceRole::Controlling, IceRole::Controlled];
    for ra in roles {
        for rb in roles {
            for (ta, tb) in [(10u64, 20u64), (20, 10)] {
                let mut s = lan(ra, ta, rb, tb, 0, identity_route());
                s.run_until(1500);

                let case = format!("A={ra:?}/{ta} B={rb:?}/{tb}");
                let (got_a, got_b) = s.roles();
                assert_ne!(got_a, got_b, "{case}: exactly one side must be controlling");
                assert_eq!((got_a, got_b), expected_roles(ra, rb, ta, tb), "{case}: wrong side won");
                assert!(s.both_have_valid_pairs(), "{case}: connectivity must still be established");
                assert!(
                    s.agents.iter().all(|ag| ag.state() != ChecklistState::Failed),
                    "{case}: resolving a conflict must not fail the check list"
                );
            }
        }
    }
}

#[test]
fn a_role_conflict_costs_only_a_round_trip_or_two() {
    for (ra, rb) in [(IceRole::Controlling, IceRole::Controlling), (IceRole::Controlled, IceRole::Controlled)] {
        let mut s = lan(ra, 10, rb, 20, 5, identity_route());
        s.run_until(400);
        assert!(s.both_have_valid_pairs(), "{ra:?}/{rb:?}: should resolve within a few packet exchanges, not a timeout");
    }
}

// ─── NATs ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// One mapping per private socket; inbound allowed from any port of an IP
    /// we have already sent to (address-restricted cone).
    Cone,
    /// A fresh mapping per destination; inbound allowed only from exactly that
    /// destination.
    Symmetric,
}

struct Nat {
    public_ip: IpAddr,
    private: SocketAddr,
    kind: Kind,
    /// The mapping a STUN server would have seen — what gets advertised.
    stun_port: u16,
    next_port: u16,
    per_dest: Vec<(SocketAddr, u16)>,
    permitted: HashSet<IpAddr>,
}

impl Nat {
    fn new(public_ip: &str, private: &str, kind: Kind, stun_port: u16) -> Self {
        Nat {
            public_ip: public_ip.parse().unwrap(),
            private: a(private),
            kind,
            stun_port,
            next_port: stun_port + 100, // distinct from the advertised mapping
            per_dest: Vec::new(),
            permitted: HashSet::new(),
        }
    }

    fn advertised(&self) -> SocketAddr {
        SocketAddr::new(self.public_ip, self.stun_port)
    }

    /// Translate an outgoing packet's source, creating state as a real NAT would.
    fn outbound(&mut self, dest: SocketAddr) -> SocketAddr {
        match self.kind {
            Kind::Cone => {
                self.permitted.insert(dest.ip());
                self.advertised()
            }
            Kind::Symmetric => {
                if let Some(&(_, p)) = self.per_dest.iter().find(|(d, _)| *d == dest) {
                    return SocketAddr::new(self.public_ip, p);
                }
                self.next_port += 1;
                self.per_dest.push((dest, self.next_port));
                SocketAddr::new(self.public_ip, self.next_port)
            }
        }
    }

    /// Filter an incoming packet; `Some(private)` if it may pass.
    fn inbound(&self, dst: SocketAddr, src: SocketAddr) -> Option<SocketAddr> {
        if dst.ip() != self.public_ip {
            return None;
        }
        let allowed = match self.kind {
            Kind::Cone => dst.port() == self.stun_port && self.permitted.contains(&src.ip()),
            Kind::Symmetric => self.per_dest.iter().any(|(d, p)| *p == dst.port() && *d == src),
        };
        allowed.then_some(self.private)
    }
}

fn nat_route(mut nat_a: Nat, mut nat_b: Nat) -> Route {
    Box::new(move |from, to| {
        let (src, dst) = if from == nat_a.private {
            (&mut nat_a, &nat_b)
        } else if from == nat_b.private {
            (&mut nat_b, &nat_a)
        } else {
            return None;
        };
        let public_src = src.outbound(to);
        let private_dst = dst.inbound(to, public_src)?;
        Some((public_src, private_dst))
    })
}

const A_PRIV: &str = "192.168.1.10:5000";
const B_PRIV: &str = "10.0.0.5:6000";

/// Two agents each behind a NAT. Each advertises its private host candidate
/// (useless from outside, as in real life) and the server-reflexive mapping a
/// STUN server saw, and knows the other's two candidates.
fn behind_nats(kind_a: Kind, kind_b: Kind) -> (Sim, SocketAddr, SocketAddr) {
    behind_nats_with(config(), kind_a, kind_b)
}

fn behind_nats_with(cfg: IceConfig, kind_a: Kind, kind_b: Kind) -> (Sim, SocketAddr, SocketAddr) {
    let t0 = Instant::now();
    let nat_a = Nat::new("203.0.113.1", A_PRIV, kind_a, 4000);
    let nat_b = Nat::new("198.51.100.7", B_PRIV, kind_b, 7000);
    let (adv_a, adv_b) = (nat_a.advertised(), nat_b.advertised());

    let a_cands = vec![host(A_PRIV, 65535), srflx(adv_a, A_PRIV, 65535)];
    let b_cands = vec![host(B_PRIV, 65535), srflx(adv_b, B_PRIV, 65535)];
    let agent_a = agent_with(cfg.clone(), "a", "b", IceRole::Controlling, 100, a_cands.clone(), b_cands.clone(), t0);
    let agent_b = agent_with(cfg, "b", "a", IceRole::Controlled, 50, b_cands, a_cands, t0);

    let sim = Sim::new([agent_a, agent_b], [a(A_PRIV), a(B_PRIV)], t0, 0, nat_route(nat_a, nat_b));
    (sim, adv_a, adv_b)
}

#[test]
fn two_address_restricted_nats_connect_through_triggered_checks() {
    // Each side's first check is dropped by the other's NAT — but sending it
    // opened the permission the other side's check needs. The triggered check
    // on receipt then completes the hole punch.
    let (mut s, adv_a, adv_b) = behind_nats(Kind::Cone, Kind::Cone);

    // Left to retransmission alone, A would not connect until its first
    // retransmit (RTO 100 ms after the check sent at 20 ms: ~120 ms). The
    // triggered check on receiving B's request gets it there within a couple
    // of pacing intervals (~42 ms). So a 100 ms bound can only be met if
    // triggered checks actually work — mutation-checked: with triggering
    // disabled this assertion fails.
    s.run_until(100);
    assert!(s.both_have_valid_pairs(), "triggered checks must complete the punch before any retransmission is due");
    s.run_until(1000);

    assert!(s.both_have_valid_pairs(), "hole punching through two cone NATs must succeed");
    let (va, vb) = (&s.agents[0].valid_pairs()[0].pair, &s.agents[1].valid_pairs()[0].pair);
    assert_eq!(va.local.transport_addr, adv_a, "A is seen as the address it already knew");
    assert_eq!(va.remote.transport_addr, adv_b);
    assert_eq!(va.local.candidate_type, CandidateType::ServerReflexive);
    assert_eq!(vb.local.transport_addr, adv_b);
    assert_eq!(vb.remote.transport_addr, adv_a);
}

#[test]
fn a_symmetric_nat_facing_a_cone_nat_connects_via_peer_reflexive_candidates() {
    // A's NAT gives every destination a fresh port, so the address B sees A's
    // check come from is not the one A advertised. Neither side was told about
    // it — each must *discover* it from the other's check.
    let (mut s, adv_a, adv_b) = behind_nats(Kind::Symmetric, Kind::Cone);

    // A's first check to B is dropped (B's NAT has no permission yet), so A needs
    // one retransmit (~120 ms); B then learns A's real address from that check
    // and probes it by a triggered check at the next pacing tick (~140 ms).
    s.run_until(250);
    assert!(s.both_have_valid_pairs(), "the punch must complete within one retransmit plus a pacing tick");
    s.run_until(1000);

    assert!(s.both_have_valid_pairs(), "ICE must punch through a symmetric NAT facing a cone NAT");

    let va = &s.agents[0].valid_pairs()[0].pair;
    assert_eq!(va.local.candidate_type, CandidateType::PeerReflexive, "A learned its real mapping from B's reply");
    assert_eq!(va.local.transport_addr.ip(), adv_a.ip());
    assert_ne!(va.local.transport_addr, adv_a, "it is not the mapping A advertised");
    assert_eq!(va.remote.transport_addr, adv_b);

    let learned = s.agents[1].remote_candidates().iter()
        .find(|c| c.candidate_type == CandidateType::PeerReflexive)
        .expect("B must have learned a remote peer-reflexive candidate from A's check");
    assert_eq!(learned.transport_addr, va.local.transport_addr, "both ends agree on A's real address");
}

#[test]
fn two_symmetric_nats_cannot_connect_directly() {
    // The boundary of what ICE alone can do: with a per-destination mapping on
    // *both* sides, each side's packets go to a mapping the other side never
    // opened. This is exactly the case a TURN relay exists for.
    let (mut s, _, _) = behind_nats(Kind::Symmetric, Kind::Symmetric);
    s.run_until(9000);

    assert!(s.agents.iter().all(|ag| ag.valid_pairs().is_empty()), "no direct path can exist");
    assert!(
        s.agents.iter().all(|ag| ag.state() == ChecklistState::Failed),
        "and both agents must conclude so, rather than hang"
    );
}

// ─── Nomination and completion ──────────────────────────────────────

fn nominating() -> IceConfig {
    IceConfig { nomination: Nomination::Regular { delay: ms(100) }, ..config() }
}

fn both_completed(s: &Sim) -> bool {
    s.agents.iter().all(|ag| ag.state() == ChecklistState::Completed)
}

/// A's selected pair and B's must be the same path seen from opposite ends.
fn selected_pairs_mirror(s: &Sim) -> bool {
    match (s.agents[0].selected_pair(), s.agents[1].selected_pair()) {
        (Some(x), Some(y)) => {
            x.pair.local.transport_addr == y.pair.remote.transport_addr
                && x.pair.remote.transport_addr == y.pair.local.transport_addr
        }
        _ => false,
    }
}

#[test]
fn both_agents_complete_on_the_same_pair() {
    let mut s = lan_with(nominating(), IceRole::Controlling, 1, IceRole::Controlled, 2, 0, identity_route());
    s.run_until(1000);
    assert!(both_completed(&s), "both sides must conclude ICE");
    assert!(selected_pairs_mirror(&s), "and must have selected the same path");
    assert_eq!(s.roles(), (IceRole::Controlling, IceRole::Controlled));
}

#[test]
fn completion_holds_across_every_role_and_tie_breaker_combination() {
    let roles = [IceRole::Controlling, IceRole::Controlled];
    for ra in roles {
        for rb in roles {
            for (ta, tb) in [(10u64, 20u64), (20, 10)] {
                let mut s = lan_with(nominating(), ra, ta, rb, tb, 0, identity_route());
                s.run_until(2000);
                let case = format!("A={ra:?}/{ta} B={rb:?}/{tb}");
                assert_eq!(s.roles(), expected_roles(ra, rb, ta, tb), "{case}: wrong side won");
                assert!(both_completed(&s), "{case}: both sides must complete");
                assert!(selected_pairs_mirror(&s), "{case}: they must agree on the path");
            }
        }
    }
}

#[test]
fn completion_survives_latency_and_early_loss() {
    let a_addr = a(A_HOST);
    let mut dropped = 0u32;
    let route: Route = Box::new(move |f, t| {
        if f == a_addr && dropped < 6 {
            dropped += 1;
            None
        } else {
            Some((f, t))
        }
    });
    let mut s = lan_with(nominating(), IceRole::Controlling, 1, IceRole::Controlled, 2, 30, route);
    s.run_until(10_000);
    assert!(both_completed(&s));
    assert!(selected_pairs_mirror(&s));
}

#[test]
fn a_dead_higher_priority_candidate_does_not_delay_completion() {
    // A is told about a candidate that outranks the real path and has nobody
    // behind it — the unreachable-private-address case that is routine in real
    // calls. Waiting for it to time out would take ~8 s even with these short
    // timers (~40 s with the RFC defaults). Nomination must proceed after its
    // short delay instead.
    let t0 = Instant::now();
    let (ha, hb) = (host(A_HOST, 65535), host(B_HOST, 65535));
    let dead = host("10.99.99.99:9999", 65535);
    let agent_a = agent_with(
        nominating(), "a", "b", IceRole::Controlling, 100,
        vec![ha.clone()], vec![dead, host(B_HOST, 100)], t0,
    );
    let agent_b = agent_with(nominating(), "b", "a", IceRole::Controlled, 50, vec![hb], vec![ha], t0);
    let mut s = Sim::new([agent_a, agent_b], [a(A_HOST), a(B_HOST)], t0, 0, identity_route());

    s.run_until(600);
    assert!(both_completed(&s), "the dead pair must not hold up a working one");
    assert_eq!(s.agents[0].selected_pair().unwrap().pair.remote.transport_addr, a(B_HOST));
}

#[test]
fn nomination_selects_the_server_reflexive_pair_through_two_cone_nats() {
    let (mut s, adv_a, adv_b) = behind_nats_with(nominating(), Kind::Cone, Kind::Cone);
    s.run_until(1500);
    assert!(both_completed(&s));
    let chosen = &s.agents[0].selected_pair().unwrap().pair;
    assert_eq!(chosen.local.transport_addr, adv_a);
    assert_eq!(chosen.remote.transport_addr, adv_b);
    assert_eq!(chosen.local.candidate_type, CandidateType::ServerReflexive);
}

#[test]
fn nomination_selects_the_peer_reflexive_path_through_a_symmetric_nat() {
    let (mut s, adv_a, _adv_b) = behind_nats_with(nominating(), Kind::Symmetric, Kind::Cone);
    s.run_until(2000);
    assert!(both_completed(&s));

    let a_chose = &s.agents[0].selected_pair().unwrap().pair;
    assert_eq!(a_chose.local.candidate_type, CandidateType::PeerReflexive);
    assert_ne!(a_chose.local.transport_addr, adv_a, "not the mapping A advertised, but the one that works");
    let b_chose = &s.agents[1].selected_pair().unwrap().pair;
    assert_eq!(b_chose.remote.candidate_type, CandidateType::PeerReflexive);
    assert_eq!(b_chose.remote.transport_addr, a_chose.local.transport_addr, "both ends agree on A's real address");
}

#[test]
fn two_symmetric_nats_still_fail_with_nomination_enabled() {
    let (mut s, _, _) = behind_nats_with(nominating(), Kind::Symmetric, Kind::Symmetric);
    s.run_until(9000);
    assert!(s.agents.iter().all(|ag| ag.state() == ChecklistState::Failed));
    assert!(s.agents.iter().all(|ag| ag.selected_pair().is_none()));
}

#[test]
fn completed_agents_go_quiet() {
    let mut s = lan_with(nominating(), IceRole::Controlling, 1, IceRole::Controlled, 2, 0, identity_route());
    s.run_until(1000);
    assert!(both_completed(&s));
    let sent = s.sent;
    s.run_until(5000);
    assert_eq!(s.sent, sent, "once both sides are completed nothing more should be sent: no checks, no retransmissions");
}
