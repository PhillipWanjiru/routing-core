//! ICE over a TURN relay, end to end, in virtual time.
//!
//! Three parties on a simulated internet: two clients, each behind its own NAT,
//! and a **real** `TurnServer`. Each client runs a real `IceAgent` and a real
//! `TurnBridge`. The NATs are the same models as in `ice_negotiation_test`, whose
//! `two_symmetric_nats_cannot_connect_directly` shows the case ICE alone cannot
//! solve — the case a relay exists for. Nothing sleeps; every run is repeatable.

use nat_traversal::ice::{
    Candidate, CandidateType, ChecklistState, IceAction, IceAgent, IceConfig, IceCredentials, IceRole,
    Nomination,
};
use nat_traversal::ice_turn::{Routed, TurnBridge};
use nat_traversal::stun::attributes::{decode_attributes, Attribute};
use nat_traversal::stun::parser::parse_message;
use nat_traversal::turn::relay::{classify_datagram, DatagramKind};
use nat_traversal::turn::{
    CredentialStore, PortPool, TurnClientAction, TurnClientConfig, TurnClientEvent, TurnClientStep,
    TurnOutput, TurnServer,
};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const REALM: &str = "routing-core.local";
const USER: &str = "alice";
const PASS: &str = "correcthorsebatterystaple";
const TURN: &str = "203.0.113.10:3478";
const A_PRIV: &str = "192.168.1.10:5000";
const B_PRIV: &str = "10.0.0.5:6000";
const LATENCY: u64 = 10;

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
fn creds(tag: &str) -> IceCredentials {
    IceCredentials { ufrag: format!("{tag}frg"), password: format!("{tag}-password-0123456789abcd") }
}
fn config() -> IceConfig {
    IceConfig {
        ta: ms(20), min_rto: ms(100), max_transmissions: 7, final_wait_multiplier: 16,
        nomination: Nomination::Regular { delay: ms(100) },
    }
}
fn host_cand(addr: SocketAddr) -> Candidate {
    Candidate::new(CandidateType::Host, addr, addr, 65535, 1)
}
fn srflx_cand(public: SocketAddr, base: SocketAddr) -> Candidate {
    Candidate::new(CandidateType::ServerReflexive, public, base, 65535, 1)
}

// ─── NATs (the same models as in ice_negotiation_test) ──────────────

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// One mapping per private socket; inbound allowed from any port of an IP
    /// already sent to (address-restricted cone).
    Cone,
    /// A fresh mapping per destination; inbound allowed only from exactly that
    /// destination.
    Symmetric,
}

struct Nat {
    public_ip: IpAddr,
    private: SocketAddr,
    kind: Kind,
    /// The mapping a STUN server would have seen: what gets advertised.
    stun_port: u16,
    next_port: u16,
    per_dest: Vec<(SocketAddr, u16)>,
    permitted: HashSet<IpAddr>,
}

impl Nat {
    fn new(public_ip: &str, private: &str, kind: Kind, stun_port: u16) -> Self {
        Nat {
            public_ip: public_ip.parse().unwrap(), private: a(private), kind, stun_port,
            next_port: stun_port + 100, per_dest: Vec::new(), permitted: HashSet::new(),
        }
    }
    fn advertised(&self) -> SocketAddr {
        SocketAddr::new(self.public_ip, self.stun_port)
    }
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

// ─── The world: two clients, their NATs, and a real TURN server ─────

#[derive(Clone, Copy)]
enum Relay {
    /// This client has no TURN support.
    None,
    Working,
    /// Its credentials are wrong, so allocation fails.
    WrongPassword,
}

struct Client {
    host: SocketAddr,
    nat: Nat,
    bridge: Option<TurnBridge>,
    agent: Option<IceAgent>,
    /// Non-ICE payloads that arrived, whichever way they came.
    media: Vec<(SocketAddr, Vec<u8>)>,
    turn_events: Vec<TurnClientEvent>,
}

struct Packet {
    deliver_at: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

struct World {
    t0: Instant,
    now: u64,
    clients: [Client; 2],
    server: TurnServer,
    queue: Vec<Packet>,
    /// Whether each client keeps asking the server for permissions.
    permit: [bool; 2],
    /// Drop everything addressed to the TURN server.
    blackhole: bool,
}

fn real_server() -> TurnServer {
    let mut store = CredentialStore::new();
    store.add_user(USER, PASS);
    TurnServer::new(REALM, a(TURN).ip(), store, PortPool::new(50000, 50010))
}

impl World {
    fn new(kinds: [Kind; 2], relay: [Relay; 2]) -> World {
        let bridge = |r: Relay| match r {
            Relay::None => None,
            Relay::Working => Some(TurnBridge::new(TurnClientConfig::new(a(TURN), USER, PASS))),
            Relay::WrongPassword => Some(TurnBridge::new(TurnClientConfig::new(a(TURN), USER, "wrong"))),
        };
        let client = |kind, public: &str, private: &str, stun_port, r| Client {
            host: a(private), nat: Nat::new(public, private, kind, stun_port), bridge: bridge(r),
            agent: None, media: Vec::new(), turn_events: Vec::new(),
        };
        World {
            t0: Instant::now(), now: 0,
            clients: [
                client(kinds[0], "203.0.113.1", A_PRIV, 4000, relay[0]),
                client(kinds[1], "198.51.100.7", B_PRIV, 7000, relay[1]),
            ],
            server: real_server(), queue: Vec::new(), permit: [true, true], blackhole: false,
        }
    }

    fn t(&self) -> Instant {
        self.t0 + ms(self.now)
    }

    // — sending —

    fn send_from(&mut self, who: usize, to: SocketAddr, data: Vec<u8>) {
        let from = self.clients[who].nat.outbound(to);
        self.queue.push(Packet { deliver_at: self.now + LATENCY, from, to, data });
    }
    fn send_turn_step(&mut self, who: usize, step: TurnClientStep) {
        for TurnClientAction::Send { to, data } in step.actions {
            self.send_from(who, to, data);
        }
        self.clients[who].turn_events.extend(step.events);
    }
    fn send_ice(&mut self, who: usize, actions: Vec<IceAction>) {
        let host = self.clients[who].host;
        let routed = match &self.clients[who].bridge {
            Some(b) => b.route(actions),
            None => Routed { via_turn: Vec::new(), direct: actions },
        };
        for TurnClientAction::Send { to, data } in routed.via_turn {
            self.send_from(who, to, data);
        }
        for IceAction::Send { from, to, data } in routed.direct {
            assert_eq!(from, host, "a direct send must leave the host socket, never the relayed address");
            self.send_from(who, to, data);
        }
    }

    // — delivery —

    fn server_outputs(&mut self, outs: Vec<TurnOutput>) {
        for out in outs {
            match out {
                TurnOutput::ToClient { to, data } => {
                    self.queue.push(Packet { deliver_at: self.now + LATENCY, from: a(TURN), to, data })
                }
                TurnOutput::ToPeer { relay_port, to, data } => self.queue.push(Packet {
                    deliver_at: self.now + LATENCY, from: SocketAddr::new(a(TURN).ip(), relay_port), to, data,
                }),
                TurnOutput::RelayOpened { .. } | TurnOutput::RelayClosed { .. } => {}
            }
        }
    }

    fn deliver(&mut self, p: Packet) {
        let t = self.t();
        if p.to == a(TURN) {
            if !self.blackhole {
                let outs = self.server.handle_from_client(p.from, &p.data, t);
                self.server_outputs(outs);
            }
        } else if p.to.ip() == a(TURN).ip() {
            // A packet for one of the server's relay sockets.
            let outs = self.server.handle_from_peer(p.to.port(), p.from, &p.data, t);
            self.server_outputs(outs);
        } else {
            for who in 0..2 {
                if let Some(private) = self.clients[who].nat.inbound(p.to, p.from) {
                    self.client_receive(who, private, p.from, p.data);
                    return;
                }
            }
            // No mapping lets it in: dropped, as a real NAT would.
        }
    }

    fn client_receive(&mut self, who: usize, private_dst: SocketAddr, from: SocketAddr, data: Vec<u8>) {
        let t = self.t();
        if from == a(TURN) {
            let c = &mut self.clients[who];
            let Some(bridge) = c.bridge.as_mut() else {
                return;
            };
            let inbound = bridge.handle_server_datagram(c.agent.as_mut(), from, &data, t);
            c.media.extend(inbound.app);
            self.send_turn_step(who, inbound.turn);
            self.send_ice(who, inbound.ice);
        } else if classify_datagram(&data) == DatagramKind::Stun {
            if let Some(agent) = self.clients[who].agent.as_mut() {
                let out = agent.handle_datagram(from, private_dst, &data, t);
                self.send_ice(who, out);
            }
        } else {
            self.clients[who].media.push((from, data));
        }
    }

    // — time —

    fn step(&mut self) {
        let now = self.now;
        let (due, later): (Vec<Packet>, Vec<Packet>) =
            std::mem::take(&mut self.queue).into_iter().partition(|p| p.deliver_at <= now);
        self.queue = later;
        for p in due {
            self.deliver(p);
        }
        let t = self.t();
        for who in 0..2 {
            if let Some(bridge) = self.clients[who].bridge.as_mut() {
                let step = bridge.poll(t);
                self.send_turn_step(who, step);
            }
            if self.permit[who] {
                let c = &mut self.clients[who];
                if let (Some(bridge), Some(agent)) = (c.bridge.as_mut(), c.agent.as_ref()) {
                    let step = bridge.sync_permissions(agent.remote_candidates(), t);
                    self.send_turn_step(who, step);
                }
            }
            if let Some(agent) = self.clients[who].agent.as_mut() {
                let out = agent.poll(t);
                self.send_ice(who, out);
            }
        }
        self.now += 1;
    }

    fn run_for(&mut self, millis: u64) {
        let end = self.now + millis;
        while self.now < end {
            self.step();
        }
    }

    fn settled(&self) -> bool {
        self.clients.iter().all(|c| c.agent.as_ref().is_some_and(|ag| ag.state() != ChecklistState::Running))
    }
    fn run_until_settled(&mut self, limit_ms: u64) {
        while self.now < limit_ms && !self.settled() {
            self.step();
        }
    }

    // — setup: what happens before ICE starts —

    /// What this client would signal to its peer.
    fn signalled(&self, who: usize) -> Vec<Candidate> {
        let c = &self.clients[who];
        let mut v = vec![host_cand(c.host), srflx_cand(c.nat.advertised(), c.host)];
        if let Some(r) = c.bridge.as_ref().and_then(|b| b.relayed_candidate(65535, 1)) {
            v.push(r);
        }
        v
    }

    /// Allocate relays, exchange candidates, install permissions, start the agents.
    fn connect(&mut self, cfg: IceConfig) {
        let t = self.t();
        for who in 0..2 {
            if let Some(b) = self.clients[who].bridge.as_mut() {
                let step = b.start(t);
                self.send_turn_step(who, step);
            }
        }
        self.run_for(1000);

        let cands = [self.signalled(0), self.signalled(1)];
        let t = self.t();
        for who in 0..2 {
            if !self.permit[who] {
                continue;
            }
            let remote = cands[1 - who].clone();
            if let Some(b) = self.clients[who].bridge.as_mut() {
                let step = b.sync_permissions(&remote, t);
                self.send_turn_step(who, step);
            }
        }
        self.run_for(500);

        let t = self.t();
        let roles = [(IceRole::Controlling, 100u64, "a", "b"), (IceRole::Controlled, 50, "b", "a")];
        for who in 0..2 {
            let (role, tie, me, peer) = roles[who];
            self.clients[who].agent =
                Some(IceAgent::new(cfg.clone(), role, tie, creds(me), creds(peer), cands[who].clone(), cands[1 - who].clone(), t));
        }
    }

    // — observation —

    fn state(&self, who: usize) -> ChecklistState {
        self.clients[who].agent.as_ref().unwrap().state()
    }
    fn both(&self, s: ChecklistState) -> bool {
        (0..2).all(|i| self.state(i) == s)
    }
    fn selected_types(&self, who: usize) -> Option<(CandidateType, CandidateType)> {
        self.clients[who].agent.as_ref().unwrap().selected_pair().map(|v| (v.pair.local.candidate_type, v.pair.remote.candidate_type))
    }
    fn uses_relay(&self, who: usize) -> bool {
        matches!(self.selected_types(who), Some((l, r)) if l == CandidateType::Relayed || r == CandidateType::Relayed)
    }

    /// Send a media payload along `who`'s selected pair: through the relay if the
    /// pair's local side is the relayed candidate, otherwise from the host socket.
    fn send_media(&mut self, who: usize, payload: &[u8]) {
        let (local, remote) = {
            let v = self.clients[who].agent.as_ref().unwrap().selected_pair().expect("completed");
            (v.pair.local.base_addr, v.pair.remote.transport_addr)
        };
        let via_relay = self.clients[who].bridge.as_ref().and_then(|b| b.relayed_addr()) == Some(local);
        if via_relay {
            let action = self.clients[who].bridge.as_ref().unwrap().send_app(remote, payload).expect("allocated");
            self.send_turn_step(who, TurnClientStep { actions: vec![action], events: vec![] });
        } else {
            self.send_from(who, remote, payload.to_vec());
        }
    }
}

const SYM: Kind = Kind::Symmetric;
const CONE: Kind = Kind::Cone;
const OK: [Relay; 2] = [Relay::Working, Relay::Working];

// ─── The headline: what ICE alone could not do ──────────────────────

#[test]
fn two_symmetric_nats_connect_through_the_relay() {
    let mut w = World::new([SYM, SYM], OK);
    w.connect(config());
    w.run_until_settled(20_000);

    assert!(w.both(ChecklistState::Completed), "the case ICE alone cannot solve must now complete");
    assert!(w.uses_relay(0) && w.uses_relay(1), "and, with no direct path, it can only be through the relay");
}

#[test]
fn the_same_network_without_a_relay_still_fails() {
    // The control: identical NATs, no TURN. Proves it is the relay that made the difference.
    let mut w = World::new([SYM, SYM], [Relay::None, Relay::None]);
    w.connect(config());
    w.run_until_settled(60_000);
    assert!(w.both(ChecklistState::Failed), "no direct path exists, and the agents must conclude so rather than hang");
}

#[test]
fn media_crosses_the_selected_path_in_both_directions() {
    let mut w = World::new([SYM, SYM], OK);
    w.connect(config());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed));

    w.send_media(0, b"A to B: RTP would go here");
    w.send_media(1, b"B to A: and back again");
    w.run_for(500);

    assert!(w.clients[1].media.iter().any(|(_, d)| d == b"A to B: RTP would go here"), "A's media must reach B");
    assert!(w.clients[0].media.iter().any(|(_, d)| d == b"B to A: and back again"), "B's media must reach A");
}

#[test]
fn a_single_relay_is_enough_when_the_other_side_can_reach_it() {
    // B has no TURN and sits behind a symmetric NAT. A's relay is a public
    // address B can send to, and the relay is permitted for B's IP.
    let mut w = World::new([SYM, SYM], [Relay::Working, Relay::None]);
    w.connect(config());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed));
    assert!(w.uses_relay(0) && w.uses_relay(1));
}

// ─── The relay is a last resort ─────────────────────────────────────

#[test]
fn cone_nats_still_choose_a_direct_path_over_the_relay() {
    let mut w = World::new([CONE, CONE], OK);
    w.connect(config());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed));
    assert!(!w.uses_relay(0) && !w.uses_relay(1), "a direct path exists, so the relay must not be chosen");
}

#[test]
fn a_symmetric_nat_facing_a_cone_nat_still_connects_without_the_relay() {
    let mut w = World::new([SYM, CONE], OK);
    w.connect(config());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed));
    assert!(!w.uses_relay(0) && !w.uses_relay(1), "peer-reflexive candidates give a direct path; relaying would only add cost");
}

// ─── Permissions: the relay is closed until opened ──────────────────

#[test]
fn with_no_permissions_installed_nothing_gets_through_the_relays() {
    let mut w = World::new([SYM, SYM], OK);
    w.permit = [false, false];
    w.connect(config());
    w.run_until_settled(60_000);
    assert!(w.both(ChecklistState::Failed), "relays forward only for permitted peers, in both directions");
}

#[test]
fn permissions_on_one_side_alone_are_enough_to_connect() {
    // A permits B's IPs; B permits nothing. B's packets to A's relay are
    // forwarded to A, and A's answers go back out through that same relay.
    let mut w = World::new([SYM, SYM], OK);
    w.permit = [true, false];
    w.connect(config());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed));
}

// ─── Failure handling ───────────────────────────────────────────────

#[test]
fn a_failed_allocation_leaves_ice_to_carry_on_without_it() {
    let mut w = World::new([CONE, CONE], [Relay::WrongPassword, Relay::Working]);
    w.connect(config());
    assert!(w.signalled(0).iter().all(|c| c.candidate_type != CandidateType::Relayed), "no relay was granted, so none is offered");
    assert!(w.clients[0].bridge.as_ref().unwrap().relayed_addr().is_none());
    w.run_until_settled(20_000);
    assert!(w.both(ChecklistState::Completed), "host and reflexive candidates still connect");
}

// ─── The bridge's own rules ─────────────────────────────────────────

fn allocated_world() -> World {
    let mut w = World::new([SYM, SYM], OK);
    let t = w.t();
    for who in 0..2 {
        let step = w.clients[who].bridge.as_mut().unwrap().start(t);
        w.send_turn_step(who, step);
    }
    w.run_for(1000);
    w
}

fn send_action(from: SocketAddr, to: SocketAddr) -> IceAction {
    IceAction::Send { from, to, data: b"\x00\x01payload".to_vec() }
}

#[test]
fn route_splits_relayed_sends_from_direct_ones() {
    let w = allocated_world();
    let bridge = w.clients[0].bridge.as_ref().unwrap();
    let relayed = bridge.relayed_addr().expect("allocated");
    let peer = a("198.51.100.9:7000");

    let routed = bridge.route(vec![send_action(w.clients[0].host, peer), send_action(relayed, peer)]);
    assert_eq!(routed.direct.len(), 1, "the host-socket send leaves directly");
    assert_eq!(routed.via_turn.len(), 1, "the relayed send is wrapped for the TURN server");
    let TurnClientAction::Send { to, data } = &routed.via_turn[0];
    assert_eq!(*to, a(TURN), "wrapped sends go to the TURN server, not to the peer");
    let m = parse_message(data).unwrap();
    assert_eq!(format!("{:?}", m.method), "Send", "as a Send indication");
}

#[test]
fn a_relayed_send_is_dropped_not_diverted_once_the_allocation_is_gone() {
    let mut w = allocated_world();
    let relayed = w.clients[0].bridge.as_ref().unwrap().relayed_addr().unwrap();
    let t = w.t();
    let step = w.clients[0].bridge.as_mut().unwrap().deallocate(t);
    w.send_turn_step(0, step);
    w.run_for(200);

    let routed = w.clients[0].bridge.as_ref().unwrap().route(vec![send_action(relayed, a("198.51.100.9:7000"))]);
    assert!(routed.via_turn.is_empty(), "no allocation, nothing to wrap");
    assert!(routed.direct.is_empty(), "and it must NOT fall through to a real socket: that would bypass the relay and reveal the host address");
}

fn permission_ips(step: &TurnClientStep) -> Vec<IpAddr> {
    let TurnClientAction::Send { data, .. } = &step.actions[0];
    let m = parse_message(data).unwrap();
    decode_attributes(&m.attributes_raw, &m.transaction_id)
        .into_iter()
        .filter_map(|x| if let Attribute::XorPeerAddress(p) = x { Some(p.ip) } else { None })
        .collect()
}

#[test]
fn permissions_are_requested_once_per_remote_ip_and_again_as_the_list_grows() {
    let mut w = allocated_world();
    let t = w.t();
    let bridge = w.clients[0].bridge.as_mut().unwrap();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();

    let first = [host_cand(a("192.0.2.1:1")), srflx_cand(a("192.0.2.1:2"), a("192.0.2.1:1")), host_cand(a("192.0.2.2:1"))];
    let s1 = bridge.sync_permissions(&first, t);
    assert_eq!(permission_ips(&s1), vec![ip("192.0.2.1"), ip("192.0.2.2")], "each distinct IP, once");

    assert!(bridge.sync_permissions(&first, t).actions.is_empty(), "nothing new, nothing sent");

    let grown = [first[0].clone(), host_cand(a("192.0.2.3:1"))];
    let s3 = bridge.sync_permissions(&grown, t);
    assert_eq!(permission_ips(&s3), vec![ip("192.0.2.3")], "only the IP that is new");
}

#[test]
fn before_the_allocation_exists_nothing_is_asked_and_the_next_call_tries_again() {
    let mut w = World::new([SYM, SYM], OK);
    let t = w.t();
    let remote = [host_cand(a("192.0.2.1:1"))];
    assert!(w.clients[0].bridge.as_mut().unwrap().sync_permissions(&remote, t).actions.is_empty());

    let step = w.clients[0].bridge.as_mut().unwrap().start(t);
    w.send_turn_step(0, step);
    w.run_for(1000);
    let t = w.t();
    let retry = w.clients[0].bridge.as_mut().unwrap().sync_permissions(&remote, t);
    assert_eq!(retry.actions.len(), 1, "the earlier call must not have been remembered as done");
}

#[test]
fn a_permission_request_that_times_out_is_asked_for_again() {
    let mut w = allocated_world();
    let remote = [host_cand(a("192.0.2.1:1"))];
    let t = w.t();
    let step = w.clients[0].bridge.as_mut().unwrap().sync_permissions(&remote, t);
    w.blackhole = true; // the request never reaches the server
    w.send_turn_step(0, step);
    w.run_for(45_000); // the whole schedule is 0, .5, 1.5, 3.5, 7.5, 15.5, 31.5s, then a final 8s wait: 39.5s
    assert!(
        w.clients[0].turn_events.iter().any(|e| matches!(e, TurnClientEvent::PermissionFailed { code: None })),
        "the timeout must surface"
    );

    w.blackhole = false;
    let t = w.t();
    let again = w.clients[0].bridge.as_mut().unwrap().sync_permissions(&remote, t);
    assert_eq!(again.actions.len(), 1, "a failed request must not be remembered as granted");
}
