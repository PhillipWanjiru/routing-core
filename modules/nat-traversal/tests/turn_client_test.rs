//! The sans-IO TURN client (RFC 5766).
//!
//! Two kinds of test. Most run the client against the **real** `TurnServer` in
//! memory, so each side is checked against the other rather than against itself.
//! The rest use a *scripted* server, for the things a correct server never does:
//! forged, unsigned, misrouted and stale-nonce responses.
//!
//! Time is virtual throughout.

use nat_traversal::stun::{
    attributes::{decode_attributes, encode_xor_mapped_address, Attribute, ATTR_LIFETIME, ATTR_XOR_PEER_ADDRESS},
    builder::{
        build_401_challenge, build_438_stale_nonce, build_allocate_success_response_with_mapped,
        build_attribute, build_message,
    },
    integrity::{append_integrity, verify_integrity},
    parser::{parse_message, MessageClass, Method},
    SocketAddrAttr,
};
use nat_traversal::turn::relay::{build_channel_data, classify_datagram, parse_channel_data, DatagramKind};
use nat_traversal::turn::{
    build_authenticated_request_with, generate_nonce, long_term_key, CredentialStore, PortPool,
    TurnClient, TurnClientAction, TurnClientConfig, TurnClientEvent, TurnClientPhase,
    TurnClientStep, TurnOutput, TurnServer,
};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const REALM: &str = "routing-core.local";
const USER: &str = "alice";
const PASS: &str = "correcthorsebatterystaple";
const SERVER: &str = "203.0.113.10:3478";
const CLIENT: &str = "198.51.100.1:5000";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn peer(n: u8, port: u16) -> SocketAddr {
    a(&format!("192.0.2.{n}:{port}"))
}
fn ip(n: u8) -> IpAddr {
    peer(n, 0).ip()
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
fn key() -> [u8; 16] {
    long_term_key(USER, REALM, PASS)
}
fn config() -> TurnClientConfig {
    TurnClientConfig::new(a(SERVER), USER, PASS)
}
fn real_server() -> TurnServer {
    let mut creds = CredentialStore::new();
    creds.add_user(USER, PASS);
    TurnServer::new(REALM, a(SERVER).ip(), creds, PortPool::new(50000, 50010))
}

// ─── Wiring the client to the real server ──────────────────────────

struct World {
    server: TurnServer,
    client: TurnClient,
    t0: Instant,
    now: Instant,
    /// Every datagram the client sent.
    sent: Vec<Vec<u8>>,
    /// What the server relayed out of the client's relay socket.
    to_peers: Vec<(u16, SocketAddr, Vec<u8>)>,
    relay_events: Vec<TurnOutput>,
}

impl World {
    fn with_config(cfg: TurnClientConfig) -> World {
        let t0 = Instant::now();
        World {
            server: real_server(), client: TurnClient::new(cfg), t0, now: t0,
            sent: Vec::new(), to_peers: Vec::new(), relay_events: Vec::new(),
        }
    }
    fn new() -> World {
        World::with_config(config())
    }
    fn advance(&mut self, secs: u64) {
        self.now += Duration::from_secs(secs);
    }

    /// Run the client's outgoing datagrams through the server and back.
    fn pump(&mut self, step: TurnClientStep) -> Vec<TurnClientEvent> {
        let mut events = step.events;
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        for TurnClientAction::Send { data, .. } in step.actions {
            self.sent.push(data.clone());
            queue.push_back(data);
        }
        while let Some(data) = queue.pop_front() {
            for out in self.server.handle_from_client(a(CLIENT), &data, self.now) {
                match out {
                    TurnOutput::ToClient { data, .. } => {
                        let s = self.client.handle_datagram(a(SERVER), &data, self.now);
                        events.extend(s.events);
                        for TurnClientAction::Send { data, .. } in s.actions {
                            self.sent.push(data.clone());
                            queue.push_back(data);
                        }
                    }
                    TurnOutput::ToPeer { relay_port, to, data } => self.to_peers.push((relay_port, to, data)),
                    other => self.relay_events.push(other),
                }
            }
        }
        events
    }

    fn start(&mut self) -> Vec<TurnClientEvent> {
        let s = self.client.start(self.now);
        self.pump(s)
    }
    fn allocated() -> World {
        let mut w = World::new();
        let events = w.start();
        assert!(matches!(&events[..], [TurnClientEvent::Allocated { .. }]), "setup: {events:?}");
        w
    }
    fn poll(&mut self) -> Vec<TurnClientEvent> {
        let s = self.client.poll(self.now);
        self.pump(s)
    }
    fn permit(&mut self, ips: &[IpAddr]) -> Vec<TurnClientEvent> {
        let s = self.client.create_permission(ips, self.now);
        self.pump(s)
    }
    fn bind(&mut self, p: SocketAddr) -> Vec<TurnClientEvent> {
        let s = self.client.channel_bind(p, self.now);
        self.pump(s)
    }
    fn send(&mut self, p: SocketAddr, payload: &[u8]) {
        if let Some(action) = self.client.send_to_peer(p, payload) {
            self.pump(TurnClientStep { actions: vec![action], events: vec![] });
        }
    }
    /// A peer sends `data` to the client's relayed address.
    fn peer_sends(&mut self, from: SocketAddr, data: &[u8]) -> Vec<TurnClientEvent> {
        let port = self.client.relayed_addr().expect("allocated").port();
        let mut events = Vec::new();
        for out in self.server.handle_from_peer(port, from, data, self.now) {
            if let TurnOutput::ToClient { data, .. } = out {
                events.extend(self.client.handle_datagram(a(SERVER), &data, self.now).events);
            }
        }
        events
    }
}

// ─── A scripted server, for what a correct server never does ───────

fn txn_of(raw: &[u8]) -> [u8; 12] {
    parse_message(raw).unwrap().transaction_id
}
fn attrs_of(raw: &[u8]) -> Vec<Attribute> {
    let m = parse_message(raw).unwrap();
    decode_attributes(&m.attributes_raw, &m.transaction_id)
}
fn only_send(step: &TurnClientStep) -> Vec<u8> {
    assert_eq!(step.actions.len(), 1, "expected exactly one datagram, got {step:?}");
    let TurnClientAction::Send { data, .. } = &step.actions[0];
    data.clone()
}
fn signed_success(txn: &[u8; 12], with_key: &[u8]) -> Vec<u8> {
    let relayed = SocketAddrAttr { ip: a(SERVER).ip(), port: 50001 };
    let mapped = SocketAddrAttr { ip: a(CLIENT).ip(), port: a(CLIENT).port() };
    let mut m = build_allocate_success_response_with_mapped(txn, relayed, mapped, 600);
    append_integrity(&mut m, with_key);
    m
}
/// A client taken through the 401 challenge, now waiting on its authenticated Allocate.
fn challenged(now: Instant) -> (TurnClient, Vec<u8>) {
    let mut c = TurnClient::new(config());
    let first = only_send(&c.start(now));
    let challenge = build_401_challenge(Method::Allocate, &txn_of(&first), REALM, "nonce-one");
    let auth = only_send(&c.handle_datagram(a(SERVER), &challenge, now));
    (c, auth)
}

// ─── Allocation ────────────────────────────────────────────────────

#[test]
fn the_first_request_is_an_unauthenticated_allocate_for_udp() {
    let mut c = TurnClient::new(config());
    let first = only_send(&c.start(Instant::now()));
    let m = parse_message(&first).unwrap();
    assert_eq!((m.class, m.method), (MessageClass::Request, Method::Allocate));
    let attrs = attrs_of(&first);
    assert!(attrs.contains(&Attribute::RequestedTransport(17)), "REQUESTED-TRANSPORT must ask for UDP");
    assert!(!attrs.iter().any(|x| matches!(x, Attribute::Username(_))), "no credentials before the server asks");
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
}

#[test]
fn starting_twice_does_nothing_the_second_time() {
    let mut c = TurnClient::new(config());
    let now = Instant::now();
    c.start(now);
    assert!(c.start(now).actions.is_empty());
}

#[test]
fn allocation_completes_through_the_real_server() {
    let mut w = World::new();
    let events = w.start();
    let relayed = w.client.relayed_addr().unwrap();
    assert_eq!(events, vec![TurnClientEvent::Allocated { relayed, mapped: a(CLIENT), lifetime_secs: 600 }]);
    assert_eq!(relayed.ip(), a(SERVER).ip(), "the relay address is on the server, not the client");
    assert_eq!(relayed.port(), w.server.allocation_for(&a(CLIENT)).unwrap().relay_port);
    assert_eq!(w.client.mapped_addr(), Some(a(CLIENT)), "and the client learned its reflexive address for free");
    assert_eq!(w.client.phase(), TurnClientPhase::Allocated);
}

#[test]
fn the_password_never_appears_on_the_wire() {
    let mut w = World::new();
    w.start();
    assert_eq!(w.sent.len(), 2, "one unauthenticated request, one authenticated retry");
    for (i, datagram) in w.sent.iter().enumerate() {
        assert!(
            !datagram.windows(PASS.len()).any(|win| win == PASS.as_bytes()),
            "datagram {i} contains the password: long-term credentials must send only a keyed hash"
        );
    }
}

#[test]
fn the_authenticated_retry_is_signed_with_the_long_term_key() {
    let mut w = World::new();
    w.start();
    assert!(verify_integrity(&w.sent[1], &key()));
    assert!(attrs_of(&w.sent[1]).iter().any(|x| matches!(x, Attribute::Username(u) if u == USER)));
}

#[test]
fn a_wrong_password_fails_with_401_and_does_not_loop() {
    let mut cfg = config();
    cfg.password = "not-the-password".into();
    let mut w = World::with_config(cfg);
    let events = w.start();
    assert_eq!(events, vec![TurnClientEvent::AllocationFailed { code: Some(401) }]);
    assert_eq!(w.client.phase(), TurnClientPhase::Failed);
    assert_eq!(w.sent.len(), 2, "exactly two requests: a rejected credential must not be retried");
    assert!(w.server.allocation_for(&a(CLIENT)).is_none());
}

#[test]
fn a_requested_lifetime_is_sent_and_granted() {
    let mut cfg = config();
    cfg.requested_lifetime = Some(1200);
    let mut w = World::with_config(cfg);
    let events = w.start();
    assert!(matches!(&events[..], [TurnClientEvent::Allocated { lifetime_secs: 1200, .. }]), "{events:?}");
}

// ─── A client must not believe a forged server ─────────────────────

#[test]
fn a_success_signed_with_the_wrong_key_is_ignored() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let forged = signed_success(&txn_of(&auth), &long_term_key(USER, REALM, "attacker-guess"));
    let step = c.handle_datagram(a(SERVER), &forged, now);
    assert!(step.events.is_empty(), "a forged success must not allocate");
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
    assert!(c.relayed_addr().is_none());

    // The transaction ran on: the genuine answer still works.
    let genuine = signed_success(&txn_of(&auth), &key());
    assert!(matches!(&c.handle_datagram(a(SERVER), &genuine, now).events[..], [TurnClientEvent::Allocated { .. }]));
}

#[test]
fn an_unsigned_success_is_ignored() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let relayed = SocketAddrAttr { ip: a(SERVER).ip(), port: 50001 };
    let mapped = SocketAddrAttr { ip: a(CLIENT).ip(), port: 5000 };
    let unsigned = build_allocate_success_response_with_mapped(&txn_of(&auth), relayed, mapped, 600);
    assert!(c.handle_datagram(a(SERVER), &unsigned, now).events.is_empty());
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
}

#[test]
fn a_genuine_success_from_another_address_is_ignored() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let genuine = signed_success(&txn_of(&auth), &key());
    let step = c.handle_datagram(a("198.51.100.99:3478"), &genuine, now);
    assert!(step.events.is_empty() && step.actions.is_empty(), "only the configured server is believed");
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
}

#[test]
fn a_response_with_the_right_transaction_but_the_wrong_method_is_ignored() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let mut wrong = build_message(MessageClass::SuccessResponse, Method::Refresh, &txn_of(&auth), &[]);
    append_integrity(&mut wrong, &key());
    assert!(c.handle_datagram(a(SERVER), &wrong, now).events.is_empty());
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
}

#[test]
fn a_success_to_the_unauthenticated_request_is_ignored() {
    // Before the challenge the client has no key, so nothing it could be sent
    // can be verified — and a success to an unauthenticated Allocate is
    // something no real server produces.
    let now = Instant::now();
    let mut c = TurnClient::new(config());
    let first = only_send(&c.start(now));
    // The attacker cannot know the real key, but a careless client might fall
    // back to a default one — so forge with the plausible fallbacks too.
    for forging_key in [&key()[..], &[][..], &[0u8; 16][..]] {
        let forged = signed_success(&txn_of(&first), forging_key);
        assert!(c.handle_datagram(a(SERVER), &forged, now).events.is_empty(), "key {forging_key:?}");
    }
    assert_eq!(c.phase(), TurnClientPhase::Allocating);
}

#[test]
fn an_unsolicited_response_is_ignored() {
    let now = Instant::now();
    let (mut c, _) = challenged(now);
    let stray = signed_success(&[0xEE; 12], &key());
    assert!(c.handle_datagram(a(SERVER), &stray, now).events.is_empty());
}

#[test]
fn a_signed_success_missing_the_relayed_address_fails_the_allocation() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let mut thin = build_message(
        MessageClass::SuccessResponse, Method::Allocate, &txn_of(&auth),
        &build_attribute(ATTR_LIFETIME, &600u32.to_be_bytes()),
    );
    append_integrity(&mut thin, &key());
    let step = c.handle_datagram(a(SERVER), &thin, now);
    assert_eq!(step.events, vec![TurnClientEvent::AllocationFailed { code: None }]);
    assert_eq!(c.phase(), TurnClientPhase::Failed);
}

// ─── Stale nonces and rejected credentials ─────────────────────────

#[test]
fn a_stale_nonce_is_adopted_and_the_request_retried() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let stale = build_438_stale_nonce(Method::Allocate, &txn_of(&auth), REALM, "fresh-nonce-1");
    let retry = only_send(&c.handle_datagram(a(SERVER), &stale, now));
    assert!(attrs_of(&retry).iter().any(|x| matches!(x, Attribute::Nonce(n) if n == "fresh-nonce-1")));
    assert_ne!(txn_of(&retry), txn_of(&auth), "a retry is a new transaction");
    assert!(verify_integrity(&retry, &key()));
}

#[test]
fn repeated_stale_nonces_eventually_give_up() {
    let now = Instant::now();
    let (mut c, mut req) = challenged(now);
    for _ in 0..2 {
        let stale = build_438_stale_nonce(Method::Allocate, &txn_of(&req), REALM, "n");
        req = only_send(&c.handle_datagram(a(SERVER), &stale, now));
    }
    let stale = build_438_stale_nonce(Method::Allocate, &txn_of(&req), REALM, "n");
    let step = c.handle_datagram(a(SERVER), &stale, now);
    assert_eq!(step.events, vec![TurnClientEvent::AllocationFailed { code: Some(438) }]);
    assert!(step.actions.is_empty(), "a server that never accepts a nonce must not be hammered forever");
}

#[test]
fn a_401_to_the_authenticated_request_fails_without_retrying() {
    let now = Instant::now();
    let (mut c, auth) = challenged(now);
    let again = build_401_challenge(Method::Allocate, &txn_of(&auth), REALM, "other-nonce");
    let step = c.handle_datagram(a(SERVER), &again, now);
    assert_eq!(step.events, vec![TurnClientEvent::AllocationFailed { code: Some(401) }]);
    assert!(step.actions.is_empty());
}

// ─── Retransmission ────────────────────────────────────────────────

#[test]
fn an_unanswered_allocate_retransmits_identically_with_backoff_then_fails() {
    let mut cfg = config();
    cfg.rto = ms(100);
    cfg.max_transmissions = 3;
    cfg.final_wait_multiplier = 4;
    let t0 = Instant::now();
    let mut c = TurnClient::new(cfg);
    let first = only_send(&c.start(t0));

    assert!(c.poll(t0 + ms(99)).actions.is_empty());
    assert_eq!(only_send(&c.poll(t0 + ms(100))), first, "a retransmission is byte-identical");
    assert!(c.poll(t0 + ms(299)).actions.is_empty(), "the interval doubled");
    assert_eq!(only_send(&c.poll(t0 + ms(300))), first);
    assert!(c.poll(t0 + ms(699)).events.is_empty(), "after the last send it waits out Rm * RTO");
    let end = c.poll(t0 + ms(700));
    assert_eq!(end.events, vec![TurnClientEvent::AllocationFailed { code: None }]);
    assert_eq!(c.phase(), TurnClientPhase::Failed);
}

// ─── Refresh and deallocation ──────────────────────────────────────

#[test]
fn the_allocation_is_refreshed_at_half_its_lifetime_and_the_server_extends_it() {
    let mut w = World::allocated();
    let before = w.sent.len();
    w.advance(299);
    assert!(w.poll().is_empty());
    assert_eq!(w.sent.len(), before, "nothing is sent before the half-life");

    w.advance(1); // 300 s
    assert_eq!(w.poll(), vec![TurnClientEvent::Refreshed { lifetime_secs: 600 }]);
    assert!(
        w.server.sweep(w.t0 + Duration::from_secs(700)).is_empty(),
        "without the refresh the 600s allocation would have expired by 700s"
    );

    w.advance(300); // 600 s: half of the new lifetime again
    assert_eq!(w.poll(), vec![TurnClientEvent::Refreshed { lifetime_secs: 600 }], "and it keeps refreshing");
}

#[test]
fn a_refresh_the_server_no_longer_recognises_means_the_allocation_is_lost() {
    let mut w = World::allocated();
    w.server = real_server(); // the server restarted and forgot everything
    w.advance(300);
    assert_eq!(w.poll(), vec![TurnClientEvent::AllocationLost]);
    assert_eq!(w.client.phase(), TurnClientPhase::Failed);
    assert!(w.client.send_to_peer(peer(7, 9000), b"x").is_none(), "a lost allocation can carry no data");
}

#[test]
fn deallocating_releases_the_relay_and_closes_the_client() {
    let mut w = World::allocated();
    let port = w.client.relayed_addr().unwrap().port();
    let s = w.client.deallocate(w.now);
    assert_eq!(w.pump(s), vec![TurnClientEvent::Closed]);
    assert!(w.relay_events.contains(&TurnOutput::RelayClosed { relay_port: port }));
    assert!(w.server.allocation_for(&a(CLIENT)).is_none());
    assert_eq!(w.client.phase(), TurnClientPhase::Closed);
    assert!(w.client.send_to_peer(peer(7, 9000), b"x").is_none());
}

// ─── Permissions and data ──────────────────────────────────────────

#[test]
fn a_permission_lets_peer_data_reach_the_client() {
    let mut w = World::allocated();
    assert_eq!(w.permit(&[ip(7)]), vec![TurnClientEvent::PermissionInstalled { peer_ips: vec![ip(7)] }]);
    let p = peer(7, 9000);
    assert_eq!(w.peer_sends(p, b"hello"), vec![TurnClientEvent::Data { peer: p, payload: b"hello".to_vec() }]);
}

#[test]
fn peer_data_without_a_permission_does_not_reach_the_client() {
    let mut w = World::allocated();
    assert!(w.peer_sends(peer(7, 9000), b"hello").is_empty(), "the server's permission barrier holds");
}

#[test]
fn send_to_peer_goes_through_the_server_as_a_send_indication() {
    let mut w = World::allocated();
    let (p, port) = (peer(7, 9000), w.client.relayed_addr().unwrap().port());
    w.permit(&[ip(7)]);
    w.send(p, b"payload");

    assert_eq!(w.to_peers, vec![(port, p, b"payload".to_vec())]);
    let last = parse_message(w.sent.last().unwrap()).unwrap();
    assert_eq!((last.class, last.method), (MessageClass::Indication, Method::Send));
}

#[test]
fn without_a_permission_the_server_drops_what_the_client_sends() {
    let mut w = World::allocated();
    w.send(peer(7, 9000), b"payload");
    assert!(w.to_peers.is_empty(), "the client sent it, but the server must not relay without a permission");
}

#[test]
fn sending_before_allocation_is_refused() {
    let c = TurnClient::new(config());
    assert!(c.send_to_peer(peer(7, 9000), b"x").is_none());
}

#[test]
fn creating_a_permission_before_allocation_does_nothing() {
    let mut c = TurnClient::new(config());
    assert!(c.create_permission(&[ip(7)], Instant::now()).actions.is_empty());
}

#[test]
fn permissions_are_refreshed_before_they_expire() {
    let mut w = World::allocated();
    w.permit(&[ip(7)]);
    w.advance(239);
    assert!(w.poll().is_empty(), "not yet due");
    w.advance(1); // 240 s
    assert_eq!(w.poll(), vec![TurnClientEvent::PermissionInstalled { peer_ips: vec![ip(7)] }]);
    assert!(
        w.server.has_permission(&a(CLIENT), ip(7), w.t0 + Duration::from_secs(350)),
        "300s after the first install it would have lapsed; the refresh kept it alive"
    );
}

// ─── Channels ──────────────────────────────────────────────────────

#[test]
fn a_channel_bind_succeeds_and_later_sends_use_channel_data() {
    let mut w = World::allocated();
    let p = peer(7, 9000);
    assert_eq!(w.bind(p), vec![TurnClientEvent::ChannelBound { channel: 0x4000, peer: p }]);
    assert_eq!(w.client.channel_for(&p), Some(0x4000));

    let TurnClientAction::Send { data, .. } = w.client.send_to_peer(p, b"media").unwrap();
    assert_eq!(classify_datagram(&data), DatagramKind::ChannelData);
    let framed = parse_channel_data(&data).unwrap();
    assert_eq!((framed.channel_number, framed.payload.as_slice()), (0x4000, &b"media"[..]));
}

#[test]
fn channel_data_flows_to_the_peer_through_the_server() {
    let mut w = World::allocated();
    let (p, port) = (peer(7, 9000), w.client.relayed_addr().unwrap().port());
    w.bind(p); // binding also installs the permission, so no CreatePermission is needed
    w.send(p, b"media");
    assert_eq!(w.to_peers, vec![(port, p, b"media".to_vec())]);
}

#[test]
fn peer_data_arrives_as_channel_data_once_a_channel_is_bound() {
    let mut w = World::allocated();
    let p = peer(7, 9000);
    w.bind(p);
    assert_eq!(w.peer_sends(p, b"reply"), vec![TurnClientEvent::Data { peer: p, payload: b"reply".to_vec() }]);
}

#[test]
fn binding_the_same_peer_twice_sends_nothing_the_second_time() {
    let mut w = World::allocated();
    let p = peer(7, 9000);
    w.bind(p);
    assert!(w.client.channel_bind(p, w.now).actions.is_empty());
}

#[test]
fn a_channel_bind_the_server_rejects_is_reported() {
    let mut w = World::allocated();
    // Occupy channel 0x4000 for another peer, behind the client's back.
    let other = peer(8, 9001);
    let t = [0x77; 12];
    let mut extras = build_attribute(0x000C, &[0x40, 0x00, 0, 0]);
    extras.extend_from_slice(&build_attribute(
        ATTR_XOR_PEER_ADDRESS,
        &encode_xor_mapped_address(&SocketAddrAttr { ip: other.ip(), port: other.port() }, &t),
    ));
    let raw = build_authenticated_request_with(
        Method::ChannelBind, &t, &extras, USER, REALM, &generate_nonce(), PASS,
    );
    w.server.handle_from_client(a(CLIENT), &raw, w.now);

    // The client's first choice is now taken.
    let p = peer(7, 9000);
    assert_eq!(w.bind(p), vec![TurnClientEvent::ChannelBindFailed { peer: p, code: Some(400) }]);
    assert!(w.client.channel_for(&p).is_none());
}

#[test]
fn channels_are_refreshed_before_they_expire() {
    let mut w = World::allocated();
    let p = peer(7, 9000);
    w.bind(p);
    w.advance(300);
    let events = w.poll();
    assert!(!events.iter().any(|e| matches!(e, TurnClientEvent::ChannelBound { .. })), "a refresh is not a new binding");
    assert!(
        w.server.channel_peer(&a(CLIENT), 0x4000, w.t0 + Duration::from_secs(650)).is_some(),
        "the 600s binding would have expired by 650s without the refresh"
    );
}

// ─── Robustness ────────────────────────────────────────────────────

#[test]
fn data_on_an_unbound_channel_is_dropped() {
    let mut w = World::allocated();
    let step = w.client.handle_datagram(a(SERVER), &build_channel_data(0x4005, b"x"), w.now);
    assert!(step.events.is_empty());
}

#[test]
fn garbage_and_datagrams_from_other_addresses_are_ignored() {
    let mut w = World::allocated();
    assert!(w.client.handle_datagram(a(SERVER), &[0xFF; 12], w.now).events.is_empty());
    assert!(w.client.handle_datagram(a(SERVER), &[], w.now).events.is_empty());
    let from_elsewhere = nat_traversal::stun::builder::build_data_indication(&[1; 12], peer(7, 9000), b"x");
    assert!(w.client.handle_datagram(a("198.51.100.99:3478"), &from_elsewhere, w.now).events.is_empty());
}

#[test]
fn a_data_indication_before_allocation_is_ignored() {
    let mut c = TurnClient::new(config());
    let data = nat_traversal::stun::builder::build_data_indication(&[1; 12], peer(7, 9000), b"x");
    assert!(c.handle_datagram(a(SERVER), &data, Instant::now()).events.is_empty());
}

#[test]
fn next_wakeup_tracks_the_earliest_deadline() {
    let t0 = Instant::now();
    let mut c = TurnClient::new(config());
    assert_eq!(c.next_wakeup(), None, "an idle client has nothing to wake for");
    c.start(t0);
    assert_eq!(c.next_wakeup(), Some(t0 + ms(500)), "the first retransmission");

    let w = World::allocated();
    assert_eq!(w.client.next_wakeup(), Some(w.t0 + Duration::from_secs(300)), "then the half-life refresh");
}

#[test]
fn a_permission_request_answered_with_437_means_the_allocation_is_lost() {
    let mut w = World::allocated();
    w.server = real_server(); // the server restarted and forgot the allocation
    assert_eq!(w.permit(&[ip(7)]), vec![TurnClientEvent::AllocationLost]);
    assert_eq!(w.client.phase(), TurnClientPhase::Failed);
}

#[test]
fn a_channel_bind_answered_with_437_means_the_allocation_is_lost() {
    let mut w = World::allocated();
    w.server = real_server();
    assert_eq!(w.bind(peer(7, 9000)), vec![TurnClientEvent::AllocationLost]);
    assert_eq!(w.client.phase(), TurnClientPhase::Failed);
}
