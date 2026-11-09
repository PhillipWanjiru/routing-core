//! The sans-IO TURN server core (RFC 5766), driven by a scripted client.
//!
//! Time is virtual — every call passes an explicit `Instant` — so lifetimes and
//! expiry are tested exactly, with no sleeping. The client here builds its
//! requests with the same codec the server parses with, so a mismatch between
//! the two would show up as a failing test rather than hiding in agreement.
//!
//! The properties that matter most are the *negative* ones: this server must not
//! be an open relay, must not leak one client's state to another, and must not
//! let a dead allocation's permissions outlive it.

use nat_traversal::stun::{
    attributes::{
        decode_attributes, encode_xor_mapped_address, Attribute, ATTR_CHANNEL_NUMBER, ATTR_DATA,
        ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT, ATTR_XOR_PEER_ADDRESS,
    },
    builder::{
        build_allocate_success_response_with_mapped, build_attribute, build_data_indication,
        build_message, build_send_indication, encode_channel_number, encode_requested_transport,
        IP_PROTOCOL_UDP,
    },
    integrity::verify_integrity,
    parser::{parse_message, MessageClass, Method},
    SocketAddrAttr,
};
use nat_traversal::turn::relay::{build_channel_data, parse_channel_data};
use nat_traversal::turn::{
    build_authenticated_request, build_authenticated_request_with, generate_nonce, long_term_key,
    CredentialStore, PortPool, TurnOutput, TurnServer,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const REALM: &str = "routing-core.local";
const USER: &str = "alice";
const PASS: &str = "correcthorsebatterystaple";
/// The server's own address — what relayed transport addresses must be on.
const RELAY_IP: &str = "203.0.113.10";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn client(n: u8) -> SocketAddr {
    a(&format!("198.51.100.{n}:5000"))
}
fn peer(n: u8, port: u16) -> SocketAddr {
    a(&format!("192.0.2.{n}:{port}"))
}
fn txn(n: u8) -> [u8; 12] {
    [n; 12]
}
fn secs(t0: Instant, n: u64) -> Instant {
    t0 + Duration::from_secs(n)
}
fn server() -> TurnServer {
    let mut creds = CredentialStore::new();
    creds.add_user(USER, PASS);
    TurnServer::new(REALM, RELAY_IP.parse().unwrap(), creds, PortPool::new(50000, 50010))
}
fn key() -> [u8; 16] {
    long_term_key(USER, REALM, PASS)
}

// ─── The scripted client ───────────────────────────────────────────

fn authed(method: Method, extras: &[u8], t: &[u8; 12]) -> Vec<u8> {
    build_authenticated_request_with(method, t, extras, USER, REALM, &generate_nonce(), PASS)
}
fn transport_attr() -> Vec<u8> {
    build_attribute(ATTR_REQUESTED_TRANSPORT, &encode_requested_transport(IP_PROTOCOL_UDP))
}
fn peer_attr(p: SocketAddr, t: &[u8; 12]) -> Vec<u8> {
    let v = encode_xor_mapped_address(&SocketAddrAttr { ip: p.ip(), port: p.port() }, t);
    build_attribute(ATTR_XOR_PEER_ADDRESS, &v)
}
fn allocate_req(n: u8) -> Vec<u8> {
    authed(Method::Allocate, &transport_attr(), &txn(n))
}
fn permission_req(n: u8, peers: &[SocketAddr]) -> Vec<u8> {
    let t = txn(n);
    let extras: Vec<u8> = peers.iter().flat_map(|p| peer_attr(*p, &t)).collect();
    authed(Method::CreatePermission, &extras, &t)
}
fn channel_bind_req(n: u8, channel: u16, p: SocketAddr) -> Vec<u8> {
    let t = txn(n);
    let mut extras = build_attribute(ATTR_CHANNEL_NUMBER, &encode_channel_number(channel));
    extras.extend_from_slice(&peer_attr(p, &t));
    authed(Method::ChannelBind, &extras, &t)
}
fn refresh_req(n: u8, lifetime: u32) -> Vec<u8> {
    authed(Method::Refresh, &build_attribute(ATTR_LIFETIME, &lifetime.to_be_bytes()), &txn(n))
}

/// A parsed server message.
struct Msg {
    class: MessageClass,
    method: Method,
    attrs: Vec<Attribute>,
    raw: Vec<u8>,
}
fn parse(raw: &[u8]) -> Msg {
    let m = parse_message(raw).expect("the server must emit parseable STUN");
    let attrs = decode_attributes(&m.attributes_raw, &m.transaction_id);
    Msg { class: m.class, method: m.method, attrs, raw: raw.to_vec() }
}
fn replies(out: &[TurnOutput]) -> Vec<(SocketAddr, Vec<u8>)> {
    out.iter()
        .filter_map(|o| if let TurnOutput::ToClient { to, data } = o { Some((*to, data.clone())) } else { None })
        .collect()
}
/// The single reply the server sent to a client.
fn the_reply(out: &[TurnOutput]) -> Msg {
    let r = replies(out);
    assert_eq!(r.len(), 1, "expected exactly one reply, got {out:?}");
    parse(&r[0].1)
}
fn error_code(m: &Msg) -> u16 {
    m.attrs
        .iter()
        .find_map(|x| if let Attribute::ErrorCode { code, .. } = x { Some(*code) } else { None })
        .expect("an ERROR-CODE attribute")
}
fn is_success(m: &Msg) -> bool {
    m.class == MessageClass::SuccessResponse
}
fn xor_addr(m: &Msg, pick: fn(&Attribute) -> Option<&SocketAddrAttr>) -> SocketAddr {
    let x = m.attrs.iter().find_map(pick).expect("the address attribute");
    SocketAddr::new(x.ip, x.port)
}
fn relayed_addr(m: &Msg) -> SocketAddr {
    xor_addr(m, |x| if let Attribute::XorRelayedAddress(v) = x { Some(v) } else { None })
}
fn mapped_addr(m: &Msg) -> SocketAddr {
    xor_addr(m, |x| if let Attribute::XorMappedAddress(v) = x { Some(v) } else { None })
}
fn lifetime_of(m: &Msg) -> u32 {
    m.attrs.iter().find_map(|x| if let Attribute::Lifetime(l) = x { Some(*l) } else { None }).expect("LIFETIME")
}

/// Allocate for `c` and return its relay port.
fn allocate(s: &mut TurnServer, c: SocketAddr, now: Instant) -> u16 {
    let out = s.handle_from_client(c, &allocate_req(1), now);
    assert!(is_success(&the_reply(&out)), "setup: Allocate must succeed, got {out:?}");
    s.allocation_for(&c).expect("an allocation").relay_port
}
fn permit(s: &mut TurnServer, c: SocketAddr, peers: &[SocketAddr], now: Instant) {
    let out = s.handle_from_client(c, &permission_req(2, peers), now);
    assert!(is_success(&the_reply(&out)), "setup: CreatePermission must succeed, got {out:?}");
}
fn send(s: &mut TurnServer, c: SocketAddr, to: SocketAddr, payload: &[u8], now: Instant) -> Vec<TurnOutput> {
    s.handle_from_client(c, &build_send_indication(&txn(9), to, payload), now)
}

// ─── Allocate ──────────────────────────────────────────────────────

#[test]
fn an_unauthenticated_allocate_is_challenged_and_creates_nothing() {
    let mut s = server();
    let c = client(1);
    let bare = build_message(MessageClass::Request, Method::Allocate, &txn(1), &transport_attr());
    let out = s.handle_from_client(c, &bare, Instant::now());

    let m = the_reply(&out);
    assert_eq!(m.class, MessageClass::ErrorResponse);
    assert_eq!(error_code(&m), 401);
    assert!(m.attrs.iter().any(|x| matches!(x, Attribute::Realm(r) if r == REALM)), "the challenge names the realm");
    assert!(m.attrs.iter().any(|x| matches!(x, Attribute::Nonce(_))), "and supplies a nonce");
    assert!(s.allocation_for(&c).is_none());
    assert!(!out.iter().any(|o| matches!(o, TurnOutput::RelayOpened { .. })));
}

#[test]
fn an_authenticated_allocate_reports_the_servers_relay_ip_not_the_clients() {
    let mut s = server();
    let c = client(1);
    let m = the_reply(&s.handle_from_client(c, &allocate_req(1), Instant::now()));
    assert!(is_success(&m));
    let relayed = relayed_addr(&m);
    assert_eq!(relayed.ip(), a(&format!("{RELAY_IP}:1")).ip(), "the relay address must be on the server");
    assert_ne!(relayed.ip(), c.ip(), "advertising the client's own IP would hand out an unreachable relay");
    assert!((50000..=50010).contains(&relayed.port()));
    assert_eq!(relayed.port(), s.allocation_for(&c).unwrap().relay_port);
}

#[test]
fn allocate_reports_the_clients_reflexive_address() {
    let mut s = server();
    let c = client(1);
    let m = the_reply(&s.handle_from_client(c, &allocate_req(1), Instant::now()));
    assert_eq!(mapped_addr(&m), c, "XOR-MAPPED-ADDRESS tells the client how the server sees it");
}

#[test]
fn allocate_grants_the_default_lifetime() {
    let mut s = server();
    let m = the_reply(&s.handle_from_client(client(1), &allocate_req(1), Instant::now()));
    assert_eq!(lifetime_of(&m), 600);
}

#[test]
fn the_allocate_success_is_signed_so_the_client_can_verify_it() {
    let mut s = server();
    let m = the_reply(&s.handle_from_client(client(1), &allocate_req(1), Instant::now()));
    assert!(verify_integrity(&m.raw, &key()), "a forged success could point a client at an attacker's relay");
    assert!(!verify_integrity(&m.raw, &long_term_key(USER, REALM, "not-the-password")));
}

#[test]
fn allocate_requires_requested_transport() {
    let mut s = server();
    let c = client(1);
    let no_transport = authed(Method::Allocate, &[], &txn(1));
    let m = the_reply(&s.handle_from_client(c, &no_transport, Instant::now()));
    assert_eq!(error_code(&m), 400);
    assert!(s.allocation_for(&c).is_none());
}

#[test]
fn allocate_rejects_a_non_udp_transport() {
    let mut s = server();
    let c = client(1);
    let tcp = build_attribute(ATTR_REQUESTED_TRANSPORT, &encode_requested_transport(6));
    let m = the_reply(&s.handle_from_client(c, &authed(Method::Allocate, &tcp, &txn(1)), Instant::now()));
    assert_eq!(error_code(&m), 442);
    assert!(s.allocation_for(&c).is_none());
}

#[test]
fn allocate_announces_the_relay_socket_before_the_reply() {
    let mut s = server();
    let c = client(1);
    let out = s.handle_from_client(c, &allocate_req(1), Instant::now());
    let port = s.allocation_for(&c).unwrap().relay_port;
    assert_eq!(out[0], TurnOutput::RelayOpened { relay_port: port }, "the driver must be ready before the client can pass the address on");
    assert!(matches!(out[1], TurnOutput::ToClient { .. }));
    assert_eq!(out.len(), 2);
}

#[test]
fn a_second_allocate_from_the_same_client_does_not_reopen_the_relay() {
    let mut s = server();
    let c = client(1);
    let port = allocate(&mut s, c, Instant::now());
    let again = s.handle_from_client(c, &allocate_req(2), Instant::now());
    assert!(!again.iter().any(|o| matches!(o, TurnOutput::RelayOpened { .. })));
    assert_eq!(s.allocation_for(&c).unwrap().relay_port, port);
}

#[test]
fn an_allocate_with_the_wrong_password_is_rejected_and_creates_nothing() {
    let mut s = server();
    let c = client(1);
    let req = build_authenticated_request_with(
        Method::Allocate, &txn(1), &transport_attr(), USER, REALM, &generate_nonce(), "wrong-password",
    );
    let out = s.handle_from_client(c, &req, Instant::now());
    assert_eq!(error_code(&the_reply(&out)), 401);
    assert!(s.allocation_for(&c).is_none());
    assert!(!out.iter().any(|o| matches!(o, TurnOutput::RelayOpened { .. })));
}

#[test]
fn different_clients_get_different_relay_ports() {
    let mut s = server();
    let (p1, p2) = (allocate(&mut s, client(1), Instant::now()), allocate(&mut s, client(2), Instant::now()));
    assert_ne!(p1, p2);
}

#[test]
fn a_binding_request_on_the_turn_port_is_answered_like_a_stun_server() {
    let mut s = server();
    let c = client(1);
    let req = build_message(MessageClass::Request, Method::Binding, &txn(1), &[]);
    let m = the_reply(&s.handle_from_client(c, &req, Instant::now()));
    assert!(is_success(&m));
    assert_eq!(mapped_addr(&m), c);
}

// ─── Refresh, expiry, and state that must die with an allocation ───

#[test]
fn refresh_grants_the_requested_lifetime_and_is_signed() {
    let mut s = server();
    let c = client(1);
    allocate(&mut s, c, Instant::now());
    let m = the_reply(&s.handle_from_client(c, &refresh_req(3, 1200), Instant::now()));
    assert!(is_success(&m));
    assert_eq!(lifetime_of(&m), 1200);
    assert!(verify_integrity(&m.raw, &key()));
}

#[test]
fn refresh_without_an_allocation_is_437() {
    let mut s = server();
    let m = the_reply(&s.handle_from_client(client(1), &refresh_req(3, 600), Instant::now()));
    assert_eq!(error_code(&m), 437);
}

#[test]
fn refresh_zero_deallocates_and_closes_the_relay() {
    let mut s = server();
    let c = client(1);
    let port = allocate(&mut s, c, Instant::now());
    let out = s.handle_from_client(c, &refresh_req(3, 0), Instant::now());
    assert!(is_success(&the_reply(&out)));
    assert!(out.contains(&TurnOutput::RelayClosed { relay_port: port }));
    assert!(s.allocation_for(&c).is_none());
}

#[test]
fn refresh_zero_clears_the_permissions_and_channels() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    s.handle_from_client(c, &channel_bind_req(4, 0x4001, p), now);
    assert!(s.has_permission(&c, p.ip(), now) && s.channel_peer(&c, 0x4001, now).is_some(), "setup");

    s.handle_from_client(c, &refresh_req(3, 0), now);
    assert!(!s.has_permission(&c, p.ip(), now), "a deallocated client must keep no permissions");
    assert!(s.channel_peer(&c, 0x4001, now).is_none(), "nor channel bindings");
}

#[test]
fn a_new_allocation_does_not_inherit_the_previous_ones_permissions() {
    // The leak this guards against: deallocate, allocate again from the same
    // address — and find the old permissions still working.
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    permit(&mut s, c, &[p], now);
    s.handle_from_client(c, &refresh_req(3, 0), now);

    allocate(&mut s, c, now);
    assert!(send(&mut s, c, p, b"x", now).is_empty(), "the new allocation never asked to talk to that peer");
}

#[test]
fn sweep_expires_allocations_and_reports_the_relay_closed() {
    let mut s = server();
    let (c, p, t0) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, t0);
    permit(&mut s, c, &[p], t0);

    assert!(s.sweep(secs(t0, 100)).is_empty(), "a live allocation is left alone");
    let out = s.sweep(secs(t0, 601));
    assert_eq!(out, vec![TurnOutput::RelayClosed { relay_port: port }]);
    assert!(s.allocation_for(&c).is_none());
}

#[test]
fn expiry_clears_permissions_and_channels_that_are_still_live() {
    // Permissions last 300s and bindings 600s, so with default timing both are
    // long dead when a 600s allocation expires — which would make "expiry clears
    // them" untestable: they would be gone anyway. Refresh both late so they are
    // still live at the moment the allocation expires; only the sweep can then
    // remove them. (The earlier version of this check passed vacuously.)
    let mut s = server();
    let (c, p, q, t0) = (client(1), peer(7, 9000), peer(8, 9001), Instant::now());
    allocate(&mut s, c, t0);
    s.handle_from_client(c, &permission_req(2, &[p]), secs(t0, 500)); // live until 800s
    s.handle_from_client(c, &channel_bind_req(3, 0x4001, q), secs(t0, 550)); // bound until 1150s

    let at = secs(t0, 601);
    assert!(s.has_permission(&c, p.ip(), at), "setup: the permission is still live");
    assert!(s.channel_peer(&c, 0x4001, at).is_some(), "setup: the channel is still bound");

    assert_eq!(s.sweep(at).len(), 1, "the 600s allocation has expired");
    assert!(s.allocation_for(&c).is_none());
    assert!(!s.has_permission(&c, p.ip(), at), "a dead allocation must not leave a live permission behind");
    assert!(s.channel_peer(&c, 0x4001, at).is_none(), "nor a live channel binding");
}

// ─── CreatePermission ──────────────────────────────────────────────

#[test]
fn create_permission_installs_the_permission_and_the_reply_is_signed() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    let m = the_reply(&s.handle_from_client(c, &permission_req(2, &[p]), now));
    assert!(is_success(&m) && verify_integrity(&m.raw, &key()));
    assert!(s.has_permission(&c, p.ip(), now));
}

// ─── Client → peer: Send indications ───────────────────────────────

#[test]
fn a_send_indication_without_a_permission_is_dropped() {
    // The property that stops this being an open relay.
    let mut s = server();
    let (c, now) = (client(1), Instant::now());
    allocate(&mut s, c, now);
    assert!(send(&mut s, c, peer(7, 9000), b"hello", now).is_empty());
}

#[test]
fn a_send_indication_with_a_permission_is_relayed_from_the_clients_relay_port() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, now);
    permit(&mut s, c, &[p], now);
    let out = send(&mut s, c, p, b"hello", now);
    assert_eq!(out, vec![TurnOutput::ToPeer { relay_port: port, to: p, data: b"hello".to_vec() }]);
}

#[test]
fn permissions_are_per_ip_so_any_port_of_a_permitted_ip_works_and_other_ips_do_not() {
    let mut s = server();
    let (c, now) = (client(1), Instant::now());
    allocate(&mut s, c, now);
    permit(&mut s, c, &[peer(7, 9000)], now);
    assert_eq!(send(&mut s, c, peer(7, 12345), b"x", now).len(), 1, "same IP, different port: permitted");
    assert!(send(&mut s, c, peer(8, 9000), b"x", now).is_empty(), "different IP: not permitted");
}

#[test]
fn a_send_indication_without_an_allocation_is_dropped() {
    let mut s = server();
    assert!(send(&mut s, client(1), peer(7, 9000), b"x", Instant::now()).is_empty());
}

#[test]
fn a_malformed_send_indication_is_ignored() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    permit(&mut s, c, &[p], now);
    let t = txn(9);
    let no_data = build_message(MessageClass::Indication, Method::Send, &t, &peer_attr(p, &t));
    let no_peer = build_message(MessageClass::Indication, Method::Send, &t, &build_attribute(ATTR_DATA, b"x"));
    assert!(s.handle_from_client(c, &no_data, now).is_empty());
    assert!(s.handle_from_client(c, &no_peer, now).is_empty());
}

#[test]
fn one_clients_permission_does_not_open_another_clients_relay() {
    let mut s = server();
    let (a_, b_, p, now) = (client(1), client(2), peer(7, 9000), Instant::now());
    allocate(&mut s, a_, now);
    allocate(&mut s, b_, now);
    permit(&mut s, a_, &[p], now);
    assert_eq!(send(&mut s, a_, p, b"x", now).len(), 1, "A is permitted");
    assert!(send(&mut s, b_, p, b"x", now).is_empty(), "B, with its own allocation but no permission, is not");
}

#[test]
fn an_expired_permission_stops_client_to_peer_relaying() {
    let mut s = server();
    let (c, p, t0) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, t0);
    permit(&mut s, c, &[p], t0);
    assert_eq!(send(&mut s, c, p, b"x", secs(t0, 299)).len(), 1);
    assert!(send(&mut s, c, p, b"x", secs(t0, 301)).is_empty(), "permissions last 300s");
}

// ─── Peer → client ─────────────────────────────────────────────────

#[test]
fn peer_data_arrives_as_a_data_indication_naming_the_peer() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, now);
    permit(&mut s, c, &[p], now);

    let out = s.handle_from_peer(port, p, b"hello", now);
    assert_eq!(out.len(), 1);
    let TurnOutput::ToClient { to, data } = &out[0] else { panic!("expected ToClient, got {out:?}") };
    assert_eq!(*to, c);
    let m = parse(data);
    assert_eq!((m.class, m.method), (MessageClass::Indication, Method::Data));
    assert!(m.attrs.contains(&Attribute::Data(b"hello".to_vec())));
    assert!(
        m.attrs.iter().any(|x| matches!(x, Attribute::XorPeerAddress(v) if v.ip == p.ip() && v.port == p.port())),
        "without the peer's address the client cannot tell who sent it"
    );
}

#[test]
fn peer_data_from_an_unpermitted_peer_is_dropped() {
    let mut s = server();
    let (c, now) = (client(1), Instant::now());
    let port = allocate(&mut s, c, now);
    permit(&mut s, c, &[peer(7, 9000)], now);
    assert!(s.handle_from_peer(port, peer(8, 9000), b"x", now).is_empty(), "a stranger must not reach the client");
}

#[test]
fn peer_data_on_an_unknown_relay_port_is_dropped() {
    let s = server();
    assert!(s.handle_from_peer(50005, peer(7, 9000), b"x", Instant::now()).is_empty());
}

#[test]
fn peer_data_goes_only_to_the_allocations_owner() {
    let mut s = server();
    let (a_, b_, p, now) = (client(1), client(2), peer(7, 9000), Instant::now());
    let port_a = allocate(&mut s, a_, now);
    let port_b = allocate(&mut s, b_, now);
    permit(&mut s, a_, &[p], now);
    permit(&mut s, b_, &[p], now);

    let to_a = s.handle_from_peer(port_a, p, b"x", now);
    assert!(matches!(&to_a[..], [TurnOutput::ToClient { to, .. }] if *to == a_), "data on A's port goes to A and only A");
    let to_b = s.handle_from_peer(port_b, p, b"x", now);
    assert!(matches!(&to_b[..], [TurnOutput::ToClient { to, .. }] if *to == b_));
}

#[test]
fn a_peer_permitted_for_one_client_cannot_reach_another_through_its_relay() {
    let mut s = server();
    let (a_, b_, p, now) = (client(1), client(2), peer(7, 9000), Instant::now());
    allocate(&mut s, a_, now);
    let port_b = allocate(&mut s, b_, now);
    permit(&mut s, a_, &[p], now); // only A permitted this peer
    assert!(s.handle_from_peer(port_b, p, b"x", now).is_empty());
}

#[test]
fn peer_data_stops_arriving_when_the_permission_expires() {
    let mut s = server();
    let (c, p, t0) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, t0);
    permit(&mut s, c, &[p], t0);
    assert_eq!(s.handle_from_peer(port, p, b"x", secs(t0, 299)).len(), 1);
    assert!(s.handle_from_peer(port, p, b"x", secs(t0, 301)).is_empty());
}

// ─── ChannelBind and ChannelData ───────────────────────────────────

#[test]
fn channel_bind_installs_the_binding_and_a_permission_and_is_signed() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    assert!(!s.has_permission(&c, p.ip(), now), "no explicit CreatePermission was made");

    let m = the_reply(&s.handle_from_client(c, &channel_bind_req(4, 0x4001, p), now));
    assert!(is_success(&m) && verify_integrity(&m.raw, &key()));
    assert_eq!(s.channel_peer(&c, 0x4001, now), Some(p));
    assert!(s.has_permission(&c, p.ip(), now), "binding a channel also permits the peer (RFC 5766 §11.2)");
}

#[test]
fn channel_data_from_the_client_is_relayed_to_the_bound_peer() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, now);
    s.handle_from_client(c, &channel_bind_req(4, 0x4001, p), now);

    let out = s.handle_from_client(c, &build_channel_data(0x4001, b"media"), now);
    assert_eq!(out, vec![TurnOutput::ToPeer { relay_port: port, to: p, data: b"media".to_vec() }]);
}

#[test]
fn peer_data_arrives_as_channel_data_once_a_channel_is_bound() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    let port = allocate(&mut s, c, now);
    s.handle_from_client(c, &channel_bind_req(4, 0x4001, p), now);

    let out = s.handle_from_peer(port, p, b"media", now);
    let TurnOutput::ToClient { data, .. } = &out[0] else { panic!("expected ToClient, got {out:?}") };
    let framed = parse_channel_data(data).expect("ChannelData framing, not a full Data indication");
    assert_eq!(framed.channel_number, 0x4001);
    assert_eq!(framed.payload, b"media");
}

#[test]
fn channel_data_on_an_unbound_channel_is_dropped() {
    let mut s = server();
    let (c, now) = (client(1), Instant::now());
    allocate(&mut s, c, now);
    assert!(s.handle_from_client(c, &build_channel_data(0x4001, b"x"), now).is_empty());
}

#[test]
fn channel_data_without_an_allocation_is_dropped() {
    let mut s = server();
    assert!(s.handle_from_client(client(1), &build_channel_data(0x4001, b"x"), Instant::now()).is_empty());
}

#[test]
fn channel_bind_requires_authentication() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    let t = txn(4);
    let mut attrs = build_attribute(ATTR_CHANNEL_NUMBER, &encode_channel_number(0x4001));
    attrs.extend_from_slice(&peer_attr(p, &t));
    let bare = build_message(MessageClass::Request, Method::ChannelBind, &t, &attrs);

    let m = the_reply(&s.handle_from_client(c, &bare, now));
    assert_eq!(error_code(&m), 401);
    assert!(s.channel_peer(&c, 0x4001, now).is_none(), "an unauthenticated bind must change nothing");
    assert!(!s.has_permission(&c, p.ip(), now));
}

#[test]
fn channel_bind_without_an_allocation_is_437() {
    let mut s = server();
    let m = the_reply(&s.handle_from_client(client(1), &channel_bind_req(4, 0x4001, peer(7, 9000)), Instant::now()));
    assert_eq!(error_code(&m), 437);
}

#[test]
fn channel_bind_with_an_out_of_range_number_is_400_and_changes_nothing() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    for bad in [0x3FFF_u16, 0x8000] {
        let m = the_reply(&s.handle_from_client(c, &channel_bind_req(4, bad, p), now));
        assert_eq!(error_code(&m), 400, "channel {bad:#06x} is outside 0x4000..=0x7FFF");
    }
    assert!(!s.has_permission(&c, p.ip(), now), "a rejected bind must not install a permission either");
}

#[test]
fn conflicting_channel_binds_are_400() {
    let mut s = server();
    let (c, now) = (client(1), Instant::now());
    allocate(&mut s, c, now);
    s.handle_from_client(c, &channel_bind_req(4, 0x4001, peer(7, 9000)), now);

    let same_channel = the_reply(&s.handle_from_client(c, &channel_bind_req(5, 0x4001, peer(8, 9000)), now));
    assert_eq!(error_code(&same_channel), 400, "a channel already bound to another peer");
    let same_peer = the_reply(&s.handle_from_client(c, &channel_bind_req(6, 0x4002, peer(7, 9000)), now));
    assert_eq!(error_code(&same_peer), 400, "a peer already bound to another channel");
    assert_eq!(s.channel_peer(&c, 0x4001, now), Some(peer(7, 9000)), "the original binding is undisturbed");
    assert!(!s.has_permission(&c, peer(8, 9000).ip(), now), "and the rejected one installed no permission");
}

#[test]
fn channel_bind_missing_an_attribute_is_400() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    let t = txn(4);
    let no_channel = authed(Method::ChannelBind, &peer_attr(p, &t), &t);
    let no_peer = authed(Method::ChannelBind, &build_attribute(ATTR_CHANNEL_NUMBER, &encode_channel_number(0x4001)), &t);
    assert_eq!(error_code(&the_reply(&s.handle_from_client(c, &no_channel, now))), 400);
    assert_eq!(error_code(&the_reply(&s.handle_from_client(c, &no_peer, now))), 400);
}

#[test]
fn rebinding_the_same_channel_to_the_same_peer_succeeds() {
    let mut s = server();
    let (c, p, now) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, now);
    for n in [4, 5] {
        assert!(is_success(&the_reply(&s.handle_from_client(c, &channel_bind_req(n, 0x4001, p), now))));
    }
}

#[test]
fn an_expired_channel_binding_stops_relaying_even_while_the_permission_lives() {
    // Isolate the binding's own expiry: refresh the permission so it outlives
    // the channel (permissions last 300s, bindings 600s).
    let mut s = server();
    let (c, p, t0) = (client(1), peer(7, 9000), Instant::now());
    allocate(&mut s, c, t0);
    s.handle_from_client(c, &channel_bind_req(4, 0x4001, p), t0);
    s.handle_from_client(c, &permission_req(5, &[p]), secs(t0, 500)); // permission now lasts to 800s

    assert!(s.has_permission(&c, p.ip(), secs(t0, 601)), "setup: the permission is still alive");
    assert!(s.channel_peer(&c, 0x4001, secs(t0, 601)).is_none(), "but the 600s binding has expired");
    assert!(s.handle_from_client(c, &build_channel_data(0x4001, b"x"), secs(t0, 601)).is_empty());
}

// ─── Robustness ────────────────────────────────────────────────────

#[test]
fn non_turn_traffic_is_ignored() {
    let mut s = server();
    let c = client(1);
    assert!(s.handle_from_client(c, &[], Instant::now()).is_empty());
    assert!(s.handle_from_client(c, &[0xFF; 16], Instant::now()).is_empty());
    assert!(s.handle_from_client(c, &[0x80, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], Instant::now()).is_empty(), "RTP is not ours");
}

#[test]
fn messages_that_are_not_requests_to_the_server_are_ignored() {
    let mut s = server();
    let c = client(1);
    let response = build_message(MessageClass::SuccessResponse, Method::Allocate, &txn(1), &[]);
    assert!(s.handle_from_client(c, &response, Instant::now()).is_empty());
    let data_indication = build_data_indication(&txn(1), peer(7, 9000), b"x");
    assert!(s.handle_from_client(c, &data_indication, Instant::now()).is_empty(), "Data indications flow server → client only");
}

// ─── The new attributes and builders ───────────────────────────────

fn decode_one(attr_type: u16, value: &[u8]) -> Vec<Attribute> {
    let m = build_message(MessageClass::Request, Method::Binding, &txn(1), &build_attribute(attr_type, value));
    let p = parse_message(&m).unwrap();
    decode_attributes(&p.attributes_raw, &p.transaction_id)
}

#[test]
fn data_attribute_decodes_any_length_including_empty() {
    assert_eq!(decode_one(ATTR_DATA, b""), vec![Attribute::Data(vec![])]);
    assert_eq!(decode_one(ATTR_DATA, &[7; 1000]), vec![Attribute::Data(vec![7; 1000])]);
}

#[test]
fn channel_number_decodes_and_ignores_the_reserved_bits() {
    assert_eq!(decode_one(ATTR_CHANNEL_NUMBER, &[0x40, 0x05, 0xAB, 0xCD]), vec![Attribute::ChannelNumber(0x4005)]);
    assert!(decode_one(ATTR_CHANNEL_NUMBER, &[0x40, 0x05]).is_empty(), "a wrong-sized value is dropped");
}

#[test]
fn requested_transport_decodes_the_protocol_byte() {
    assert_eq!(decode_one(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]), vec![Attribute::RequestedTransport(17)]);
    assert!(decode_one(ATTR_REQUESTED_TRANSPORT, &[17]).is_empty());
}

#[test]
fn send_and_data_indications_round_trip_the_peer_and_payload() {
    for (build, method) in [
        (build_send_indication as fn(&[u8; 12], SocketAddr, &[u8]) -> Vec<u8>, Method::Send),
        (build_data_indication, Method::Data),
    ] {
        let p = a("[2001:db8::7]:4242"); // IPv6 exercises the transaction-ID-dependent XOR
        let m = parse(&build(&txn(0x33), p, b"payload"));
        assert_eq!((m.class, method), (MessageClass::Indication, m.method));
        assert!(m.attrs.contains(&Attribute::Data(b"payload".to_vec())));
        assert!(m.attrs.iter().any(|x| matches!(x, Attribute::XorPeerAddress(v) if v.ip == p.ip() && v.port == p.port())));
    }
}

#[test]
fn allocate_success_with_mapped_carries_all_three_attributes() {
    let relayed = SocketAddrAttr { ip: a(RELAY_IP.to_owned().as_str().replace(RELAY_IP, "203.0.113.10:1").as_str()).ip(), port: 50001 };
    let mapped = SocketAddrAttr { ip: client(1).ip(), port: 5000 };
    let m = parse(&build_allocate_success_response_with_mapped(&txn(1), relayed, mapped, 600));
    assert_eq!(relayed_addr(&m), SocketAddr::new(relayed.ip, 50001));
    assert_eq!(mapped_addr(&m), client(1));
    assert_eq!(lifetime_of(&m), 600);
}

#[test]
fn the_extended_request_builder_with_no_extras_is_the_original_byte_for_byte() {
    let nonce = generate_nonce();
    let original = build_authenticated_request(Method::Allocate, &txn(1), USER, REALM, &nonce, PASS);
    let extended = build_authenticated_request_with(Method::Allocate, &txn(1), &[], USER, REALM, &nonce, PASS);
    assert_eq!(original, extended);
}

#[test]
fn extra_attributes_are_covered_by_message_integrity() {
    let req = allocate_req(1);
    assert!(verify_integrity(&req, &key()));
    let mut tampered = req.clone();
    tampered[24] ^= 0x01; // inside REQUESTED-TRANSPORT, the first attribute
    assert!(!verify_integrity(&tampered, &key()), "an attacker must not be able to change the requested transport");
}

// ─── Abandoning an allocation ──────────────────────────────────────
//
// For a driver whose relay socket could not be opened: the allocation is given
// up as if the client had deallocated it.

#[test]
fn abandoning_an_allocation_removes_it_and_reports_the_relay_closed() {
    let (mut s, t0, c) = (server(), Instant::now(), client(1));
    let port = allocate(&mut s, c, t0);
    assert_eq!(s.abandon(&c, t0), vec![TurnOutput::RelayClosed { relay_port: port }]);
    assert!(s.allocation_for(&c).is_none());
}

#[test]
fn abandoning_clears_permissions_and_channels_too() {
    let (mut s, t0, c) = (server(), Instant::now(), client(1));
    allocate(&mut s, c, t0);
    permit(&mut s, c, &[peer(7, 9000)], t0);
    s.handle_from_client(c, &channel_bind_req(3, 0x4001, peer(8, 9001)), t0);
    assert!(s.has_permission(&c, peer(7, 9000).ip(), t0));

    s.abandon(&c, t0);
    assert!(!s.has_permission(&c, peer(7, 9000).ip(), t0), "a later allocation from this address must not inherit it");
    assert!(s.channel_peer(&c, 0x4001, t0).is_none());
}

#[test]
fn an_abandoned_port_becomes_available_again() {
    // A pool of exactly one port: a second client can have it only if the
    // abandoned allocation really released it.
    let mut creds = CredentialStore::new();
    creds.add_user(USER, PASS);
    let mut s = TurnServer::new(REALM, RELAY_IP.parse().unwrap(), creds, PortPool::new(50000, 50000));
    let t0 = Instant::now();

    allocate(&mut s, client(1), t0);
    let refused = s.handle_from_client(client(2), &allocate_req(1), t0);
    assert!(!is_success(&the_reply(&refused)), "setup: the pool is exhausted");

    s.abandon(&client(1), t0);
    let granted = s.handle_from_client(client(2), &allocate_req(1), t0);
    assert!(is_success(&the_reply(&granted)), "the abandoned port must be reusable");
}

#[test]
fn abandoning_an_unknown_client_does_nothing() {
    let (mut s, t0) = (server(), Instant::now());
    allocate(&mut s, client(1), t0);
    assert!(s.abandon(&client(9), t0).is_empty());
    assert!(s.allocation_for(&client(1)).is_some(), "and it must not touch anyone else's allocation");
}
