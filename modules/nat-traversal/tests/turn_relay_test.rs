//! TURN relay data path tests (RFC 5766 §10-11).
//!
//! The forwarding-decision tests matter more than the framing tests:
//! `decide_peer_to_client` is the only thing standing between an
//! allocated relay port and an open forwarder, since Send/Data
//! indications carry no per-packet authentication by design.

use nat_traversal::turn::{
    build_channel_data, classify_datagram, decide_client_to_peer, decide_peer_to_client,
    parse_channel_data, AllocationTable, ChannelBindError, ChannelDataError, ChannelTable,
    DatagramKind, DropReason, PermissionTable, PortPool, RelayDecision,
    CHANNELDATA_HEADER_LEN, CHANNEL_LIFETIME_SECS, CHANNEL_NUMBER_MAX, CHANNEL_NUMBER_MIN,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn client(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn peer(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), port)
}

// ─── Demultiplexing ───────────────────────────────────────────────

#[test]
fn classify_recognises_stun_by_top_bits() {
    // 0x00 = 00xxxxxx → STUN (a Binding Request's first byte).
    assert_eq!(classify_datagram(&[0x00, 0x01]), DatagramKind::Stun);
    assert_eq!(classify_datagram(&[0x01, 0x01]), DatagramKind::Stun);
}

#[test]
fn classify_recognises_channeldata_by_top_bits() {
    // 0x40 = 01xxxxxx → ChannelData (channel 0x4000).
    assert_eq!(classify_datagram(&[0x40, 0x00]), DatagramKind::ChannelData);
    assert_eq!(classify_datagram(&[0x7F, 0xFF]), DatagramKind::ChannelData);
}

#[test]
fn classify_recognises_rtp_as_other() {
    // 0x80 = 10xxxxxx → RTP version 2, not TURN traffic. This is the
    // case that makes sharing a port with media unambiguous.
    assert_eq!(classify_datagram(&[0x80, 0x00]), DatagramKind::Other);
}

#[test]
fn classify_empty_datagram_is_other_not_panic() {
    assert_eq!(classify_datagram(&[]), DatagramKind::Other);
}

// ─── ChannelData framing ──────────────────────────────────────────

#[test]
fn channel_data_round_trips() {
    let payload = b"media payload bytes";
    let framed = build_channel_data(0x4001, payload);

    assert_eq!(framed.len(), CHANNELDATA_HEADER_LEN + payload.len());

    let parsed = parse_channel_data(&framed).expect("own framing must parse");
    assert_eq!(parsed.channel_number, 0x4001);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn channel_data_header_is_exactly_four_bytes_of_overhead() {
    // The entire point of ChannelData over Send indications: 4 bytes,
    // not 36+. Worth asserting so a regression in framing size is caught.
    let framed = build_channel_data(0x4000, &[0u8; 160]);
    assert_eq!(framed.len(), 164);
}

#[test]
fn channel_data_rejects_too_short_input() {
    assert_eq!(parse_channel_data(&[0x40]), Err(ChannelDataError::TooShort));
    assert_eq!(parse_channel_data(&[]), Err(ChannelDataError::TooShort));
}

#[test]
fn channel_data_rejects_channel_number_below_range() {
    // 0x3FFF is one below the valid minimum.
    let raw = [0x3F, 0xFF, 0x00, 0x00];
    assert_eq!(
        parse_channel_data(&raw),
        Err(ChannelDataError::InvalidChannelNumber(0x3FFF))
    );
}

#[test]
fn channel_data_rejects_channel_number_above_range() {
    // 0x8000 is one above the valid maximum (and would classify as RTP anyway).
    let raw = [0x80, 0x00, 0x00, 0x00];
    assert_eq!(
        parse_channel_data(&raw),
        Err(ChannelDataError::InvalidChannelNumber(0x8000))
    );
}

#[test]
fn channel_data_rejects_declared_length_exceeding_datagram() {
    // Header claims 100 bytes of payload; only 4 are present.
    let raw = [0x40, 0x00, 0x00, 0x64, 0xAA, 0xBB, 0xCC, 0xDD];
    assert_eq!(
        parse_channel_data(&raw),
        Err(ChannelDataError::DeclaredLengthExceedsDatagram { declared: 100, available: 4 })
    );
}

#[test]
fn channel_data_tolerates_trailing_padding() {
    // RFC 5766 §11.4 requires 4-byte padding over TCP. Reading exactly
    // the declared length must ignore any trailing padding rather than
    // treating it as payload.
    let mut raw = build_channel_data(0x4000, b"abc"); // 3-byte payload
    raw.push(0x00); // one padding byte to reach a 4-byte boundary

    let parsed = parse_channel_data(&raw).expect("padding must not break parsing");
    assert_eq!(parsed.payload, b"abc", "padding must not be included in the payload");
}

#[test]
fn channel_data_accepts_boundary_channel_numbers() {
    for ch in [CHANNEL_NUMBER_MIN, CHANNEL_NUMBER_MAX] {
        let framed = build_channel_data(ch, b"x");
        let parsed = parse_channel_data(&framed)
            .unwrap_or_else(|e| panic!("channel {ch:#06x} should be valid, got {e:?}"));
        assert_eq!(parsed.channel_number, ch);
    }
}

#[test]
fn channel_data_empty_payload_is_valid() {
    let framed = build_channel_data(0x4000, &[]);
    let parsed = parse_channel_data(&framed).expect("zero-length payload is legal");
    assert!(parsed.payload.is_empty());
}

// ─── Channel bindings ─────────────────────────────────────────────

#[test]
fn channel_bind_then_resolve_in_both_directions() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);

    table.bind(c, 0x4000, p, now).expect("bind should succeed");

    assert_eq!(table.peer_for_channel(&c, 0x4000, now), Some(p));
    assert_eq!(table.channel_for_peer(&c, &p, now), Some(0x4000));
}

#[test]
fn channel_bind_rejects_invalid_channel_number() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    assert_eq!(
        table.bind(client(5000), 0x3FFF, peer(7, 9000), now),
        Err(ChannelBindError::InvalidChannelNumber(0x3FFF))
    );
}

#[test]
fn rebinding_same_channel_to_same_peer_is_a_refresh_not_an_error() {
    let mut table = ChannelTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);

    table.bind(c, 0x4000, p, t0).unwrap();
    let t1 = t0 + Duration::from_secs(100);
    table.bind(c, 0x4000, p, t1).expect("rebinding the same pair must be allowed as a refresh");

    // At the original expiry, the refreshed binding must still resolve.
    let original_expiry = t0 + Duration::from_secs(CHANNEL_LIFETIME_SECS);
    assert_eq!(
        table.peer_for_channel(&c, 0x4000, original_expiry), Some(p),
        "refresh must extend expiry from the refresh time"
    );
    assert_eq!(table.binding_count_for(&c), 1, "refresh must not duplicate the binding");
}

#[test]
fn channel_cannot_be_rebound_to_a_different_peer() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    let c = client(5000);

    table.bind(c, 0x4000, peer(7, 9000), now).unwrap();
    assert_eq!(
        table.bind(c, 0x4000, peer(8, 9000), now),
        Err(ChannelBindError::ChannelAlreadyBoundToDifferentPeer),
        "RFC 5766 §11.2: a channel number maps to at most one peer"
    );
}

#[test]
fn peer_cannot_be_bound_to_a_second_channel() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);

    table.bind(c, 0x4000, p, now).unwrap();
    assert_eq!(
        table.bind(c, 0x4001, p, now),
        Err(ChannelBindError::PeerAlreadyBoundToDifferentChannel),
        "RFC 5766 §11.2: a peer maps to at most one channel number"
    );
}

#[test]
fn bindings_are_scoped_per_client() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    let client_a = client(5000);
    let client_b = client(6000);
    let p = peer(7, 9000);

    // The same channel number bound to the same peer by two different
    // clients must not collide — the uniqueness rules are per-allocation.
    table.bind(client_a, 0x4000, p, now).unwrap();
    table.bind(client_b, 0x4000, p, now)
        .expect("channel numbers are scoped per client, not globally");

    assert_eq!(table.peer_for_channel(&client_a, 0x4000, now), Some(p));
    assert_eq!(table.peer_for_channel(&client_b, 0x4000, now), Some(p));
}

#[test]
fn expired_binding_resolves_in_neither_direction() {
    let mut table = ChannelTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);

    table.bind(c, 0x4000, p, t0).unwrap();
    let after_expiry = t0 + Duration::from_secs(CHANNEL_LIFETIME_SECS + 1);

    assert_eq!(table.peer_for_channel(&c, 0x4000, after_expiry), None);
    assert_eq!(
        table.channel_for_peer(&c, &p, after_expiry), None,
        "an expired binding must not remain resolvable via the reverse index"
    );
}

#[test]
fn sweep_removes_expired_bindings_from_both_indexes() {
    let mut table = ChannelTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);

    table.bind(c, 0x4000, p, t0).unwrap();
    let removed = table.sweep_expired(t0 + Duration::from_secs(CHANNEL_LIFETIME_SECS + 1));

    assert_eq!(removed, 1);
    assert_eq!(table.binding_count_for(&c), 0);
    // Re-binding must now succeed, proving the reverse index was also
    // cleaned — a stale by_peer entry would trigger a false
    // PeerAlreadyBoundToDifferentChannel here.
    table.bind(c, 0x4001, p, Instant::now())
        .expect("sweep must clear the reverse index too, allowing a fresh bind");
}

#[test]
fn sweep_leaves_unexpired_bindings_alone() {
    let mut table = ChannelTable::new();
    let t0 = Instant::now();
    let c = client(5000);

    table.bind(c, 0x4000, peer(7, 9000), t0).unwrap();
    let removed = table.sweep_expired(t0 + Duration::from_secs(10));

    assert_eq!(removed, 0);
    assert_eq!(table.binding_count_for(&c), 1);
}

#[test]
fn clear_for_client_removes_all_bindings() {
    let mut table = ChannelTable::new();
    let now = Instant::now();
    let c = client(5000);

    table.bind(c, 0x4000, peer(1, 9000), now).unwrap();
    table.bind(c, 0x4001, peer(2, 9000), now).unwrap();
    assert_eq!(table.binding_count_for(&c), 2);

    table.clear_for_client(&c);
    assert_eq!(table.binding_count_for(&c), 0);
    assert_eq!(table.peer_for_channel(&c, 0x4000, now), None);
}

// ─── Forwarding: client → peer ────────────────────────────────────

/// Build an allocation table with one allocation, returning the table
/// and the relay port assigned.
fn allocated(c: SocketAddr, now: Instant) -> (AllocationTable, u16) {
    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    let a = allocations.create_or_refresh(c, None, now).expect("allocation should succeed");
    let port = a.relay_port;
    (allocations, port)
}

#[test]
fn client_to_peer_forwards_when_permitted() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, _) = allocated(c, now);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), now);

    let decision = decide_client_to_peer(c, p, b"media".to_vec(), &allocations, &permissions, now);
    assert_eq!(decision, RelayDecision::Forward { to: p, payload: b"media".to_vec() });
}

#[test]
fn client_to_peer_drops_without_permission() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, _) = allocated(c, now);
    let permissions = PermissionTable::new(); // deliberately empty

    let decision = decide_client_to_peer(c, p, b"media".to_vec(), &allocations, &permissions, now);
    assert_eq!(decision, RelayDecision::Drop(DropReason::NoPermission));
}

#[test]
fn client_to_peer_drops_without_allocation() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let allocations = AllocationTable::new(PortPool::new(50000, 50010)); // empty

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), now);

    let decision = decide_client_to_peer(c, p, b"media".to_vec(), &allocations, &permissions, now);
    assert_eq!(
        decision, RelayDecision::Drop(DropReason::NoAllocation),
        "a permission without a backing allocation must not enable forwarding"
    );
}

#[test]
fn client_to_peer_drops_once_permission_expires() {
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, _) = allocated(c, t0);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), t0);

    // 300s permission lifetime; check well past it.
    let later = t0 + Duration::from_secs(400);
    let decision = decide_client_to_peer(c, p, b"media".to_vec(), &allocations, &permissions, later);
    assert_eq!(decision, RelayDecision::Drop(DropReason::NoPermission));
}

#[test]
fn permission_is_ip_scoped_so_peer_port_change_still_forwards() {
    // RFC 5766 §8 keys permissions on IP only. A peer legitimately
    // changing source port mid-session must not break the relay.
    let now = Instant::now();
    let c = client(5000);
    let (allocations, _) = allocated(c, now);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, peer(7, 9000).ip(), now);

    let different_port = peer(7, 41234);
    let decision = decide_client_to_peer(c, different_port, b"m".to_vec(), &allocations, &permissions, now);
    assert_eq!(
        decision, RelayDecision::Forward { to: different_port, payload: b"m".to_vec() },
        "a permission must cover the peer IP on any source port"
    );
}

// ─── Forwarding: peer → client (security-critical direction) ──────

#[test]
fn peer_to_client_forwards_when_permitted() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, relay_port) = allocated(c, now);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), now);
    let channels = ChannelTable::new(); // no channel bound

    let decision = decide_peer_to_client(
        relay_port, p, b"inbound".to_vec(), &allocations, &permissions, &channels, now,
    );
    let (to, payload) = forwarded(decision);
    assert_eq!(to, c);
    assert_data_indication(&payload, p, b"inbound");
}

#[test]
fn peer_to_client_drops_without_permission() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, relay_port) = allocated(c, now);

    let permissions = PermissionTable::new(); // no permission installed
    let channels = ChannelTable::new();

    let decision = decide_peer_to_client(
        relay_port, p, b"injected".to_vec(), &allocations, &permissions, &channels, now,
    );
    assert_eq!(
        decision, RelayDecision::Drop(DropReason::NoPermission),
        "this is the check preventing an allocated relay port from being an open forwarder"
    );
}

#[test]
fn peer_to_client_drops_on_unknown_relay_port() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, _) = allocated(c, now);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), now);
    let channels = ChannelTable::new();

    // A port that belongs to no allocation at all.
    let decision = decide_peer_to_client(
        59999, p, b"x".to_vec(), &allocations, &permissions, &channels, now,
    );
    assert_eq!(decision, RelayDecision::Drop(DropReason::UnknownRelayPort));
}

#[test]
fn peer_to_client_uses_channeldata_framing_when_channel_is_bound() {
    let now = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, relay_port) = allocated(c, now);

    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(c, p.ip(), now);

    let mut channels = ChannelTable::new();
    channels.bind(c, 0x4005, p, now).unwrap();

    let decision = decide_peer_to_client(
        relay_port, p, b"abc".to_vec(), &allocations, &permissions, &channels, now,
    );

    let RelayDecision::Forward { to, payload } = decision else {
        panic!("expected a Forward decision, got {decision:?}");
    };
    assert_eq!(to, c);

    // The payload must be ChannelData-framed, and decode back cleanly.
    let parsed = parse_channel_data(&payload).expect("framed payload must be valid ChannelData");
    assert_eq!(parsed.channel_number, 0x4005);
    assert_eq!(parsed.payload, b"abc");
}

#[test]
fn peer_to_client_falls_back_to_a_data_indication_when_channel_expired() {
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer(7, 9000);
    let (allocations, relay_port) = allocated(c, t0);

    let mut permissions = PermissionTable::new();
    let mut channels = ChannelTable::new();
    channels.bind(c, 0x4005, p, t0).unwrap();

    // Past the channel's 600s lifetime, but keep the permission fresh so
    // the only thing that changed is the channel binding's validity.
    let later = t0 + Duration::from_secs(CHANNEL_LIFETIME_SECS + 10);
    permissions.create_or_refresh(c, p.ip(), later);

    let decision = decide_peer_to_client(
        relay_port, p, b"abc".to_vec(), &allocations, &permissions, &channels, later,
    );
    let (to, payload) = forwarded(decision);
    assert_eq!(to, c, "an expired channel must fall back to a Data indication, not drop the packet");
    assert_data_indication(&payload, p, b"abc");
}

#[test]
fn relay_isolates_two_clients_from_each_other() {
    // Two allocations, each permitting a different peer. Data from
    // client A's permitted peer must never reach client B.
    let now = Instant::now();
    let client_a = client(5000);
    let client_b = client(6000);

    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    let port_a = allocations.create_or_refresh(client_a, None, now).unwrap().relay_port;
    let port_b = allocations.create_or_refresh(client_b, None, now).unwrap().relay_port;
    assert_ne!(port_a, port_b, "each allocation must get its own relay port");

    let peer_a = peer(1, 9000);
    let mut permissions = PermissionTable::new();
    permissions.create_or_refresh(client_a, peer_a.ip(), now);
    // client_b deliberately has no permissions.

    let channels = ChannelTable::new();

    // Arriving on A's port from A's permitted peer → forwarded to A.
    let to_a = decide_peer_to_client(
        port_a, peer_a, b"x".to_vec(), &allocations, &permissions, &channels, now,
    );
    let (to, payload) = forwarded(to_a);
    assert_eq!(to, client_a, "data for A's allocation must go to A");
    assert_data_indication(&payload, peer_a, b"x");

    // The same peer arriving on B's port → dropped, since B never
    // permitted it. Relay ports must not be interchangeable.
    let to_b = decide_peer_to_client(
        port_b, peer_a, b"x".to_vec(), &allocations, &permissions, &channels, now,
    );
    assert_eq!(to_b, RelayDecision::Drop(DropReason::NoPermission));
}

fn forwarded(decision: RelayDecision) -> (std::net::SocketAddr, Vec<u8>) {
    match decision {
        RelayDecision::Forward { to, payload } => (to, payload),
        other => panic!("expected Forward, got {other:?}"),
    }
}

/// With no channel bound, peer data must reach the client as a Data indication
/// that names the peer — a bare payload would leave the client unable to tell
/// who sent it.
fn assert_data_indication(wire: &[u8], peer: std::net::SocketAddr, payload: &[u8]) {
    use nat_traversal::stun::attributes::{decode_attributes, Attribute};
    use nat_traversal::stun::parser::{parse_message, MessageClass, Method};
    let msg = parse_message(wire).expect("a Data indication, not a bare payload");
    assert_eq!((msg.class, msg.method), (MessageClass::Indication, Method::Data));
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert!(attrs.contains(&Attribute::Data(payload.to_vec())), "DATA must carry the payload");
    assert!(
        attrs.iter().any(|a| matches!(a, Attribute::XorPeerAddress(x) if x.ip == peer.ip() && x.port == peer.port())),
        "XOR-PEER-ADDRESS must name the peer"
    );
}
