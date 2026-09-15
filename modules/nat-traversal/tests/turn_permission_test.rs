//! TURN permission tests (RFC 5766 §8-9).
//!
//! Like the allocation tests, expiry is tested with caller-controlled
//! `Instant` values rather than real sleeps — `PermissionTable`'s
//! methods all take `now: Instant` explicitly for exactly this reason.

use nat_traversal::stun::{
    attributes::{decode_attributes, Attribute, ATTR_XOR_PEER_ADDRESS},
    builder::{build_attribute, build_header_with_length, build_message},
    parser::{parse_message, MessageClass, Method},
};
use nat_traversal::turn::{
    handle_create_permission_datagram, AllocationTable, CredentialStore,
    PermissionTable, PortPool, PERMISSION_LIFETIME_SECS,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

fn client(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn peer_ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

// ─── PermissionTable: basic create / check ────────────────────────

#[test]
fn permission_granted_then_recognised() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let c = client(5000);
    let p = peer_ip(7);

    assert!(!table.has_permission(&c, &p, now), "no permission should exist initially");
    table.create_or_refresh(c, p, now);
    assert!(table.has_permission(&c, &p, now), "permission must be recognised after creation");
}

#[test]
fn permission_is_scoped_to_the_granting_client() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let client_a = client(5000);
    let client_b = client(6000);
    let p = peer_ip(7);

    table.create_or_refresh(client_a, p, now);

    assert!(table.has_permission(&client_a, &p, now));
    assert!(
        !table.has_permission(&client_b, &p, now),
        "one client's permission must never grant access to another client's allocation"
    );
}

#[test]
fn permission_does_not_leak_to_other_peers() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let c = client(5000);

    table.create_or_refresh(c, peer_ip(7), now);

    assert!(table.has_permission(&c, &peer_ip(7), now));
    assert!(
        !table.has_permission(&c, &peer_ip(8), now),
        "permitting one peer must not implicitly permit a different peer"
    );
}

#[test]
fn multiple_peers_can_be_permitted_for_one_client() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let c = client(5000);

    for last in 1..=5 {
        table.create_or_refresh(c, peer_ip(last), now);
    }

    for last in 1..=5 {
        assert!(table.has_permission(&c, &peer_ip(last), now), "peer {last} should be permitted");
    }
    assert_eq!(table.permission_count_for(&c), 5);
}

#[test]
fn ipv6_peer_addresses_are_supported() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let c = client(5000);
    let v6: IpAddr = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());

    table.create_or_refresh(c, v6, now);
    assert!(table.has_permission(&c, &v6, now));
}

// ─── Lifetime and expiry ──────────────────────────────────────────

#[test]
fn permission_valid_just_before_lifetime_elapses() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer_ip(7);

    table.create_or_refresh(c, p, t0);

    let just_before = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS - 1);
    assert!(table.has_permission(&c, &p, just_before));
}

#[test]
fn permission_expires_at_and_after_lifetime_boundary() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer_ip(7);

    table.create_or_refresh(c, p, t0);

    let at_boundary = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS);
    let past_boundary = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS + 60);

    assert!(!table.has_permission(&c, &p, at_boundary), "exactly at expiry must count as expired");
    assert!(!table.has_permission(&c, &p, past_boundary));
}

#[test]
fn refreshing_extends_permission_past_original_expiry() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer_ip(7);

    table.create_or_refresh(c, p, t0);

    // Refresh partway through the original lifetime.
    let t1 = t0 + Duration::from_secs(100);
    table.create_or_refresh(c, p, t1);

    // At the ORIGINAL expiry point, the refreshed permission must still
    // be valid — this is the check that proves refresh actually moved
    // the expiry rather than merely resetting some unrelated field.
    let original_expiry = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS);
    assert!(
        table.has_permission(&c, &p, original_expiry),
        "refresh must extend expiry relative to the refresh time, not the original creation time"
    );
}

#[test]
fn refreshing_does_not_create_a_duplicate_entry() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    let p = peer_ip(7);

    table.create_or_refresh(c, p, t0);
    table.create_or_refresh(c, p, t0 + Duration::from_secs(10));

    assert_eq!(table.permission_count_for(&c), 1, "refreshing must update in place, not duplicate");
}

// ─── clear_for_client ─────────────────────────────────────────────

#[test]
fn clear_for_client_removes_all_that_clients_permissions() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let c = client(5000);

    table.create_or_refresh(c, peer_ip(1), now);
    table.create_or_refresh(c, peer_ip(2), now);
    assert_eq!(table.permission_count_for(&c), 2);

    table.clear_for_client(&c);

    assert_eq!(table.permission_count_for(&c), 0);
    assert!(!table.has_permission(&c, &peer_ip(1), now));
    assert!(!table.has_permission(&c, &peer_ip(2), now));
}

#[test]
fn clear_for_client_leaves_other_clients_untouched() {
    let mut table = PermissionTable::new();
    let now = Instant::now();
    let client_a = client(5000);
    let client_b = client(6000);

    table.create_or_refresh(client_a, peer_ip(1), now);
    table.create_or_refresh(client_b, peer_ip(1), now);

    table.clear_for_client(&client_a);

    assert!(!table.has_permission(&client_a, &peer_ip(1), now));
    assert!(
        table.has_permission(&client_b, &peer_ip(1), now),
        "clearing one client must not affect another client's permissions"
    );
}

#[test]
fn clear_for_unknown_client_is_a_safe_noop() {
    let mut table = PermissionTable::new();
    table.clear_for_client(&client(9999));
    assert_eq!(table.client_count(), 0);
}

// ─── sweep_expired ────────────────────────────────────────────────

#[test]
fn sweep_removes_only_expired_peer_entries() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);

    // Create one permission early, another much later, so only the first
    // is expired at the sweep point.
    table.create_or_refresh(c, peer_ip(1), t0);
    let t_later = t0 + Duration::from_secs(200);
    table.create_or_refresh(c, peer_ip(2), t_later);

    // Sweep at a time past peer 1's expiry but within peer 2's.
    let sweep_at = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS + 10);
    let removed = table.sweep_expired(sweep_at);

    assert_eq!(removed, 1, "exactly one expired entry should be removed");
    assert!(!table.has_permission(&c, &peer_ip(1), sweep_at));
    assert!(table.has_permission(&c, &peer_ip(2), sweep_at), "the unexpired peer must survive");
    assert_eq!(table.permission_count_for(&c), 1);
}

#[test]
fn sweep_drops_client_entries_left_completely_empty() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);

    table.create_or_refresh(c, peer_ip(1), t0);
    assert_eq!(table.client_count(), 1);

    let sweep_at = t0 + Duration::from_secs(PERMISSION_LIFETIME_SECS + 10);
    table.sweep_expired(sweep_at);

    assert_eq!(
        table.client_count(), 0,
        "a client with zero remaining permissions must not be retained as an empty entry"
    );
}

#[test]
fn sweep_with_nothing_expired_changes_nothing() {
    let mut table = PermissionTable::new();
    let t0 = Instant::now();
    let c = client(5000);
    table.create_or_refresh(c, peer_ip(1), t0);

    let removed = table.sweep_expired(t0 + Duration::from_secs(10));

    assert_eq!(removed, 0);
    assert_eq!(table.permission_count_for(&c), 1);
}

#[test]
fn sweep_on_empty_table_is_a_safe_noop() {
    let mut table = PermissionTable::new();
    assert_eq!(table.sweep_expired(Instant::now()), 0);
}

// ─── XOR-PEER-ADDRESS wire format ─────────────────────────────────

#[test]
fn xor_peer_address_decodes_from_the_wire() {
    // Build a message carrying an XOR-PEER-ADDRESS, then decode it back —
    // confirming the new attribute type round-trips through the same
    // proven XOR encoding used by XOR-MAPPED/RELAYED-ADDRESS.
    use nat_traversal::stun::attributes::encode_xor_mapped_address;
    use nat_traversal::stun::SocketAddrAttr;

    let txn_id = [0x33u8; 12];
    let addr = SocketAddrAttr { ip: peer_ip(42), port: 9000 };

    let value = encode_xor_mapped_address(&addr, &txn_id);
    let attr = build_attribute(ATTR_XOR_PEER_ADDRESS, &value);
    let wire = build_message(MessageClass::Request, Method::CreatePermission, &txn_id, &attr);

    let parsed = parse_message(&wire).expect("should parse");
    let attrs = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id);

    let decoded = attrs.iter().find_map(|a| match a {
        Attribute::XorPeerAddress(p) => Some(*p),
        _ => None,
    }).expect("XOR-PEER-ADDRESS must decode");

    assert_eq!(decoded.ip, addr.ip);
    assert_eq!(decoded.port, addr.port);
}

#[test]
fn multiple_xor_peer_addresses_all_decode() {
    use nat_traversal::stun::attributes::encode_xor_mapped_address;
    use nat_traversal::stun::SocketAddrAttr;

    let txn_id = [0x44u8; 12];
    let mut attrs_bytes = Vec::new();
    for last in 1..=3u8 {
        let addr = SocketAddrAttr { ip: peer_ip(last), port: 9000 + last as u16 };
        let value = encode_xor_mapped_address(&addr, &txn_id);
        attrs_bytes.extend_from_slice(&build_attribute(ATTR_XOR_PEER_ADDRESS, &value));
    }
    let wire = build_message(MessageClass::Request, Method::CreatePermission, &txn_id, &attrs_bytes);

    let parsed = parse_message(&wire).unwrap();
    let decoded: Vec<_> = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id)
        .into_iter()
        .filter_map(|a| match a { Attribute::XorPeerAddress(p) => Some(p), _ => None })
        .collect();

    assert_eq!(decoded.len(), 3, "all three peer addresses must decode, not just the first");
    for (i, d) in decoded.iter().enumerate() {
        assert_eq!(d.ip, peer_ip((i + 1) as u8));
    }
}

// ─── handle_create_permission_datagram ────────────────────────────

const TEST_REALM: &str = "routing-core.local";
const TEST_USER: &str = "alice";
const TEST_PASS: &str = "correcthorsebatterystaple";

fn store() -> CredentialStore {
    let mut s = CredentialStore::new();
    s.add_user(TEST_USER, TEST_PASS);
    s
}

/// Build an authenticated CreatePermission request naming the given peers.
fn authed_create_permission(txn_id: &[u8; 12], nonce: &str, peers: &[IpAddr]) -> Vec<u8> {
    use nat_traversal::stun::attributes::{
        encode_xor_mapped_address, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME,
    };
    use nat_traversal::stun::SocketAddrAttr;
    use nat_traversal::turn::long_term_key;

    let mut attrs = Vec::new();
    for ip in peers {
        let addr = SocketAddrAttr { ip: *ip, port: 9000 };
        let v = encode_xor_mapped_address(&addr, txn_id);
        attrs.extend_from_slice(&build_attribute(ATTR_XOR_PEER_ADDRESS, &v));
    }
    attrs.extend_from_slice(&build_attribute(ATTR_USERNAME, TEST_USER.as_bytes()));
    attrs.extend_from_slice(&build_attribute(ATTR_REALM, TEST_REALM.as_bytes()));
    attrs.extend_from_slice(&build_attribute(ATTR_NONCE, nonce.as_bytes()));

    // MESSAGE-INTEGRITY over the adjusted-length prefix (RFC 5389 §15.4).
    const MI_LEN: usize = 24;
    let adjusted = (attrs.len() + MI_LEN) as u16;
    let header = build_header_with_length(
        MessageClass::Request, Method::CreatePermission, txn_id, adjusted,
    );
    let mut hmac_input = header.clone();
    hmac_input.extend_from_slice(&attrs);

    let key = long_term_key(TEST_USER, TEST_REALM, TEST_PASS);
    let mi = nat_traversal::turn::hmac_sha1(&key, &hmac_input);
    let mi_attr = build_attribute(ATTR_MESSAGE_INTEGRITY, &mi);

    let mut full = header;
    full.extend_from_slice(&attrs);
    full.extend_from_slice(&mi_attr);
    full
}

#[test]
fn create_permission_succeeds_and_installs_permission() {
    let c = client(5000);
    let now = Instant::now();

    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    allocations.create_or_refresh(c, None, now).expect("allocation needed first");

    let mut permissions = PermissionTable::new();
    let nonce = nat_traversal::turn::generate_nonce();
    let txn_id = [0x55u8; 12];
    let target = peer_ip(7);

    let req = authed_create_permission(&txn_id, &nonce, &[target]);
    let resp = handle_create_permission_datagram(
        &req, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    ).expect("should respond");

    let parsed = parse_message(&resp).expect("response must parse");
    assert_eq!(parsed.class, MessageClass::SuccessResponse);
    assert_eq!(parsed.method, Method::CreatePermission);
    assert_eq!(parsed.transaction_id, txn_id);

    assert!(
        permissions.has_permission(&c, &target, Instant::now()),
        "the permission must actually be installed, not just acknowledged"
    );
}

#[test]
fn create_permission_installs_all_named_peers() {
    let c = client(5000);
    let now = Instant::now();

    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    allocations.create_or_refresh(c, None, now).unwrap();

    let mut permissions = PermissionTable::new();
    let nonce = nat_traversal::turn::generate_nonce();
    let targets = [peer_ip(1), peer_ip(2), peer_ip(3)];

    let req = authed_create_permission(&[0x66u8; 12], &nonce, &targets);
    handle_create_permission_datagram(
        &req, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    ).expect("should respond");

    let check_at = Instant::now();
    for t in &targets {
        assert!(permissions.has_permission(&c, t, check_at), "peer {t} must be permitted");
    }
    assert_eq!(permissions.permission_count_for(&c), 3);
}

#[test]
fn create_permission_without_allocation_returns_437() {
    let c = client(5000);
    // Deliberately empty — this client has no allocation.
    let allocations = AllocationTable::new(PortPool::new(50000, 50010));
    let mut permissions = PermissionTable::new();
    let nonce = nat_traversal::turn::generate_nonce();

    let req = authed_create_permission(&[0x77u8; 12], &nonce, &[peer_ip(7)]);
    let resp = handle_create_permission_datagram(
        &req, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    ).expect("should respond");

    let parsed = parse_message(&resp).unwrap();
    assert_eq!(parsed.class, MessageClass::ErrorResponse);

    let code = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id)
        .iter()
        .find_map(|a| match a { Attribute::ErrorCode { code, .. } => Some(*code), _ => None })
        .expect("error response must carry an ERROR-CODE");
    assert_eq!(code, 437, "no allocation must produce 437 Allocation Mismatch");

    assert!(
        !permissions.has_permission(&c, &peer_ip(7), Instant::now()),
        "a rejected request must not install any permission"
    );
}

#[test]
fn create_permission_with_no_peer_addresses_returns_400() {
    let c = client(5000);
    let now = Instant::now();

    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    allocations.create_or_refresh(c, None, now).unwrap();

    let mut permissions = PermissionTable::new();
    let nonce = nat_traversal::turn::generate_nonce();

    // Empty peer list — malformed per RFC 5766 §9.1.
    let req = authed_create_permission(&[0x88u8; 12], &nonce, &[]);
    let resp = handle_create_permission_datagram(
        &req, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    ).expect("should respond");

    let parsed = parse_message(&resp).unwrap();
    assert_eq!(parsed.class, MessageClass::ErrorResponse);

    let code = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id)
        .iter()
        .find_map(|a| match a { Attribute::ErrorCode { code, .. } => Some(*code), _ => None })
        .expect("error response must carry an ERROR-CODE");
    assert_eq!(code, 400, "a CreatePermission naming no peers is Bad Request, not a silent success");
}

#[test]
fn create_permission_unauthenticated_returns_challenge_not_permission() {
    let c = client(5000);
    let now = Instant::now();

    let mut allocations = AllocationTable::new(PortPool::new(50000, 50010));
    allocations.create_or_refresh(c, None, now).unwrap();

    let mut permissions = PermissionTable::new();

    // A bare request with no credentials at all.
    let txn_id = [0x99u8; 12];
    let bare = build_message(MessageClass::Request, Method::CreatePermission, &txn_id, &[]);

    let resp = handle_create_permission_datagram(
        &bare, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    ).expect("should respond with a challenge");

    let parsed = parse_message(&resp).unwrap();
    assert_eq!(parsed.class, MessageClass::ErrorResponse);

    let code = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id)
        .iter()
        .find_map(|a| match a { Attribute::ErrorCode { code, .. } => Some(*code), _ => None })
        .expect("challenge must carry an ERROR-CODE");
    assert_eq!(code, 401);

    assert_eq!(
        permissions.client_count(), 0,
        "an unauthenticated request must never install a permission"
    );
}

#[test]
fn create_permission_ignores_non_matching_methods() {
    let c = client(5000);
    let allocations = AllocationTable::new(PortPool::new(50000, 50010));
    let mut permissions = PermissionTable::new();

    // An Allocate request handed to the CreatePermission handler.
    let wrong = build_message(MessageClass::Request, Method::Allocate, &[0xAAu8; 12], &[]);
    let resp = handle_create_permission_datagram(
        &wrong, c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    );
    assert!(resp.is_none(), "a non-CreatePermission request must be silently ignored");
}

#[test]
fn create_permission_ignores_unparseable_garbage() {
    let c = client(5000);
    let allocations = AllocationTable::new(PortPool::new(50000, 50010));
    let mut permissions = PermissionTable::new();

    let resp = handle_create_permission_datagram(
        &[0xFF; 8], c, TEST_REALM, &store(), &allocations, &mut permissions, 3600,
    );
    assert!(resp.is_none(), "garbage must be dropped, not panic");
}
