//! STUN message builder and server-handler tests.

use nat_traversal::stun::{
    attributes::{decode_attributes, Attribute, SocketAddrAttr},
    builder::{build_attribute, build_binding_success_response, build_message},
    handle_datagram,
    parser::{parse_message, MessageClass, Method},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ─── encode_class_and_method, tested exhaustively through the wire ───
//
// encode_class_and_method itself is private to builder.rs; it is only
// reachable through build_message. Testing it here through the full
// build_message -> parse_message round trip is strictly stronger than
// unit-testing the bit-shuffling function in isolation — it proves the
// actual wire bytes a peer would receive decode correctly, not just that
// two internal functions agree with each other.

#[test]
fn encode_decode_round_trip_exhaustive() {
    // The Python verification (independent of this Rust code) checked
    // encode_class_and_method against decode_class_and_method across all
    // 16,384 possible 14-bit message-type values with zero mismatches
    // before this file was written. This test re-derives the same
    // guarantee through the real Rust implementation and the real wire
    // format, across every class and a full sweep of the 12-bit method
    // space (0..4096).
    let classes = [
        MessageClass::Request,
        MessageClass::Indication,
        MessageClass::SuccessResponse,
        MessageClass::ErrorResponse,
    ];

    let txn_id = [0u8; 12];
    let mut checked = 0u32;

    for &class in &classes {
        for method_bits in 0u16..4096 {
            // Several method_bits values now map to named variants
            // (Binding, Allocate, Refresh, Send, Data, CreatePermission,
            // ChannelBind) rather than round-tripping as Extension(m) —
            // the expected result must reflect that, not assume naive
            // input==output identity.
            let input_method = Method::Extension(method_bits);
            let expected_method = match method_bits {
                0x001 => Method::Binding,
                0x003 => Method::Allocate,
                0x004 => Method::Refresh,
                0x006 => Method::Send,
                0x007 => Method::Data,
                0x008 => Method::CreatePermission,
                0x009 => Method::ChannelBind,
                other => Method::Extension(other),
            };

            let wire = build_message(class, input_method, &txn_id, &[]);
            let decoded = parse_message(&wire)
                .unwrap_or_else(|e| panic!("failed to parse own encoding: {e} (class={class:?}, method_bits={method_bits:#x})"));

            assert_eq!(decoded.class, class,
                "class mismatch at method_bits={method_bits:#x}");
            assert_eq!(decoded.method, expected_method,
                "method mismatch at method_bits={method_bits:#x}");

            checked += 1;
        }
    }

    assert_eq!(checked, 4 * 4096, "did not check the full expected space");
}

#[test]
fn build_message_binding_request_matches_known_constant() {
    // 0x0001 is the single most well-known STUN constant — Binding
    // Request. If this doesn't hold, nothing else here can be trusted.
    let txn_id = [0u8; 12];
    let wire = build_message(MessageClass::Request, Method::Binding, &txn_id, &[]);
    assert_eq!(&wire[0..2], &[0x00, 0x01]);
}

#[test]
fn build_message_binding_success_response_matches_known_constant() {
    let txn_id = [0u8; 12];
    let wire = build_message(MessageClass::SuccessResponse, Method::Binding, &txn_id, &[]);
    assert_eq!(&wire[0..2], &[0x01, 0x01]);
}

#[test]
fn build_message_length_field_matches_attributes_length() {
    let txn_id = [0u8; 12];
    let attrs: &[u8] = &[0xAA; 12];
    let wire = build_message(MessageClass::Request, Method::Binding, &txn_id, attrs);
    let declared_len = u16::from_be_bytes([wire[2], wire[3]]);
    assert_eq!(declared_len, 12);
    assert_eq!(wire.len(), 20 + 12);
}

// ─── build_attribute padding ──────────────────────────────────────

#[test]
fn build_attribute_pads_three_byte_value_to_four() {
    let attr = build_attribute(0x0006, b"abc"); // 3-byte value
    // header(4) + value(3) + pad(1) = 8 bytes total
    assert_eq!(attr.len(), 8);
    // Declared length is the UNPADDED value length (3), not 4.
    let declared_len = u16::from_be_bytes([attr[2], attr[3]]);
    assert_eq!(declared_len, 3);
    assert_eq!(&attr[4..7], b"abc");
    assert_eq!(attr[7], 0, "padding byte must be zero");
}

#[test]
fn build_attribute_four_byte_value_needs_no_padding() {
    let attr = build_attribute(0x0020, &[1, 2, 3, 4]);
    assert_eq!(attr.len(), 8); // 4 header + 4 value, no padding needed
}

#[test]
fn build_attribute_round_trips_through_decode_attributes() {
    // Build a USERNAME attribute with an odd length requiring padding,
    // then verify decode_attributes reads back exactly the unpadded value.
    let attr = build_attribute(0x0006, b"xy"); // 2 bytes, needs 2 bytes padding
    let txn_id = [0u8; 12];
    let attrs = decode_attributes(&attr, &txn_id);
    assert_eq!(attrs.len(), 1);
    match &attrs[0] {
        Attribute::Username(s) => assert_eq!(s, "xy"),
        other => panic!("expected Username, got {other:?}"),
    }
}

// ─── build_binding_success_response ────────────────────────────────

#[test]
fn binding_success_response_echoes_transaction_id_exactly() {
    let txn_id = [0x42u8; 12];
    let addr = SocketAddrAttr {
        ip:   IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        port: 4242,
    };
    let wire = build_binding_success_response(&txn_id, addr);
    let parsed = parse_message(&wire).unwrap();
    assert_eq!(parsed.transaction_id, txn_id);
}

#[test]
fn binding_success_response_contains_correct_xor_mapped_address() {
    let txn_id = [0x77u8; 12];
    let addr = SocketAddrAttr {
        ip:   IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        port: 51820,
    };
    let wire = build_binding_success_response(&txn_id, addr);
    let parsed = parse_message(&wire).unwrap();
    assert_eq!(parsed.class, MessageClass::SuccessResponse);
    assert_eq!(parsed.method, Method::Binding);

    let attrs = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id);
    assert_eq!(attrs.len(), 1);
    match &attrs[0] {
        Attribute::XorMappedAddress(decoded_addr) => assert_eq!(*decoded_addr, addr),
        other => panic!("expected XorMappedAddress, got {other:?}"),
    }
}

// ─── server::handle_datagram ────────────────────────────────────────

fn make_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    build_message(MessageClass::Request, Method::Binding, txn_id, &[])
}

#[test]
fn handle_datagram_responds_to_binding_request() {
    let txn_id = [0x11u8; 12];
    let request = make_binding_request(&txn_id);
    let peer: SocketAddr = "192.168.1.50:6000".parse().unwrap();

    let response = handle_datagram(&request, peer).expect("must respond to a valid Binding Request");
    let parsed = parse_message(&response).expect("response must itself be valid STUN");

    assert_eq!(parsed.class, MessageClass::SuccessResponse);
    assert_eq!(parsed.method, Method::Binding);
    assert_eq!(parsed.transaction_id, txn_id, "transaction ID must be echoed exactly");
}

#[test]
fn handle_datagram_response_contains_peer_address() {
    let txn_id = [0x22u8; 12];
    let request = make_binding_request(&txn_id);
    let peer: SocketAddr = "10.20.30.40:9999".parse().unwrap();

    let response = handle_datagram(&request, peer).unwrap();
    let parsed = parse_message(&response).unwrap();
    let attrs = decode_attributes(&parsed.attributes_raw, &parsed.transaction_id);

    let observed = attrs.iter().find_map(|a| match a {
        Attribute::XorMappedAddress(addr) => Some(*addr),
        _ => None,
    }).expect("response must contain XOR-MAPPED-ADDRESS");

    assert_eq!(observed.ip, peer.ip());
    assert_eq!(observed.port, peer.port());
}

#[test]
fn handle_datagram_drops_indication_class_message() {
    // Not a Request — must be silently dropped, not answered.
    let txn_id = [0x33u8; 12];
    let indication = build_message(MessageClass::Indication, Method::Binding, &txn_id, &[]);
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    assert!(handle_datagram(&indication, peer).is_none());
}

#[test]
fn handle_datagram_drops_non_binding_method() {
    let txn_id = [0x44u8; 12];
    let other_method = build_message(MessageClass::Request, Method::Extension(0x123), &txn_id, &[]);
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    assert!(handle_datagram(&other_method, peer).is_none());
}

#[test]
fn handle_datagram_drops_unparseable_garbage_not_panic() {
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let garbage: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(handle_datagram(garbage, peer).is_none());
}

#[test]
fn handle_datagram_different_peers_get_different_observed_addresses() {
    let txn_id = [0x55u8; 12];
    let request = make_binding_request(&txn_id);

    let peer_a: SocketAddr = "1.2.3.4:1111".parse().unwrap();
    let peer_b: SocketAddr = "5.6.7.8:2222".parse().unwrap();

    let resp_a = handle_datagram(&request, peer_a).unwrap();
    let resp_b = handle_datagram(&request, peer_b).unwrap();

    let parsed_a = parse_message(&resp_a).unwrap();
    let parsed_b = parse_message(&resp_b).unwrap();

    let addr_a = decode_attributes(&parsed_a.attributes_raw, &parsed_a.transaction_id);
    let addr_b = decode_attributes(&parsed_b.attributes_raw, &parsed_b.transaction_id);

    let get_addr = |attrs: &[Attribute]| attrs.iter().find_map(|a| match a {
        Attribute::XorMappedAddress(addr) => Some(*addr),
        _ => None,
    }).unwrap();

    assert_eq!(get_addr(&addr_a).ip, peer_a.ip());
    assert_eq!(get_addr(&addr_b).ip, peer_b.ip());
    assert_ne!(get_addr(&addr_a), get_addr(&addr_b));
}
