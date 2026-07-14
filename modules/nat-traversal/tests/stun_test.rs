//! STUN parser and attribute tests.
//!
//! Test vectors are constructed independently in Python directly from the
//! RFC 5389 §6 and §15 bit-layout rules (message-type class/method bit
//! interleaving, XOR-MAPPED-ADDRESS obfuscation), then self-verified by
//! decoding them back with separately-written Python before being
//! transcribed here — the same "compute independently before writing the
//! Rust test" discipline used throughout this project (Erlang B reference
//! tables, G.711 SNR, the E-model MOS worked examples). We deliberately
//! do not rely on recalling RFC 5769's published test vectors from
//! memory — a misremembered byte would silently "verify" against itself.

use nat_traversal::stun::{
    attributes::{decode_attributes, decode_xor_mapped_address, encode_xor_mapped_address,
                 Attribute, SocketAddrAttr},
    parser::{parse_message, MessageClass, Method, ParseError, MAGIC_COOKIE},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ─── Vector 1: Binding Request, no attributes ────────────────────

#[test]
fn vector1_binding_request_parses() {
    let raw: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let msg = parse_message(raw).expect("should parse a well-formed Binding Request");
    assert_eq!(msg.class, MessageClass::Request);
    assert_eq!(msg.method, Method::Binding);
    assert_eq!(msg.message_length, 0);
    assert_eq!(msg.transaction_id, [0,1,2,3,4,5,6,7,8,9,10,11]);
    assert!(msg.attributes_raw.is_empty());
    assert!(msg.is_binding_request());
}

#[test]
fn magic_cookie_constant_matches_rfc5389() {
    assert_eq!(MAGIC_COOKIE, 0x2112_A442);
}

// ─── Vector 2: Success Response with IPv4 XOR-MAPPED-ADDRESS ────

#[test]
fn vector2_xor_mapped_address_ipv4_decodes_correctly() {
    let raw: &[u8] = &[
        0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x20, 0x00, 0x08,
        0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
    ];
    let msg = parse_message(raw).expect("should parse Binding Success Response");
    assert_eq!(msg.class, MessageClass::SuccessResponse);
    assert_eq!(msg.method, Method::Binding);

    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert_eq!(attrs.len(), 1);

    match &attrs[0] {
        Attribute::XorMappedAddress(addr) => {
            assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
            assert_eq!(addr.port, 32853);
        }
        other => panic!("expected XorMappedAddress, got {other:?}"),
    }
}

// ─── Vector 3: corrupted magic cookie ────────────────────────────

#[test]
fn vector3_wrong_magic_cookie_is_rejected() {
    let raw: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let result = parse_message(raw);
    assert!(result.is_err(), "message with wrong magic cookie must be rejected");
    match result.unwrap_err() {
        ParseError::Malformed(_) => {} // expected
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// ─── Vector 4: top two bits set (must be rejected per RFC 5389 §6) ──

#[test]
fn vector4_top_bits_set_is_rejected() {
    let raw: &[u8] = &[
        0xc0, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let result = parse_message(raw);
    assert!(
        result.is_err(),
        "message with top 2 bits set must be rejected — this is what lets STUN \
         share a port unambiguously with RTP/RTCP, and silently accepting it \
         would break that demultiplexing guarantee"
    );
}

// ─── Vector 5: non-XOR MAPPED-ADDRESS ────────────────────────────

#[test]
fn vector5_mapped_address_ipv4_decodes_without_xor() {
    let raw: &[u8] = &[
        0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x00, 0x01, 0x00, 0x08,
        0x00, 0x01, 0x15, 0xb3, 0x0a, 0x14, 0x1e, 0x28,
    ];
    let msg = parse_message(raw).unwrap();
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert_eq!(attrs.len(), 1);
    match &attrs[0] {
        Attribute::MappedAddress(addr) => {
            assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
            assert_eq!(addr.port, 5555);
        }
        other => panic!("expected MappedAddress, got {other:?}"),
    }
}

// ─── Vector 6: IPv6 XOR-MAPPED-ADDRESS ───────────────────────────

#[test]
fn vector6_xor_mapped_address_ipv6_decodes_correctly() {
    let raw: &[u8] = &[
        0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x20, 0x00, 0x14,
        0x00, 0x02, 0x3e, 0x82, 0x01, 0x13, 0xa9, 0xfa, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x67,
    ];
    let msg = parse_message(raw).unwrap();
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert_eq!(attrs.len(), 1);
    match &attrs[0] {
        Attribute::XorMappedAddress(addr) => {
            assert_eq!(
                addr.ip,
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
            );
            assert_eq!(addr.port, 8080);
        }
        other => panic!("expected XorMappedAddress, got {other:?}"),
    }
}

// ─── Vector 7: declared length exceeds available input ──────────

#[test]
fn vector7_declared_length_exceeding_datagram_is_malformed() {
    // STUN's transport here is UDP: recv_from() always hands us one
    // complete, atomic datagram — there is no "the rest is still coming."
    // A message_length field claiming 100 bytes when only 4 are present
    // in an already-complete datagram is not incomplete, it's corrupt or
    // malicious. Treating it as NeedsMoreData would mean waiting on bytes
    // that will never arrive — a mild DoS vector. Malformed is correct.
    let raw: &[u8] = &[
        0x00, 0x01, 0x00, 0x64, 0x21, 0x12, 0xa4, 0x42, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x00, 0x01, 0x00, 0x00,
    ];
    let result = parse_message(raw);
    assert!(
        matches!(result, Err(ParseError::Malformed(_))),
        "declared message_length=100 exceeding an already-complete 24-byte \
         datagram must be rejected as Malformed, not panic, not read past \
         the buffer, and not wait indefinitely as NeedsMoreData; got {result:?}"
    );
}

#[test]
fn empty_input_is_rejected_not_panic() {
    let result = parse_message(&[]);
    assert!(result.is_err(), "empty input must not panic");
}

#[test]
fn single_byte_is_rejected_not_panic() {
    let result = parse_message(&[0x00]);
    assert!(result.is_err(), "single byte must not panic");
}

// ─── Vector 8: two attributes, tests iteration + 4-byte padding ──

#[test]
fn vector8_multiple_attributes_with_padding_all_decode() {
    let raw: &[u8] = &[
        0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x00, 0x06, 0x00, 0x03,
        0x61, 0x62, 0x63, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x11, 0x2b,
        0xea, 0x12, 0xd5, 0x47,
    ];
    let msg = parse_message(raw).unwrap();
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert_eq!(
        attrs.len(), 2,
        "both attributes must decode — this verifies the padded-length \
         iteration advances past the 3-byte USERNAME's 1 padding byte \
         correctly to find the second attribute"
    );

    let Attribute::Username(name) = &attrs[0] else {
        panic!("expected Username first, got {:?}", attrs[0]);
    };
    assert_eq!(name, "abc");

    let Attribute::XorMappedAddress(addr) = &attrs[1] else {
        panic!("expected XorMappedAddress second, got {:?}", attrs[1]);
    };
    assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(addr.port, 12345);
}

// ─── Vector 9: unknown attribute type is preserved, not dropped ─

#[test]
fn vector9_unknown_attribute_type_preserved() {
    let raw: &[u8] = &[
        0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0xc1, 0xc2, 0xc3, 0xc4,
        0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0x99, 0x99, 0x00, 0x04,
        0xde, 0xad, 0xbe, 0xef,
    ];
    let msg = parse_message(raw).unwrap();
    let attrs = decode_attributes(&msg.attributes_raw, &msg.transaction_id);
    assert_eq!(attrs.len(), 1);
    match &attrs[0] {
        Attribute::Unknown { attr_type, value } => {
            assert_eq!(*attr_type, 0x9999);
            assert_eq!(value, &[0xde, 0xad, 0xbe, 0xef]);
        }
        other => panic!(
            "unknown attribute types must be preserved (RFC 5389 §15 \
             forward-compatibility requirement), got {other:?}"
        ),
    }
}

// ─── Vector 10: Indication class, non-Binding method ─────────────

#[test]
fn vector10_indication_class_and_extension_method_decode() {
    let raw: &[u8] = &[
        0x00, 0x12, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    ];
    let msg = parse_message(raw).unwrap();
    assert_eq!(msg.class, MessageClass::Indication);
    assert_eq!(msg.method, Method::Extension(0x002));
    assert!(!msg.is_binding_request());
}

// ─── Round-trip: our own encode against our own decode ──────────

#[test]
fn xor_mapped_address_ipv4_round_trip() {
    let txn_id = [7u8; 12];
    let original = SocketAddrAttr {
        ip:   IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)),
        port: 54321,
    };
    let encoded = encode_xor_mapped_address(&original, &txn_id);
    let decoded = decode_xor_mapped_address(&encoded, &txn_id).expect("decode must succeed");
    assert_eq!(decoded, original);
}

#[test]
fn xor_mapped_address_ipv6_round_trip() {
    let txn_id = [42u8; 12];
    let original = SocketAddrAttr {
        ip:   IpAddr::V6("2001:db8:1234::5678".parse().unwrap()),
        port: 9999,
    };
    let encoded = encode_xor_mapped_address(&original, &txn_id);
    let decoded = decode_xor_mapped_address(&encoded, &txn_id).expect("decode must succeed");
    assert_eq!(decoded, original);
}

#[test]
fn xor_mapped_address_round_trip_different_transaction_ids_differ() {
    // The XOR mask for IPv6 includes the transaction ID (RFC 5389 §15.2),
    // so encoding the same address with two different transaction IDs
    // must produce different ciphertext-like bytes — this is the same
    // "IV must be unique per encryption" property SRTP relies on, applied
    // here to obfuscation rather than encryption.
    let addr = SocketAddrAttr {
        ip:   IpAddr::V6("::1".parse().unwrap()),
        port: 1234,
    };
    let enc_a = encode_xor_mapped_address(&addr, &[1u8; 12]);
    let enc_b = encode_xor_mapped_address(&addr, &[2u8; 12]);
    assert_ne!(
        enc_a, enc_b,
        "same address with different transaction IDs must XOR-obfuscate differently"
    );
}

// ─── Attribute-level error handling ──────────────────────────────

#[test]
fn decode_xor_mapped_address_rejects_truncated_value() {
    let txn_id = [0u8; 12];
    let too_short: &[u8] = &[0x00, 0x01, 0x00, 0x00]; // family+port only, no address bytes
    let result = decode_xor_mapped_address(too_short, &txn_id);
    assert!(result.is_err(), "truncated attribute value must be rejected, not panic");
}

#[test]
fn decode_attributes_stops_cleanly_on_truncated_final_attribute() {
    // A well-formed 4-byte attribute header claiming 100 bytes of value,
    // but the buffer only has 2 more bytes. decode_attributes must return
    // whatever it successfully decoded before the truncation point,
    // not panic on the out-of-bounds slice.
    let txn_id = [0u8; 12];
    let raw: &[u8] = &[0x00, 0x06, 0x00, 0x64, 0xAB, 0xCD]; // USERNAME, len=100, only 2 bytes present
    let attrs = decode_attributes(raw, &txn_id);
    assert!(attrs.is_empty(), "truncated attribute must not be decoded, and must not panic");
}
