//! STUN-layer tests for what ICE checks depend on: the new attributes,
//! CRC-32/FINGERPRINT, general-key MESSAGE-INTEGRITY, and the attribute
//! locator. Fixtures come from an independent Python oracle
//! (hmac/hashlib/zlib), generated rather than hand-transcribed.

include!("ice_check_fixtures.rs");

use nat_traversal::stun::{
    attributes::{
        decode_attributes, Attribute, ATTR_FINGERPRINT, ATTR_ICE_CONTROLLED,
        ATTR_ICE_CONTROLLING, ATTR_MESSAGE_INTEGRITY, ATTR_PRIORITY, ATTR_USERNAME,
        ATTR_USE_CANDIDATE,
    },
    builder::{build_attribute, build_message},
    fingerprint::{append_fingerprint, crc32, verify_fingerprint, FINGERPRINT_XOR},
    integrity::{append_integrity, verify_integrity},
    parser::{parse_message, MessageClass, Method},
    scan::locate_attribute,
};
use nat_traversal::turn::{build_authenticated_request, hmac_sha1, long_term_key};

/// Decode a single crafted attribute through the real parse path.
fn decode_one_attr(attr_type: u16, value: &[u8]) -> Vec<Attribute> {
    let attrs = build_attribute(attr_type, value);
    let wire = build_message(MessageClass::Request, Method::Binding, &[0u8; 12], &attrs);
    let parsed = parse_message(&wire).expect("crafted message must parse");
    decode_attributes(&parsed.attributes_raw, &parsed.transaction_id)
}

fn strip_fingerprint(msg: &[u8]) -> Vec<u8> {
    let mut m = msg[..msg.len() - 8].to_vec();
    let len = (m.len() - 20) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    m
}

// ─── New attributes ─────────────────────────────────────────────────

#[test]
fn priority_decodes() {
    let attrs = decode_one_attr(ATTR_PRIORITY, &0x6E00_01FFu32.to_be_bytes());
    assert_eq!(attrs, vec![Attribute::Priority(0x6E00_01FF)]);
}

#[test]
fn priority_with_wrong_length_is_dropped() {
    assert!(decode_one_attr(ATTR_PRIORITY, &[1, 2, 3]).is_empty());
    assert!(decode_one_attr(ATTR_PRIORITY, &[1, 2, 3, 4, 5]).is_empty());
}

#[test]
fn ice_controlling_decodes_full_64_bit_value() {
    let attrs = decode_one_attr(ATTR_ICE_CONTROLLING, &u64::MAX.to_be_bytes());
    assert_eq!(attrs, vec![Attribute::IceControlling(u64::MAX)]);
}

#[test]
fn ice_controlled_decodes_full_64_bit_value() {
    let attrs = decode_one_attr(ATTR_ICE_CONTROLLED, &0x0123_4567_89AB_CDEFu64.to_be_bytes());
    assert_eq!(attrs, vec![Attribute::IceControlled(0x0123_4567_89AB_CDEF)]);
}

#[test]
fn role_attributes_with_wrong_length_are_dropped() {
    for ty in [ATTR_ICE_CONTROLLING, ATTR_ICE_CONTROLLED] {
        assert!(decode_one_attr(ty, &[0; 7]).is_empty(), "7-byte tie-breaker must be dropped");
        assert!(decode_one_attr(ty, &[0; 9]).is_empty(), "9-byte tie-breaker must be dropped");
    }
}

#[test]
fn use_candidate_decodes_only_when_zero_length() {
    assert_eq!(decode_one_attr(ATTR_USE_CANDIDATE, &[]), vec![Attribute::UseCandidate]);
    assert!(decode_one_attr(ATTR_USE_CANDIDATE, &[1]).is_empty(), "a flag with content is malformed");
}

#[test]
fn fingerprint_attribute_decodes_its_value() {
    let attrs = decode_one_attr(ATTR_FINGERPRINT, &0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(attrs, vec![Attribute::Fingerprint(0xDEAD_BEEF)]);
}

// ─── Attribute locator ──────────────────────────────────────────────

#[test]
fn locate_finds_attributes_at_structurally_derivable_offsets() {
    // USERNAME "rmtu:lcl1" is 9 bytes, padded to 12. Header is 20 bytes, so
    // USERNAME's TLV starts at 20 (value at 24) and PRIORITY's at 24+12=36.
    let u = locate_attribute(REQ_CONTROLLING, ATTR_USERNAME).expect("USERNAME present");
    assert_eq!((u.tlv_start, u.value_start, u.value_len), (20, 24, 9));
    let p = locate_attribute(REQ_CONTROLLING, ATTR_PRIORITY).expect("PRIORITY present");
    assert_eq!((p.tlv_start, p.value_start, p.value_len), (36, 40, 4));
}

#[test]
fn locate_returns_none_for_absent_attribute() {
    assert!(locate_attribute(REQ_CONTROLLED, ATTR_USE_CANDIDATE).is_none());
}

#[test]
fn locate_handles_short_and_truncated_buffers_without_panicking() {
    assert!(locate_attribute(&[], ATTR_PRIORITY).is_none());
    assert!(locate_attribute(&REQ_CONTROLLING[..10], ATTR_PRIORITY).is_none());
    // Cut mid-attribute: the walk must report "not found", never read out of bounds.
    for cut in 20..REQ_CONTROLLING.len() {
        let _ = locate_attribute(&REQ_CONTROLLING[..cut], ATTR_FINGERPRINT);
    }
}

#[test]
fn locate_returns_the_first_of_duplicate_attributes() {
    let mut attrs = build_attribute(ATTR_PRIORITY, &1u32.to_be_bytes());
    attrs.extend_from_slice(&build_attribute(ATTR_PRIORITY, &2u32.to_be_bytes()));
    let wire = build_message(MessageClass::Request, Method::Binding, &[0u8; 12], &attrs);
    let loc = locate_attribute(&wire, ATTR_PRIORITY).unwrap();
    assert_eq!(loc.tlv_start, 20, "must return the first occurrence");
}

// ─── CRC-32 ─────────────────────────────────────────────────────────

#[test]
fn crc32_matches_python_zlib_on_every_vector() {
    for (input, expected) in CRC32_VECTORS {
        assert_eq!(crc32(input), *expected, "crc32({input:?})");
    }
}

#[test]
fn crc32_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn fingerprint_xor_constant_spells_stun() {
    assert_eq!(&FINGERPRINT_XOR.to_be_bytes(), b"STUN");
}

// ─── FINGERPRINT ────────────────────────────────────────────────────

#[test]
fn fingerprint_verifies_every_oracle_message() {
    for (name, msg) in [
        ("controlling request", REQ_CONTROLLING),
        ("controlled request", REQ_CONTROLLED),
        ("success response", RESP_SUCCESS),
        ("role conflict", RESP_ROLE_CONFLICT),
        ("401 without MI", RESP_UNAUTHORIZED_NO_MI),
    ] {
        assert!(verify_fingerprint(msg), "{name} must verify");
    }
}

#[test]
fn fingerprint_value_matches_the_oracle() {
    let tail = &REQ_CONTROLLING[REQ_CONTROLLING.len() - 4..];
    assert_eq!(u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]), REQ_CONTROLLING_FP);
}

#[test]
fn fingerprint_detects_every_single_bit_flip() {
    // CRC-32 detects all single-bit errors; prove it over every bit of
    // every byte preceding the fingerprint, header included.
    let body_len = REQ_CONTROLLING.len() - 8;
    for byte in 0..body_len {
        for bit in 0..8 {
            let mut m = REQ_CONTROLLING.to_vec();
            m[byte] ^= 1 << bit;
            assert!(!verify_fingerprint(&m), "flip at byte {byte} bit {bit} went undetected");
        }
    }
}

#[test]
fn fingerprint_rejects_when_missing() {
    assert!(!verify_fingerprint(&strip_fingerprint(REQ_CONTROLLING)));
}

#[test]
fn fingerprint_rejects_when_not_the_last_attribute() {
    let mut m = REQ_CONTROLLING.to_vec();
    m.extend_from_slice(&build_attribute(ATTR_USE_CANDIDATE, &[])); // 4 more bytes after it
    let len = (m.len() - 20) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    assert!(!verify_fingerprint(&m), "FINGERPRINT must be final");
}

#[test]
fn fingerprint_rejects_trailing_bytes_beyond_declared_length() {
    let mut m = REQ_CONTROLLING.to_vec();
    m.push(0);
    assert!(!verify_fingerprint(&m));
}

#[test]
fn fingerprint_rejects_truncated_and_empty_input_without_panicking() {
    assert!(!verify_fingerprint(&[]));
    for cut in 0..REQ_CONTROLLING.len() {
        assert!(!verify_fingerprint(&REQ_CONTROLLING[..cut]), "cut at {cut}");
    }
}

#[test]
fn append_fingerprint_round_trips_and_updates_the_length_field() {
    let attrs = build_attribute(ATTR_USERNAME, b"someone");
    let mut m = build_message(MessageClass::Request, Method::Binding, &[9u8; 12], &attrs);
    append_fingerprint(&mut m);
    assert!(verify_fingerprint(&m));
    let declared = u16::from_be_bytes([m[2], m[3]]) as usize;
    assert_eq!(declared, m.len() - 20, "header length must count the FINGERPRINT itself");
}

#[test]
fn append_fingerprint_reproduces_the_oracle_byte_for_byte() {
    let mut m = strip_fingerprint(RESP_UNAUTHORIZED_NO_MI);
    append_fingerprint(&mut m);
    assert_eq!(m, RESP_UNAUTHORIZED_NO_MI);
}

// ─── MESSAGE-INTEGRITY (general key, trailing FINGERPRINT) ──────────

#[test]
fn integrity_verifies_every_signed_oracle_message() {
    for (name, msg) in [
        ("controlling request", REQ_CONTROLLING),
        ("controlled request", REQ_CONTROLLED),
        ("success response", RESP_SUCCESS),
        ("role conflict", RESP_ROLE_CONFLICT),
    ] {
        assert!(verify_integrity(msg, CHECK_PASSWORD), "{name} must verify");
    }
}

#[test]
fn integrity_value_matches_the_oracle() {
    let loc = locate_attribute(REQ_CONTROLLING, ATTR_MESSAGE_INTEGRITY).unwrap();
    assert_eq!(
        &REQ_CONTROLLING[loc.value_start..loc.value_start + 20],
        &REQ_CONTROLLING_MI[..]
    );
}

#[test]
fn integrity_is_false_when_the_message_carries_none() {
    assert!(!verify_integrity(RESP_UNAUTHORIZED_NO_MI, CHECK_PASSWORD));
}

#[test]
fn integrity_rejects_the_wrong_password() {
    assert!(!verify_integrity(REQ_CONTROLLING, b"remotepwd-0123456789abcX"));
    assert!(!verify_integrity(REQ_CONTROLLING, b""));
}

#[test]
fn integrity_detects_every_single_bit_flip_before_it() {
    // Bytes 2..4 are the length field, which verification deliberately
    // overwrites with the length-through-MI value (RFC 5389 §15.4), so MI
    // alone cannot see changes there. They are covered instead by FINGERPRINT
    // and by the parser's declared-length-must-match-datagram check.
    let loc = locate_attribute(REQ_CONTROLLING, ATTR_MESSAGE_INTEGRITY).unwrap();
    for byte in 0..loc.tlv_start {
        if (2..4).contains(&byte) {
            continue;
        }
        for bit in 0..8 {
            let mut m = REQ_CONTROLLING.to_vec();
            m[byte] ^= 1 << bit;
            assert!(!verify_integrity(&m, CHECK_PASSWORD), "flip at byte {byte} bit {bit} went undetected");
        }
    }
}

#[test]
fn integrity_survives_a_trailing_fingerprint_where_the_naive_approach_does_not() {
    // The reason this module exists. The received header length counts the
    // trailing FINGERPRINT, so hashing the received prefix unchanged — what
    // the TURN-side verifier does — cannot reproduce the sender's HMAC.
    let loc = locate_attribute(REQ_CONTROLLING, ATTR_MESSAGE_INTEGRITY).unwrap();
    let naive = hmac_sha1(CHECK_PASSWORD, &REQ_CONTROLLING[..loc.tlv_start]);
    assert_ne!(
        &naive[..],
        &REQ_CONTROLLING[loc.value_start..loc.value_start + 20],
        "the naive prefix hash must NOT match when FINGERPRINT trails MI"
    );
    assert!(verify_integrity(REQ_CONTROLLING, CHECK_PASSWORD), "length-rewriting verifier must accept it");
}

#[test]
fn integrity_is_a_strict_superset_of_the_turn_verifier() {
    // A TURN long-term message (no trailing attributes, 16-byte MD5 key)
    // must verify under the general function too.
    let msg = build_authenticated_request(
        Method::Allocate, &[7u8; 12], "alice", "routing-core.local", "f00dcafe", "correcthorsebatterystaple",
    );
    let key = long_term_key("alice", "routing-core.local", "correcthorsebatterystaple");
    assert!(verify_integrity(&msg, &key));
    assert!(!verify_integrity(&msg, b"not the key"));
}

#[test]
fn append_integrity_reproduces_the_oracle_byte_for_byte() {
    // Strip MI and FINGERPRINT from the oracle request, re-sign with the
    // Rust builders, and require the identical bytes.
    let loc = locate_attribute(REQ_CONTROLLING, ATTR_MESSAGE_INTEGRITY).unwrap();
    let mut m = REQ_CONTROLLING[..loc.tlv_start].to_vec();
    let len = (m.len() - 20) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    append_integrity(&mut m, CHECK_PASSWORD);
    append_fingerprint(&mut m);
    assert_eq!(m, REQ_CONTROLLING);
}

#[test]
fn integrity_handles_malformed_attributes_without_panicking() {
    // MI declared 16 bytes instead of 20.
    let attrs = build_attribute(ATTR_MESSAGE_INTEGRITY, &[0u8; 16]);
    let wire = build_message(MessageClass::Request, Method::Binding, &[1u8; 12], &attrs);
    assert!(!verify_integrity(&wire, CHECK_PASSWORD));
    // Truncated everywhere.
    for cut in 0..REQ_CONTROLLING.len() {
        let _ = verify_integrity(&REQ_CONTROLLING[..cut], CHECK_PASSWORD);
    }
}

#[test]
fn fingerprint_is_a_checksum_not_security() {
    // Tamper with PRIORITY, then recompute a *valid* FINGERPRINT over the
    // tampered content: the fingerprint verifies, but integrity must not.
    let mut m = REQ_CONTROLLING.to_vec();
    let p = locate_attribute(&m, ATTR_PRIORITY).unwrap();
    m[p.value_start] ^= 0x01;
    let mut m = strip_fingerprint(&m);
    append_fingerprint(&mut m);
    assert!(verify_fingerprint(&m), "the forged message has a perfectly valid fingerprint");
    assert!(!verify_integrity(&m, CHECK_PASSWORD), "but its MESSAGE-INTEGRITY must fail");
}
