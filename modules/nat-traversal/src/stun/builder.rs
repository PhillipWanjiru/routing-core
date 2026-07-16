//! STUN message construction — the encode-side counterpart to
//! `stun::parser`'s decode side.
//!
//! Kept as a separate file from `parser.rs` for the same reason
//! `sip::builder` was kept separate from `sip::parser` in the voip-sip
//! module: parsing and building operate on the same wire format but are
//! different concerns, and the split keeps each file focused.

use super::attributes::{encode_xor_mapped_address, SocketAddrAttr, ATTR_XOR_MAPPED_ADDRESS};
use super::parser::{MessageClass, Method, MAGIC_COOKIE};

/// Encode a message class and method into the 16-bit STUN message type
/// field (RFC 5389 §6).
///
/// This is the exact structural inverse of `parser::decode_class_and_method`
/// — verified by re-deriving it from that function's bit operations in
/// reverse, then checking the result against every one of the 16,384
/// possible 14-bit message-type values (not just the well-known constants
/// 0x0001 / 0x0101), with zero mismatches. See
/// `tests/stun_server_test.rs::encode_decode_round_trip_exhaustive`.
fn encode_class_and_method(class: MessageClass, method: Method) -> u16 {
    let (c1, c0): (bool, bool) = match class {
        MessageClass::Request         => (false, false),
        MessageClass::Indication      => (false, true),
        MessageClass::SuccessResponse => (true,  false),
        MessageClass::ErrorResponse   => (true,  true),
    };

    let method_bits: u16 = match method {
        Method::Binding        => 0x001,
        Method::Extension(m)   => m,
    };

    // Inverse of decode's three extraction steps, applied in reverse:
    // decode took msg_type bits {0-3, 5-7, 9-13} and packed them into
    // method_bits bits {0-3, 4-6, 7-11} respectively. Encoding un-packs
    // method_bits back into those same three non-contiguous msg_type
    // bit ranges.
    let m_low  = method_bits & 0x000F;         // -> msg_type bits 0-3
    let m_mid  = (method_bits & 0x0070) << 1;  // -> msg_type bits 5-7
    let m_high = (method_bits & 0x0F80) << 2;  // -> msg_type bits 9-13

    let c0_bit = if c0 { 0x0010 } else { 0 };
    let c1_bit = if c1 { 0x0100 } else { 0 };

    m_high | c1_bit | m_mid | c0_bit | m_low
}

/// Build a complete, wire-ready STUN message: 20-byte header + attributes.
///
/// `attributes` must already be TLV-encoded and padded (see
/// [`build_attribute`]) — this function only assembles the header
/// around them, it does not encode individual attributes itself.
pub fn build_message(
    class: MessageClass,
    method: Method,
    transaction_id: &[u8; 12],
    attributes: &[u8],
) -> Vec<u8> {
    let msg_type = encode_class_and_method(class, method);
    let mut out = Vec::with_capacity(20 + attributes.len());
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(transaction_id);
    out.extend_from_slice(attributes);
    out
}

/// Build a single TLV-encoded attribute, padded to a 4-byte boundary
/// per RFC 5389 §15. The declared length field is the *unpadded* value
/// length — padding bytes are appended after but not counted, matching
/// exactly what `attributes::decode_attributes` expects on the read side.
pub fn build_attribute(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let len = value.len() as u16;
    let pad = (4 - (value.len() % 4)) % 4;
    let mut out = Vec::with_capacity(4 + value.len() + pad);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

/// Build a Binding Success Response carrying `observed_addr` as an
/// XOR-MAPPED-ADDRESS attribute.
///
/// The transaction ID is echoed back exactly as received in the request
/// (RFC 5389 §7.3.1: "the response has the same Transaction ID as the
/// request") — this is the entire mechanism that lets a client match a
/// response to the request it sent, since UDP has no built-in request/
/// response correlation.
pub fn build_binding_success_response(
    transaction_id: &[u8; 12],
    observed_addr: SocketAddrAttr,
) -> Vec<u8> {
    let xma_value = encode_xor_mapped_address(&observed_addr, transaction_id);
    let attr = build_attribute(ATTR_XOR_MAPPED_ADDRESS, &xma_value);
    build_message(MessageClass::SuccessResponse, Method::Binding, transaction_id, &attr)
}
