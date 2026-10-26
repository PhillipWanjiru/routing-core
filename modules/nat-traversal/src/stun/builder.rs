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
        Method::Binding          => 0x001,
        Method::Allocate         => 0x003,
        Method::Refresh          => 0x004,
        Method::Send             => 0x006,
        Method::Data             => 0x007,
        Method::CreatePermission => 0x008,
        Method::ChannelBind      => 0x009,
        Method::Extension(m)     => m,
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

/// Build just the 20-byte STUN header, with an explicitly given length
/// field rather than one derived from an attributes slice.
///
/// Used by `turn::auth` to construct the "adjusted length" prefix needed
/// for MESSAGE-INTEGRITY computation (RFC 5389 §15.4), where the header
/// must describe a length that includes an attribute (MESSAGE-INTEGRITY
/// itself) not yet appended to the bytes being hashed.
pub fn build_header_with_length(
    class: MessageClass,
    method: Method,
    transaction_id: &[u8; 12],
    length: u16,
) -> Vec<u8> {
    let msg_type = encode_class_and_method(class, method);
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(transaction_id);
    out
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
    let mut out = build_header_with_length(class, method, transaction_id, attributes.len() as u16);
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

// ─── ERROR-CODE (RFC 5389 §15.6) and error responses ────────────────

/// Encode an ERROR-CODE attribute value (without the 4-byte TLV header —
/// [`build_attribute`] adds that).
///
/// Format: 2 reserved bytes (must be zero) + 1 byte class (low 3 bits,
/// e.g. 4 for a 4xx code) + 1 byte number (0-99) + UTF-8 reason phrase.
/// This is the exact inverse of `attributes::decode_error_code` — a code
/// of 401 becomes class=4, number=1, matching what that decoder expects
/// back (`code = class * 100 + number`).
pub fn encode_error_code(code: u16, reason: &str) -> Vec<u8> {
    let class  = (code / 100) as u8;
    let number = (code % 100) as u8;
    let mut value = vec![0u8, 0u8, class & 0x07, number];
    value.extend_from_slice(reason.as_bytes());
    value
}

/// Build a complete STUN error response: header (ErrorResponse class) +
/// ERROR-CODE attribute + any additional caller-supplied attributes
/// (already TLV-encoded, e.g. REALM/NONCE for a 401 challenge).
pub fn build_error_response(
    method: Method,
    transaction_id: &[u8; 12],
    code: u16,
    reason: &str,
    extra_attrs: &[u8],
) -> Vec<u8> {
    let error_attr = build_attribute(super::attributes::ATTR_ERROR_CODE, &encode_error_code(code, reason));
    let mut attrs = error_attr;
    attrs.extend_from_slice(extra_attrs);
    build_message(MessageClass::ErrorResponse, method, transaction_id, &attrs)
}

/// Build a 401 Unauthorized challenge: ERROR-CODE(401) + REALM + NONCE.
///
/// RFC 5389 §10.2.2 / RFC 5766 §9: this is how a server tells a client
/// "authenticate with these credentials against this realm, using this
/// nonce" — the client is expected to resend the same request with
/// USERNAME + the echoed REALM + the echoed NONCE + a computed
/// MESSAGE-INTEGRITY attribute added.
pub fn build_401_challenge(method: Method, transaction_id: &[u8; 12], realm: &str, nonce: &str) -> Vec<u8> {
    let realm_attr = build_attribute(super::attributes::ATTR_REALM, realm.as_bytes());
    let nonce_attr = build_attribute(super::attributes::ATTR_NONCE, nonce.as_bytes());
    let mut extra = realm_attr;
    extra.extend_from_slice(&nonce_attr);
    build_error_response(method, transaction_id, 401, "Unauthorized", &extra)
}

/// Build a 438 Stale Nonce response: ERROR-CODE(438) + REALM + a fresh
/// NONCE. RFC 5766 §9: sent when a request's NONCE was once valid but
/// has since expired — distinct from 401, which is for missing or
/// incorrect credentials entirely.
///
/// The specific code 438 is, like the TURN method numbers, a recalled
/// registry value rather than something derivable — flagged for the same
/// reason.
pub fn build_438_stale_nonce(method: Method, transaction_id: &[u8; 12], realm: &str, fresh_nonce: &str) -> Vec<u8> {
    let realm_attr = build_attribute(super::attributes::ATTR_REALM, realm.as_bytes());
    let nonce_attr = build_attribute(super::attributes::ATTR_NONCE, fresh_nonce.as_bytes());
    let mut extra = realm_attr;
    extra.extend_from_slice(&nonce_attr);
    build_error_response(method, transaction_id, 438, "Stale Nonce", &extra)
}

pub fn encode_lifetime(seconds: u32) -> Vec<u8> {
    seconds.to_be_bytes().to_vec()
}

pub fn build_allocate_success_response(
    transaction_id: &[u8; 12],
    relayed_addr: SocketAddrAttr,
    lifetime_secs: u32,
) -> Vec<u8> {
    let relayed_value = encode_xor_mapped_address(&relayed_addr, transaction_id);
    let relayed_attr  = build_attribute(super::attributes::ATTR_XOR_RELAYED_ADDRESS, &relayed_value);
    let lifetime_attr = build_attribute(super::attributes::ATTR_LIFETIME, &encode_lifetime(lifetime_secs));

    let mut attrs = relayed_attr;
    attrs.extend_from_slice(&lifetime_attr);
    build_message(MessageClass::SuccessResponse, Method::Allocate, transaction_id, &attrs)
}

pub fn build_refresh_success_response(transaction_id: &[u8; 12], lifetime_secs: u32) -> Vec<u8> {
    let lifetime_attr = build_attribute(super::attributes::ATTR_LIFETIME, &encode_lifetime(lifetime_secs));
    build_message(MessageClass::SuccessResponse, Method::Refresh, transaction_id, &lifetime_attr)
}

// ─── TURN CreatePermission responses ────────────────────────────

/// Build a CreatePermission Success Response. RFC 5766 §9 requires no
/// attributes in the success case — the response's class, method, and
/// echoed transaction ID are the entire confirmation.
pub fn build_create_permission_success_response(transaction_id: &[u8; 12]) -> Vec<u8> {
    build_message(MessageClass::SuccessResponse, Method::CreatePermission, transaction_id, &[])
}

/// Build a 437 Allocation Mismatch error — sent when a request arrives
/// for a client that has no existing allocation (RFC 5766 §9). Like the
/// other TURN numeric codes in this project, 437 is recalled from
/// training data rather than independently derivable; confirm against
/// RFC 5766 before real-world interop.
pub fn build_437_allocation_mismatch(method: Method, transaction_id: &[u8; 12]) -> Vec<u8> {
    build_error_response(method, transaction_id, 437, "Allocation Mismatch", &[])
}

// ─── ICE attribute value encoders (RFC 8445 §7.1) ───────────────

/// PRIORITY attribute value: one big-endian u32.
pub fn encode_priority(priority: u32) -> Vec<u8> {
    priority.to_be_bytes().to_vec()
}

/// ICE-CONTROLLING / ICE-CONTROLLED attribute value: one big-endian u64
/// tie-breaker.
pub fn encode_tie_breaker(tie_breaker: u64) -> Vec<u8> {
    tie_breaker.to_be_bytes().to_vec()
}

// ─── TURN relay data-path builders (RFC 5766 §10, §11) ──────────

/// IANA IP protocol number for UDP — the only transport this TURN server relays.
pub const IP_PROTOCOL_UDP: u8 = 17;

/// CHANNEL-NUMBER value: the 16-bit channel number, then 16 reserved bits.
pub fn encode_channel_number(channel: u16) -> Vec<u8> {
    let b = channel.to_be_bytes();
    vec![b[0], b[1], 0, 0]
}

/// REQUESTED-TRANSPORT value: the IP protocol number, then 24 reserved bits.
pub fn encode_requested_transport(protocol: u8) -> Vec<u8> {
    vec![protocol, 0, 0, 0]
}

/// A Send or Data indication: XOR-PEER-ADDRESS then DATA. The two directions
/// share one shape — Send goes client → server, Data server → client — and
/// differ only in method.
fn build_peer_data_indication(
    method: Method,
    txn: &[u8; 12],
    peer: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let peer_value = encode_xor_mapped_address(&SocketAddrAttr { ip: peer.ip(), port: peer.port() }, txn);
    let mut attrs = build_attribute(crate::stun::attributes::ATTR_XOR_PEER_ADDRESS, &peer_value);
    attrs.extend_from_slice(&build_attribute(crate::stun::attributes::ATTR_DATA, payload));
    build_message(MessageClass::Indication, method, txn, &attrs)
}

/// Client → server: relay `payload` to `peer`.
pub fn build_send_indication(txn: &[u8; 12], peer: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    build_peer_data_indication(Method::Send, txn, peer, payload)
}

/// Server → client: `payload` arrived from `peer` on the relayed address. The
/// peer's identity travels with the data — without it the client could not tell
/// who sent a packet.
pub fn build_data_indication(txn: &[u8; 12], peer: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    build_peer_data_indication(Method::Data, txn, peer, payload)
}

pub fn build_channel_bind_success_response(txn: &[u8; 12]) -> Vec<u8> {
    build_message(MessageClass::SuccessResponse, Method::ChannelBind, txn, &[])
}

/// Allocate success: the relayed address, the client's own reflexive address as
/// the server saw it, and the granted lifetime (RFC 5766 §6.2). The mapped
/// address is how a TURN client learns its server-reflexive address for free.
pub fn build_allocate_success_response_with_mapped(
    txn: &[u8; 12],
    relayed: SocketAddrAttr,
    mapped: SocketAddrAttr,
    lifetime_secs: u32,
) -> Vec<u8> {
    let mut attrs = build_attribute(
        crate::stun::attributes::ATTR_XOR_RELAYED_ADDRESS, &encode_xor_mapped_address(&relayed, txn),
    );
    attrs.extend_from_slice(&build_attribute(ATTR_XOR_MAPPED_ADDRESS, &encode_xor_mapped_address(&mapped, txn)));
    attrs.extend_from_slice(&build_attribute(crate::stun::attributes::ATTR_LIFETIME, &lifetime_secs.to_be_bytes()));
    build_message(MessageClass::SuccessResponse, Method::Allocate, txn, &attrs)
}
