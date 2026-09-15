//! RFC 5389 STUN attribute decoding.
//!
//! Attributes are TLV-encoded: 2-byte type, 2-byte length, value padded
//! to a 4-byte boundary (RFC 5389 §15). This module decodes the
//! attributes this Phase 4 milestone actually needs; unknown attribute
//! types are skipped, not rejected — RFC 5389 §15 requires this so that
//! future extensions don't break existing parsers.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ─── Attribute type registry (RFC 5389 §18.2, subset) ───────────

pub const ATTR_MAPPED_ADDRESS:     u16 = 0x0001;
pub const ATTR_USERNAME:           u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY:  u16 = 0x0008;
pub const ATTR_ERROR_CODE:         u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM:              u16 = 0x0014;
pub const ATTR_NONCE:              u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE:           u16 = 0x8022;
pub const ATTR_FINGERPRINT:        u16 = 0x8028;

// RFC 5766 §14 (TURN) attribute types. Like the TURN method and error
// code numbers elsewhere in this project, these are IANA registry
// assignments recalled from training data, not independently derivable —
// confirm against RFC 5766's text before real-world interop.
pub const ATTR_LIFETIME:            u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS:    u16 = 0x0012;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;

/// STUN address family values (RFC 5389 §15.1).
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

// ─── Decoded attribute ────────────────────────────────────────────

/// One decoded attribute. Attributes this parser doesn't specifically
/// understand are preserved as `Unknown` (type, raw value) rather than
/// dropped — a caller inspecting `Unknown` attributes can still see
/// MESSAGE-INTEGRITY or FINGERPRINT bytes for later verification even
/// before dedicated decode support exists for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    XorMappedAddress(SocketAddrAttr),
    MappedAddress(SocketAddrAttr),
    Username(String),
    Realm(String),
    Nonce(String),
    Software(String),
    ErrorCode { code: u16, reason: String },
    XorRelayedAddress(SocketAddrAttr),
    /// RFC 5766 §14.3. Same wire format as XOR-MAPPED-ADDRESS again,
    /// different meaning once more: "here is a peer address I want to
    /// permit" (CreatePermission), or "here is the peer this Send/Data
    /// indication concerns" (once the relay data path exists). The port
    /// half is decoded for wire-format completeness, but permission
    /// checks deliberately use only the IP, per RFC 5766 §8's IP-only
    /// permission model.
    XorPeerAddress(SocketAddrAttr),
    Lifetime(u32),
    Unknown { attr_type: u16, value: Vec<u8> },
}

/// A decoded (already de-obfuscated, in the XOR-MAPPED-ADDRESS case)
/// socket address from a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddrAttr {
    pub ip:   IpAddr,
    pub port: u16,
}

impl fmt::Display for SocketAddrAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// Errors from attribute decoding — separate from the message-framing
/// `ParseError` in `parser.rs`, since here we're decoding meaning inside
/// an already-correctly-framed attributes section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeError {
    Truncated,
    UnsupportedFamily(u8),
    InvalidUtf8,
}

impl fmt::Display for AttributeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttributeError::Truncated => write!(f, "attribute value shorter than declared length"),
            AttributeError::UnsupportedFamily(fam) => write!(f, "unsupported address family: {fam:#04x}"),
            AttributeError::InvalidUtf8 => write!(f, "attribute value is not valid UTF-8"),
        }
    }
}

impl std::error::Error for AttributeError {}

// ─── Attribute-section iteration ──────────────────────────────────

/// Decode every attribute in a raw attributes section (as produced by
/// `parser::StunMessage::attributes_raw`), given the message's
/// transaction ID (needed for XOR-MAPPED-ADDRESS on IPv6, per RFC 5389
/// §15.2 — the XOR mask for the address is `magic_cookie || transaction_id`).
///
/// Malformed individual attributes are skipped rather than aborting the
/// whole decode — one corrupt optional attribute (e.g. a vendor extension
/// we don't recognise) should not prevent reading the attributes that
/// come after it.
pub fn decode_attributes(raw: &[u8], transaction_id: &[u8; 12]) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= raw.len() {
        let attr_type = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let attr_len  = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end   = value_start + attr_len;

        if value_end > raw.len() {
            break; // Truncated attribute — stop decoding, keep what we have.
        }

        let value = &raw[value_start..value_end];

        if let Some(decoded) = decode_one(attr_type, value, transaction_id) {
            attrs.push(decoded);
        }

        // RFC 5389 §15: attributes are padded to a 4-byte boundary.
        let padded_len = (attr_len + 3) & !3;
        offset = value_start + padded_len;
    }

    attrs
}

fn decode_one(attr_type: u16, value: &[u8], transaction_id: &[u8; 12]) -> Option<Attribute> {
    match attr_type {
        ATTR_XOR_MAPPED_ADDRESS => {
            decode_xor_mapped_address(value, transaction_id).ok().map(Attribute::XorMappedAddress)
        }
        ATTR_XOR_RELAYED_ADDRESS => {
            decode_xor_mapped_address(value, transaction_id).ok().map(Attribute::XorRelayedAddress)
        }
        ATTR_XOR_PEER_ADDRESS => {
            // Same reuse pattern again (RFC 5766 §14.3).
            decode_xor_mapped_address(value, transaction_id).ok().map(Attribute::XorPeerAddress)
        }
        ATTR_MAPPED_ADDRESS => {
            decode_mapped_address(value).ok().map(Attribute::MappedAddress)
        }
        ATTR_LIFETIME => {
            decode_lifetime(value).ok().map(Attribute::Lifetime)
        }
        ATTR_USERNAME => decode_utf8(value).ok().map(Attribute::Username),
        ATTR_REALM    => decode_utf8(value).ok().map(Attribute::Realm),
        ATTR_NONCE    => decode_utf8(value).ok().map(Attribute::Nonce),
        ATTR_SOFTWARE => decode_utf8(value).ok().map(Attribute::Software),
        ATTR_ERROR_CODE => decode_error_code(value).ok(),
        _ => Some(Attribute::Unknown { attr_type, value: value.to_vec() }),
    }
}

fn decode_lifetime(value: &[u8]) -> Result<u32, AttributeError> {
    if value.len() < 4 {
        return Err(AttributeError::Truncated);
    }
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn decode_utf8(value: &[u8]) -> Result<String, AttributeError> {
    std::str::from_utf8(value)
        .map(|s| s.to_owned())
        .map_err(|_| AttributeError::InvalidUtf8)
}

fn decode_error_code(value: &[u8]) -> Result<Attribute, AttributeError> {
    if value.len() < 4 {
        return Err(AttributeError::Truncated);
    }
    // RFC 5389 §15.6: byte 2 = class (top 3 bits of a 3-digit code),
    // byte 3 = number (bottom 2 digits).
    let class  = (value[2] & 0x07) as u16;
    let number = value[3] as u16;
    let code   = class * 100 + number;
    let reason = decode_utf8(&value[4..]).unwrap_or_default();
    Ok(Attribute::ErrorCode { code, reason })
}

// ─── MAPPED-ADDRESS (RFC 5389 §15.1) ────────────────────────────

fn decode_mapped_address(value: &[u8]) -> Result<SocketAddrAttr, AttributeError> {
    if value.len() < 4 {
        return Err(AttributeError::Truncated);
    }
    let family = value[1];
    let port   = u16::from_be_bytes([value[2], value[3]]);

    let ip = match family {
        FAMILY_IPV4 => {
            if value.len() < 8 { return Err(AttributeError::Truncated); }
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7]))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 { return Err(AttributeError::Truncated); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(AttributeError::UnsupportedFamily(other)),
    };

    Ok(SocketAddrAttr { ip, port })
}

// ─── XOR-MAPPED-ADDRESS (RFC 5389 §15.2) ────────────────────────

/// Decode an XOR-MAPPED-ADDRESS attribute value.
///
/// Port is XORed with the top 16 bits of the magic cookie.
/// IPv4 address is XORed with the magic cookie (32 bits).
/// IPv6 address is XORed with (magic cookie || transaction ID) — 128 bits.
pub fn decode_xor_mapped_address(
    value: &[u8],
    transaction_id: &[u8; 12],
) -> Result<SocketAddrAttr, AttributeError> {
    use crate::stun::parser::MAGIC_COOKIE;

    if value.len() < 4 {
        return Err(AttributeError::Truncated);
    }
    let family    = value[1];
    let xor_port  = u16::from_be_bytes([value[2], value[3]]);
    let port      = xor_port ^ ((MAGIC_COOKIE >> 16) as u16);

    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

    let ip = match family {
        FAMILY_IPV4 => {
            if value.len() < 8 { return Err(AttributeError::Truncated); }
            let mut octets = [0u8; 4];
            for i in 0..4 {
                octets[i] = value[4 + i] ^ cookie_bytes[i];
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 { return Err(AttributeError::Truncated); }
            // XOR mask is magic_cookie (4 bytes) || transaction_id (12 bytes).
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&cookie_bytes);
            mask[4..].copy_from_slice(transaction_id);

            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ mask[i];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(AttributeError::UnsupportedFamily(other)),
    };

    Ok(SocketAddrAttr { ip, port })
}

/// Encode a SocketAddrAttr as an XOR-MAPPED-ADDRESS attribute value
/// (without the 4-byte TLV header — callers prepend that).
///
/// This is the inverse of `decode_xor_mapped_address`, used by the STUN
/// server to build its Binding response.
pub fn encode_xor_mapped_address(addr: &SocketAddrAttr, transaction_id: &[u8; 12]) -> Vec<u8> {
    use crate::stun::parser::MAGIC_COOKIE;

    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    let xor_port = addr.port ^ ((MAGIC_COOKIE >> 16) as u16);

    let mut out = Vec::new();
    out.push(0); // reserved byte

    match addr.ip {
        IpAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&xor_port.to_be_bytes());
            let octets = v4.octets();
            for i in 0..4 {
                out.push(octets[i] ^ cookie_bytes[i]);
            }
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&xor_port.to_be_bytes());
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&cookie_bytes);
            mask[4..].copy_from_slice(transaction_id);
            let octets = v6.octets();
            for i in 0..16 {
                out.push(octets[i] ^ mask[i]);
            }
        }
    }

    out
}
