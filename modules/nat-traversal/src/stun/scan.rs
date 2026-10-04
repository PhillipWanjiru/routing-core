//! Locating one attribute inside an already-encoded STUN message.
//!
//! `decode_attributes` answers "what do the attributes mean"; this answers
//! "where, byte-for-byte, does this attribute sit" — which MESSAGE-INTEGRITY
//! and FINGERPRINT both need, since each is computed over the message bytes
//! *preceding* it, so verifying one requires knowing its exact offset.

use super::parser::HEADER_LEN;

/// Byte offsets of one attribute within a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrLoc {
    /// Offset of the attribute's 4-byte TLV header.
    pub tlv_start: usize,
    /// Offset of the first byte of the attribute's value.
    pub value_start: usize,
    /// Value length as declared in the TLV header (before padding).
    pub value_len: usize,
}

/// Find the first attribute of `attr_type`, walking the attribute section
/// the header declares (clamped to the buffer). Returns `None` if the
/// attribute is absent, or if the walk hits a truncated attribute before
/// finding it — a truncated attribute makes everything after it
/// untrustworthy, so the honest answer is "not found", not a guess.
pub fn locate_attribute(msg: &[u8], attr_type: u16) -> Option<AttrLoc> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let declared = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = (HEADER_LEN + declared).min(msg.len());

    let mut off = HEADER_LEN;
    while off + 4 <= end {
        let t = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let l = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
        let value_start = off + 4;
        if value_start + l > end {
            return None;
        }
        if t == attr_type {
            return Some(AttrLoc { tlv_start: off, value_start, value_len: l });
        }
        off = value_start + ((l + 3) & !3);
    }
    None
}
