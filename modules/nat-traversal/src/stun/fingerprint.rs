//! STUN FINGERPRINT (RFC 5389 §15.5) and the CRC-32 underneath it.
//!
//! FINGERPRINT lets a receiver sharing one port between STUN and other
//! protocols (here: ICE checks alongside RTP) cheaply confirm "this really
//! is STUN" before spending effort on it. It is a checksum, **not** a
//! security mechanism — an attacker who alters a message can trivially
//! recompute it. That is exactly why ICE also requires MESSAGE-INTEGRITY,
//! and why the tests include a case where the fingerprint is recomputed
//! over tampered content and verification must still fail (at integrity).
//!
//! Verified against Python's `zlib.crc32` (the independent oracle) for seven
//! inputs including the standard "123456789" check value 0xCBF43926, and
//! against fully-built messages whose fingerprints were derived independently.
//!
//! The XOR constant 0x5354554e is ASCII "STUN"; like every other protocol
//! constant in this project it is recalled rather than derived — confirm
//! against RFC 5389 before real-world interop.

use super::{attributes::ATTR_FINGERPRINT, parser::HEADER_LEN, scan::locate_attribute};

/// RFC 5389 §15.5: the CRC-32 is XORed with this before being sent.
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

const FINGERPRINT_TLV_LEN: usize = 8; // 4-byte TLV header + 4-byte value

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

/// CRC-32 (IEEE 802.3 / zlib): reflected polynomial 0xEDB88320, initial
/// value and final XOR both 0xFFFFFFFF.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Append a FINGERPRINT attribute to a complete STUN message.
///
/// Per RFC 5389 §15.5 the CRC covers the message *including a header length
/// that already counts the FINGERPRINT attribute itself* — so the length
/// field is updated first, then the CRC taken, then the attribute appended.
/// If MESSAGE-INTEGRITY is also present it must already have been appended:
/// FINGERPRINT is always the last attribute.
pub fn append_fingerprint(msg: &mut Vec<u8>) {
    let new_len = (msg.len() - HEADER_LEN + FINGERPRINT_TLV_LEN) as u16;
    msg[2..4].copy_from_slice(&new_len.to_be_bytes());
    let value = crc32(msg) ^ FINGERPRINT_XOR;
    msg.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    msg.extend_from_slice(&4u16.to_be_bytes());
    msg.extend_from_slice(&value.to_be_bytes());
}

/// Verify a received message's FINGERPRINT.
///
/// Returns `false` (never panics) if the attribute is missing, malformed,
/// not the final attribute, or if the datagram is not exactly the length
/// its header declares. Because FINGERPRINT is last, the header length as
/// received already includes it, so the CRC is taken over the received
/// bytes up to the attribute unmodified.
pub fn verify_fingerprint(full: &[u8]) -> bool {
    let Some(loc) = locate_attribute(full, ATTR_FINGERPRINT) else {
        return false;
    };
    if loc.value_len != 4 {
        return false;
    }
    let declared = u16::from_be_bytes([full[2], full[3]]) as usize;
    if loc.value_start + 4 != HEADER_LEN + declared || full.len() != HEADER_LEN + declared {
        return false;
    }
    let expected = crc32(&full[..loc.tlv_start]) ^ FINGERPRINT_XOR;
    let got = u32::from_be_bytes([
        full[loc.value_start],
        full[loc.value_start + 1],
        full[loc.value_start + 2],
        full[loc.value_start + 3],
    ]);
    expected == got
}
