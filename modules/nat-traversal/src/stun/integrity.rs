//! MESSAGE-INTEGRITY for any key length, tolerant of a trailing FINGERPRINT.
//!
//! `turn::auth` already implements MESSAGE-INTEGRITY for the TURN
//! *long-term* credential mechanism, with a fixed 16-byte MD5-derived key.
//! ICE uses the *short-term* mechanism (RFC 5389 §10.1): the key is simply
//! the ICE password, of arbitrary length — and ICE messages also carry a
//! trailing FINGERPRINT. Both differences matter:
//!
//! - **Key length:** this module takes `&[u8]`, not `&[u8; 16]`.
//! - **Trailing FINGERPRINT:** MESSAGE-INTEGRITY is computed over the message
//!   up to itself with the header length set to end at MESSAGE-INTEGRITY. In
//!   a message that also has a FINGERPRINT, the length field *as received*
//!   counts the FINGERPRINT too (8 more bytes) — so a verifier that hashes
//!   the received prefix unchanged, as `turn::auth::verify_message_integrity`
//!   does, would reject every valid ICE message. This verifier rewrites the
//!   length field to end at MESSAGE-INTEGRITY before hashing. For a message
//!   with no trailing attributes that rewrite is a no-op, so this function
//!   is a strict superset of the TURN one — a test proves it by verifying a
//!   TURN long-term message with it.
//!
//! No SASLprep is applied to the password; ICE passwords are restricted to
//! ASCII characters SASLprep leaves untouched.
//!
//! The HMAC-SHA1 primitive currently lives in `turn::auth` (where it was
//! first needed). Reaching into `turn` from `stun` is a mild layering
//! inversion; hoisting the hash primitives into a shared `crypto` module is
//! a reasonable future cleanup, deliberately not done here to avoid touching
//! already-verified TURN code.

use super::{
    attributes::ATTR_MESSAGE_INTEGRITY, parser::HEADER_LEN, scan::locate_attribute,
};
use crate::turn::hmac_sha1;

const MI_VALUE_LEN: usize = 20;
const MI_TLV_LEN: usize = 24; // 4-byte TLV header + 20-byte HMAC-SHA1

/// Append MESSAGE-INTEGRITY to a complete STUN message, keyed by `key`.
///
/// The length field is first set to cover the not-yet-appended attribute
/// (RFC 5389 §15.4), the HMAC taken over that, then the attribute appended.
/// Must be called *before* `append_fingerprint`.
pub fn append_integrity(msg: &mut Vec<u8>, key: &[u8]) {
    let new_len = (msg.len() - HEADER_LEN + MI_TLV_LEN) as u16;
    msg[2..4].copy_from_slice(&new_len.to_be_bytes());
    let mi = hmac_sha1(key, msg);
    msg.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&(MI_VALUE_LEN as u16).to_be_bytes());
    msg.extend_from_slice(&mi);
}

/// Verify a received message's MESSAGE-INTEGRITY against `key`.
///
/// Returns `false` (never panics) if the attribute is absent or malformed or
/// the HMAC differs. The comparison is constant-time.
pub fn verify_integrity(full_message: &[u8], key: &[u8]) -> bool {
    let Some(loc) = locate_attribute(full_message, ATTR_MESSAGE_INTEGRITY) else {
        return false;
    };
    if loc.value_len != MI_VALUE_LEN || loc.value_start + MI_VALUE_LEN > full_message.len() {
        return false;
    }

    // Length through the end of MESSAGE-INTEGRITY, as the sender hashed it:
    // end_of_MI = tlv_start + 24 = value_start + 20, minus the 20-byte header
    // = value_start.
    let Ok(adjusted) = u16::try_from(loc.value_start) else {
        return false;
    };
    let mut prefix = full_message[..loc.tlv_start].to_vec();
    prefix[2..4].copy_from_slice(&adjusted.to_be_bytes());

    let expected = hmac_sha1(key, &prefix);
    constant_time_eq(&expected, &full_message[loc.value_start..loc.value_start + MI_VALUE_LEN])
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y)) == 0
}
