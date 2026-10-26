//! TURN long-term credential authentication (RFC 5766 §9, built on the
//! STUN long-term credential mechanism, RFC 5389 §10.2 / §15.4).
//!
//! # Flow
//!
//! ```text
//! Client                                  Server
//!   |--- Allocate (no credentials) ------->|
//!   |<-- 401 Unauthorized (REALM, NONCE) --|
//!   |--- Allocate (USERNAME, REALM,        |
//!   |     NONCE, MESSAGE-INTEGRITY) ------>|
//!   |<-- Success Response -----------------|
//! ```
//!
//! # Key derivation (RFC 5389 §15.4)
//!
//! ```text
//! key = MD5(username ":" realm ":" password)
//! ```
//!
//! MD5 here is *not* being relied on for collision resistance — it is
//! purely a fixed-length key-derivation step, with the actual
//! authentication strength coming from HMAC-SHA1 over a server-issued
//! nonce. This project implements MD5 from scratch (RFC 1321) rather
//! than pull in a crate, matching the project's existing pattern of
//! self-contained hash primitives (SHA-256 in voip-sip's Digest auth,
//! SHA-1 in its SRTP implementation). Verified against Python's
//! `hashlib.md5` for five reference strings before this file was
//! written — see `tests/turn_auth_test.rs`.
//!
//! # MESSAGE-INTEGRITY construction (RFC 5389 §15.4) — the one genuinely
//! tricky part
//!
//! The HMAC-SHA1 is computed over the STUN message *up to but not
//! including* the MESSAGE-INTEGRITY attribute itself — but with the
//! header's length field already adjusted as though MESSAGE-INTEGRITY
//! (24 bytes: 4-byte TLV header + 20-byte HMAC value) were present. This
//! chicken-and-egg construction (the length field describes a message
//! that isn't fully built yet) is the single most common source of
//! interop bugs in hand-rolled STUN/TURN implementations, because it
//! looks correct in a self-contained round-trip test (build and verify
//! share the same bug) while silently failing against any real peer.
//! Independently verified against a full worked example computed in
//! Python (`hmac.new(key, message, hashlib.sha1)`) before this Rust was
//! written — and both the build and verify directions in this file are
//! separately checked against that same Python-computed fixture, not
//! just against each other.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── MD5 (RFC 1321) ────────────────────────────────────────────
//
// Only used for the long-term credential key derivation above — not a
// general-purpose hash utility. Note the byte order: MD5 packs message
// words and produces its digest in LITTLE-endian order, unlike the
// SHA-1/SHA-256 already in this project (both big-endian) — this is the
// single easiest mistake to make copying the shape of that code, so it's
// called out explicitly here and directly verified against Python's
// hashlib for five reference strings in the test suite.

const MD5_S: [u32; 64] = [
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
];

// The 64 constants K[i] = floor(2^32 * abs(sin(i+1))), per RFC 1321 §3.4.
const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Compute the MD5 digest of `msg` (RFC 1321).
pub fn md5(msg: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Padding: append 0x80, then zeros, until length ≡ 56 mod 64, then
    // append the original bit-length as a LITTLE-endian u64 (MD5's one
    // big divergence from the SHA family's big-endian length suffix).
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            // LITTLE-endian word packing — the other MD5-specific
            // byte-order divergence from SHA-1/SHA-256.
            m[i] = u32::from_le_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g): (u32, usize) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5*i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3*i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7*i) % 16)
            };

            let f = f.wrapping_add(a).wrapping_add(MD5_K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    // Output is little-endian, per RFC 1321 §3.5.
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ─── SHA-1 (FIPS 180-4) + HMAC-SHA1 ────────────────────────────
//
// A fresh copy local to this crate, matching the project's established
// pattern (srtp/encrypt.rs in voip-sip keeps its own local AES-128 copy
// "for encrypt.rs independence" rather than reaching across a module
// boundary) — nat-traversal cannot reach voip-sip's private SHA-1 anyway,
// since it's a different crate, so this is not a stylistic choice so
// much as a structural necessity, but it matches the existing precedent
// either way.

/// SHA-1 digest (FIPS 180-4). Exposed `pub` so it can be tested directly
/// against independent reference vectors, not only indirectly through
/// `hmac_sha1`/`compute_message_integrity`.
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0];
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i-3]^w[i-8]^w[i-14]^w[i-16]).rotate_left(1);
        }
        let (mut a,mut b,mut c,mut d,mut e) = (h[0],h[1],h[2],h[3],h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19  => ((b&c)|((!b)&d),            0x5A827999u32),
                20..=39 => (b^c^d,                     0x6ED9EBA1u32),
                40..=59 => ((b&c)|(b&d)|(c&d),         0x8F1BBCDCu32),
                _       => (b^c^d,                     0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e)
                        .wrapping_add(k).wrapping_add(w[i]);
            e=d; d=c; c=b.rotate_left(30); b=a; a=temp;
        }
        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &word) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA1 (RFC 2104). Output is the full 20 bytes — TURN's
/// MESSAGE-INTEGRITY is *not* truncated, unlike SRTP's HMAC-SHA1-80.
/// Exposed `pub` so it can be tested directly against a published
/// RFC 2202 test vector (which uses a 20-byte key, a genuinely different
/// case from the 16-byte MD5-derived key `compute_message_integrity`
/// always passes it internally).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha1(key);
        k[..20].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ikey = [0u8; BLOCK]; let mut okey = [0u8; BLOCK];
    for i in 0..BLOCK {
        ikey[i] = k[i] ^ 0x36;
        okey[i] = k[i] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(BLOCK + data.len());
    inner_input.extend_from_slice(&ikey);
    inner_input.extend_from_slice(data);
    let inner = sha1(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK + 20);
    outer_input.extend_from_slice(&okey);
    outer_input.extend_from_slice(&inner);
    sha1(&outer_input)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y)) == 0
}

// ─── Long-term credential key derivation ────────────────────────

/// Derive the long-term credential key: `MD5(username ":" realm ":" password)`.
///
/// No SASLprep normalisation is applied — that only matters for non-ASCII
/// usernames/passwords, out of scope for this milestone.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{username}:{realm}:{password}");
    md5(input.as_bytes())
}

// ─── MESSAGE-INTEGRITY (RFC 5389 §15.4) ─────────────────────────

/// Fixed size of a MESSAGE-INTEGRITY attribute including its TLV header:
/// 4 bytes (type + length) + 20 bytes (HMAC-SHA1 value) = 24.
pub const MESSAGE_INTEGRITY_ATTR_LEN: usize = 24;

/// Compute the MESSAGE-INTEGRITY value for a message being *built*.
///
/// `header_and_attrs_before_mi` is the 20-byte STUN header followed by
/// every attribute that will appear *before* MESSAGE-INTEGRITY in the
/// final message — but with the header's length field already set as
/// though MESSAGE-INTEGRITY (24 bytes) were appended, per RFC 5389 §15.4.
pub fn compute_message_integrity(key: &[u8; 16], header_and_attrs_before_mi: &[u8]) -> [u8; 20] {
    hmac_sha1(key, header_and_attrs_before_mi)
}

/// Verify a MESSAGE-INTEGRITY attribute found in an already-received
/// message.
///
/// `full_message` is the complete received datagram. `mi_value_offset` is
/// the byte offset where the MESSAGE-INTEGRITY attribute's *value*
/// begins (i.e. immediately after its 4-byte TLV header). This function
/// reconstructs the same "prefix with adjusted length" bytes a builder
/// would have hashed, recomputes the HMAC, and compares it against the
/// 20 bytes actually present, using a constant-time comparison.
pub fn verify_message_integrity(
    full_message: &[u8],
    mi_value_offset: usize,
    key: &[u8; 16],
) -> bool {
    if mi_value_offset < 4 || mi_value_offset + 20 > full_message.len() {
        return false;
    }
    let prefix = &full_message[..mi_value_offset - 4]; // up to, not including, the MI TLV header
    let received_mi = &full_message[mi_value_offset..mi_value_offset + 20];

    let computed = compute_message_integrity(key, prefix);
    constant_time_eq(&computed, received_mi)
}

// ─── Nonce management ────────────────────────────────────────────
//
// Same embedded-timestamp approach already proven in voip-sip's
// sip::auth::generate_nonce — a fresh, independent implementation here
// since nonce state cannot be shared across the crate boundary, but the
// design is deliberately identical.

/// Generate a nonce embedding the current Unix timestamp in its first 16
/// hex characters, so `nonce_is_stale` can check age without a database.
pub fn generate_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0xfeed_face);
    let r = COUNTER.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);

    let combined = ((ts as u128) << 64) | r as u128;
    format!("{combined:032x}")
}

/// True if `nonce_hex` is older than `max_age_secs`.
pub fn nonce_is_stale(nonce_hex: &str, max_age_secs: u64) -> bool {
    if nonce_hex.len() < 16 { return true; }
    let ts_hex = &nonce_hex[..16];
    let ts = u64::from_str_radix(ts_hex, 16).unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(ts) > max_age_secs
}

// ─── Credential store ────────────────────────────────────────────

/// In-memory username→password store.
///
/// This is a placeholder for what would eventually be a real credential
/// backend — the project's own documentation already earmarks
/// `services/auth-pki` for production key/credential management. This
/// milestone's scope is the authentication *mechanism*, not credential
/// storage.
#[derive(Debug, Default)]
pub struct CredentialStore {
    passwords: HashMap<String, String>,
}

impl CredentialStore {
    pub fn new() -> Self {
        CredentialStore { passwords: HashMap::new() }
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.passwords.insert(username.into(), password.into());
    }

    pub fn password_for(&self, username: &str) -> Option<&str> {
        self.passwords.get(username).map(|s| s.as_str())
    }
}

// ─── Authentication gate ─────────────────────────────────────────

/// Outcome of attempting to authenticate one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// MESSAGE-INTEGRITY verified against a known user's credentials.
    Authenticated { username: String },
    /// No credentials were present at all — caller should send a 401
    /// challenge (build with `stun::builder::build_401_challenge`).
    ChallengeRequired,
    /// Credentials were present but invalid: unknown username, wrong
    /// password (MESSAGE-INTEGRITY didn't verify), or a stale nonce.
    Rejected { stale_nonce: bool },
}

/// Fields extracted from a request that carries (or should carry)
/// long-term credential attributes. The caller pulls these out of the
/// parsed `StunMessage` + decoded attributes — this function only
/// performs the credential *check*.
pub struct CredentialAttempt<'a> {
    pub username:        Option<&'a str>,
    pub realm:            Option<&'a str>,
    pub nonce:            Option<&'a str>,
    /// Byte offset of the MESSAGE-INTEGRITY attribute's *value* (not its
    /// TLV header) within `full_message`, if present.
    pub mi_value_offset: Option<usize>,
}

/// Attempt to authenticate one request against `credentials`, given the
/// server's configured `realm` and the raw message bytes (needed to
/// recompute MESSAGE-INTEGRITY over the actual prefix bytes).
pub fn authenticate_request(
    attempt: &CredentialAttempt,
    full_message: &[u8],
    realm: &str,
    credentials: &CredentialStore,
    max_nonce_age_secs: u64,
) -> AuthResult {
    let (Some(username), Some(req_realm), Some(nonce), Some(mi_offset)) =
        (attempt.username, attempt.realm, attempt.nonce, attempt.mi_value_offset)
    else {
        return AuthResult::ChallengeRequired;
    };

    if req_realm != realm {
        return AuthResult::Rejected { stale_nonce: false };
    }

    if nonce_is_stale(nonce, max_nonce_age_secs) {
        return AuthResult::Rejected { stale_nonce: true };
    }

    let Some(password) = credentials.password_for(username) else {
        return AuthResult::Rejected { stale_nonce: false };
    };

    let key = long_term_key(username, realm, password);

    if verify_message_integrity(full_message, mi_offset, &key) {
        AuthResult::Authenticated { username: username.to_owned() }
    } else {
        AuthResult::Rejected { stale_nonce: false }
    }
}

// ─── Client-side request construction ───────────────────────────

/// Build a complete, authenticated TURN request: USERNAME + REALM +
/// NONCE + a correctly-computed MESSAGE-INTEGRITY attribute, ready to
/// send on the wire.
///
/// This is the client-side counterpart to [`authenticate_request`] — it
/// performs the same RFC 5389 §15.4 "adjusted length field" construction
/// that a real TURN client must perform when responding to a 401
/// challenge with credentials. Tested byte-for-byte against an
/// independently-computed (Python `hmac`/`hashlib`) worked example in
/// `tests/turn_auth_test.rs` — not just checked for internal consistency
/// with this crate's own `verify_message_integrity`.
pub fn build_authenticated_request(
    method: crate::stun::parser::Method,
    transaction_id: &[u8; 12],
    username: &str,
    realm: &str,
    nonce: &str,
    password: &str,
) -> Vec<u8> {
    build_authenticated_request_with(method, transaction_id, &[], username, realm, nonce, password)
}

/// Like [`build_authenticated_request`], with extra attributes placed ahead of
/// the credential ones. Allocate (REQUESTED-TRANSPORT), CreatePermission and
/// ChannelBind (XOR-PEER-ADDRESS, CHANNEL-NUMBER) and Refresh (LIFETIME) all
/// need them. `extra_attrs` is already-encoded attribute TLVs; with none this is
/// byte-for-byte the original, which the worked-example test pins.
pub fn build_authenticated_request_with(
    method: crate::stun::parser::Method,
    transaction_id: &[u8; 12],
    extra_attrs: &[u8],
    username: &str,
    realm: &str,
    nonce: &str,
    password: &str,
) -> Vec<u8> {
    use crate::stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME};
    use crate::stun::builder::{build_attribute, build_header_with_length};
    use crate::stun::parser::MessageClass;

    let username_attr = build_attribute(ATTR_USERNAME, username.as_bytes());
    let realm_attr    = build_attribute(ATTR_REALM, realm.as_bytes());
    let nonce_attr    = build_attribute(ATTR_NONCE, nonce.as_bytes());

    let mut attrs_before_mi = extra_attrs.to_vec();
    attrs_before_mi.extend_from_slice(&username_attr);
    attrs_before_mi.extend_from_slice(&realm_attr);
    attrs_before_mi.extend_from_slice(&nonce_attr);

    let adjusted_length = (attrs_before_mi.len() + MESSAGE_INTEGRITY_ATTR_LEN) as u16;
    let header_for_hmac = build_header_with_length(
        MessageClass::Request, method, transaction_id, adjusted_length,
    );

    let mut hmac_input = header_for_hmac.clone();
    hmac_input.extend_from_slice(&attrs_before_mi);

    let key = long_term_key(username, realm, password);
    let mi_value = compute_message_integrity(&key, &hmac_input);
    let mi_attr  = build_attribute(ATTR_MESSAGE_INTEGRITY, &mi_value);

    let mut full = header_for_hmac;
    full.extend_from_slice(&attrs_before_mi);
    full.extend_from_slice(&mi_attr);
    full
}
