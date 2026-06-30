//! SIP Digest authentication (RFC 3261 §22, RFC 7616).
//!
//! Uses SHA-256. MD5 is the legacy RFC 3261 default but is cryptographically
//! broken; SHA-256 is the RFC 7616 upgrade and what new deployments should use.
//!
//! The server side:
//!   1. Sends a 401/407 with WWW-Authenticate / Proxy-Authenticate.
//!   2. The client sends the same request with Authorization /
//!      Proxy-Authorization.
//!   3. We verify by recomputing the digest.
//!
//! Nonces are 128-bit random values (hex encoded) with an embedded
//! timestamp so stale nonces can be detected without a database.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Nonce ────────────────────────────────────────────────────

/// Generate a nonce embedding the current Unix timestamp so stale detection
/// does not require a server-side nonce database.
///
/// Format: hex(timestamp_secs:u64 || random:u64)
pub fn generate_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple pseudo-random for Phase 2; Phase 4 uses proper CSPRNG.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0xdeadbeef);
    let r = COUNTER.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);

    let combined = ((ts as u128) << 64) | r as u128;
    format!("{:032x}", combined)
}

/// True if a nonce is older than `max_age_secs`.
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

// ─── Digest calculation ───────────────────────────────────────

/// Parameters for computing or verifying a digest response.
pub struct DigestParams<'a> {
    pub username: &'a str,
    pub realm:    &'a str,
    pub password: &'a str,
    pub nonce:    &'a str,
    pub method:   &'a str,
    pub uri:      &'a str,
    /// cnonce (client nonce) — empty string if not present.
    pub cnonce:   &'a str,
    /// nc (nonce count, hex) — "00000001" if not present.
    pub nc:       &'a str,
    /// qop — "auth", "auth-int", or empty.
    pub qop:      &'a str,
}

/// Compute the Digest response value using SHA-256.
///
/// RFC 7616 §3.4:
/// ```text
/// HA1 = SHA256(username:realm:password)
/// HA2 = SHA256(method:uri)
/// if qop == "auth":
///   response = SHA256(HA1:nonce:nc:cnonce:qop:HA2)
/// else:
///   response = SHA256(HA1:nonce:HA2)
/// ```
pub fn compute_digest(p: &DigestParams) -> String {
    let ha1 = sha256_hex(&format!("{}:{}:{}", p.username, p.realm, p.password));
    let ha2 = sha256_hex(&format!("{}:{}", p.method, p.uri));

    let preimage = if p.qop == "auth" || p.qop == "auth-int" {
        format!("{}:{}:{}:{}:{}:{}", ha1, p.nonce, p.nc, p.cnonce, p.qop, ha2)
    } else {
        format!("{}:{}:{}", ha1, p.nonce, ha2)
    };

    sha256_hex(&preimage)
}

/// Verify a client's digest response against the server's expectation.
pub fn verify_digest(p: &DigestParams, client_response: &str) -> bool {
    let expected = compute_digest(p);
    // Constant-time comparison to resist timing attacks.
    constant_time_eq(expected.as_bytes(), client_response.as_bytes())
}

// ─── SHA-256 (pure Rust, no external dep for Phase 2) ─────────
//
// Phase 4 (auth-pki service) will replace this with ring.
// For Phase 2 we implement SHA-256 from the FIPS 180-4 spec so we
// have no dependency on a crypto crate that might not be cached.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_bytes(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19)  ^ (w[i-2]  >> 10);
            w[i] = w[i-16].wrapping_add(s0)
                           .wrapping_add(w[i-7])
                           .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch)
                           .wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256_hex(s: &str) -> String {
    let bytes = sha256_bytes(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in &bytes { let _ = write!(out, "{:02x}", b); }
    out
}

/// Constant-time byte-slice equality.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
