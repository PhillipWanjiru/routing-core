//! SRTP key management — SDES key extraction from SDP.
//!
//! SDES (Security DEScriptions) is the simplest SRTP key exchange:
//! the master key and salt are carried in an SDP `a=crypto` attribute.
//!
//! RFC 4568 §6.1 format:
//!   a=crypto:<tag> <crypto-suite> <key-params> [<session-params>]
//!
//! Example:
//!   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zLWhlbGxvd29ybGQBAAAA
//!
//! The `inline:` key parameter is base64(master_key || master_salt):
//!   - AES_CM_128_HMAC_SHA1_80: 16 bytes key + 14 bytes salt = 30 bytes
//!
//! DTLS-SRTP (for WebRTC) derives the master key differently — from the
//! TLS Keying Material Exporter (RFC 5705). That path is in webrtc/dtls.rs.
//! This module handles SDES only.

/// A parsed SRTP master key and salt from an SDP `a=crypto` line.
#[derive(Debug, Clone)]
pub struct SrtpKeyMaterial {
    /// Crypto-suite identifier, e.g. "AES_CM_128_HMAC_SHA1_80".
    pub suite:       String,
    /// Master key (16 bytes for AES-128).
    pub master_key:  Vec<u8>,
    /// Master salt (14 bytes for AES_CM_128_HMAC_SHA1_80).
    pub master_salt: Vec<u8>,
}

/// Parse an `a=crypto` attribute value and extract the key material.
///
/// Input is the value after `a=crypto:`, e.g.:
///   `1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zLWhlbGxvd29ybGQBAAAA`
pub fn parse_sdes_crypto(attr_value: &str) -> Option<SrtpKeyMaterial> {
    let parts: Vec<&str> = attr_value.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    // parts[0] = tag, parts[1] = suite, parts[2] = key-params
    let suite      = parts[1].to_owned();
    let key_params = parts[2];

    // Strip the "inline:" prefix.
    let b64 = key_params.strip_prefix("inline:")?;
    // Strip any trailing key lifetime ("|2^48|...") before decoding.
    let b64 = b64.split('|').next().unwrap_or(b64).trim();

    let raw = base64_decode(b64)?;

    // Determine key and salt lengths from the suite name.
    let (key_len, salt_len) = key_salt_lengths(&suite)?;
    if raw.len() < key_len + salt_len {
        return None;
    }

    Some(SrtpKeyMaterial {
        suite,
        master_key:  raw[..key_len].to_vec(),
        master_salt: raw[key_len..key_len + salt_len].to_vec(),
    })
}

/// Key and salt lengths in bytes for known SRTP cipher suites.
fn key_salt_lengths(suite: &str) -> Option<(usize, usize)> {
    match suite {
        "AES_CM_128_HMAC_SHA1_80" | "AES_CM_128_HMAC_SHA1_32" => Some((16, 14)),
        "AES_256_CM_HMAC_SHA1_80" | "AES_256_CM_HMAC_SHA1_32" => Some((32, 14)),
        _ => None,
    }
}

// ─── RFC 3711 §4.3.1 key derivation ────────────────────────────
//
// The master key and salt are not used directly as the session key.
// We derive three per-session values from them using a PRF:
//   - session encryption key   (k_e)
//   - session message-auth key (k_a)
//   - session salting key      (k_s)
//
// For AES-CM the PRF is AES-CM itself applied with a label and index:
//   PRF(master_key, x) = AES-CM(master_key, master_salt XOR label XOR index)
//
// Labels (RFC 3711 §4.3.1):
//   k_e: 0x00 (cipher key)
//   k_a: 0x01 (message auth key)
//   k_s: 0x02 (salting key)

/// Derived session keys for one SRTP stream.
#[derive(Debug, Clone)]
pub struct SrtpSessionKeys {
    /// Session encryption key (AES key).
    pub k_e: Vec<u8>,
    /// Session salting key.
    pub k_s: Vec<u8>,
    /// Session message-authentication key (HMAC key).
    pub k_a: Vec<u8>,
}

/// Derive SRTP session keys from master key material.
///
/// `index` is the SRTP packet index (use 0 for initial derivation).
/// Returns `None` for unsupported suite lengths.
pub fn derive_session_keys(km: &SrtpKeyMaterial, index: u64) -> Option<SrtpSessionKeys> {
    let (key_len, salt_len) = key_salt_lengths(&km.suite)?;

    // AES-CM PRF: key stream at (master_salt XOR label_iv), where
    // label_iv = label << 48 (labels are 8-bit values shifted to bits [55:48]).
    let k_e = aes_cm_prf(&km.master_key, &km.master_salt, 0x00, index, key_len);
    let k_s = aes_cm_prf(&km.master_key, &km.master_salt, 0x02, index, salt_len);
    // HMAC-SHA1-80 needs 20 bytes for the authentication key.
    let k_a = aes_cm_prf(&km.master_key, &km.master_salt, 0x01, index, 20);

    Some(SrtpSessionKeys { k_e, k_s, k_a })
}

/// AES Counter Mode Pseudo-Random Function (RFC 3711 §4.3.1).
///
/// Generates `length` bytes of pseudo-random key stream.
/// IV = (master_salt XOR (label << 48) XOR (index << 16)) as a 128-bit value.
fn aes_cm_prf(
    master_key:  &[u8],
    master_salt: &[u8],
    label:       u8,
    index:       u64,
    length:      usize,
) -> Vec<u8> {
    // Build the 128-bit IV.
    let mut iv = [0u8; 16];

    // Embed master_salt in iv[2..16] (salt is 14 bytes, starts at byte 2).
    let salt_len = master_salt.len().min(14);
    iv[2..2 + salt_len].copy_from_slice(&master_salt[..salt_len]);

    // XOR label into byte 7 (label occupies bits [55:48] = bytes [6:7]).
    iv[7] ^= label;

    // XOR packet index into bytes [10:14] (bits [47:16]).
    let index_bytes = index.to_be_bytes(); // 8 bytes
    // Use only the low 6 bytes of the index (48-bit index).
    for i in 0..6 {
        iv[10 + i] ^= index_bytes[2 + i];
    }

    // Generate key stream using AES in counter mode.
    // Phase 3: use our pure-Rust AES-128-CTR implementation.
    aes128_ctr_keystream(master_key, &iv, length)
}

// ─── AES-128-CTR keystream (pure Rust) ─────────────────────────
//
// Full AES-128 implementation from FIPS 197. Used here for key derivation
// only — not for the actual SRTP media encryption (that path uses the
// session keys derived above, and in Phase 4 is handed to the ring crate).
//
// This implementation is correct but not constant-time. Phase 4's auth-pki
// integration replaces it with ring::aead for the media path.

fn aes128_ctr_keystream(key: &[u8], iv: &[u8; 16], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut counter = u128::from_be_bytes(*iv);

    while out.len() < length {
        let block = aes128_encrypt_block(key, &counter.to_be_bytes());
        let remaining = length - out.len();
        out.extend_from_slice(&block[..remaining.min(16)]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// AES-128 block encryption (FIPS 197).
fn aes128_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let rk = aes128_key_expand(key);
    let mut state = *block;
    add_round_key(&mut state, &rk[0]);
    for round in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &rk[round]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &rk[10]);
    state
}

// ─── AES primitives ────────────────────────────────────────────

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const RCON: [u8; 11] = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

fn aes128_key_expand(key: &[u8]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0][..].copy_from_slice(&key[..16]);
    for i in 1..=10 {
        let prev = rk[i-1];
        // RotWord + SubWord + Rcon on the last column of the previous round key.
        let w = [
            SBOX[prev[13] as usize] ^ RCON[i],
            SBOX[prev[14] as usize],
            SBOX[prev[15] as usize],
            SBOX[prev[12] as usize],
        ];
        for j in 0..4 {
            // Read the previous column of rk[i] before mutably borrowing it.
            let (c0, c1, c2, c3) = if j == 0 {
                (w[0], w[1], w[2], w[3])
            } else {
                let base = (j - 1) * 4;
                (rk[i][base], rk[i][base+1], rk[i][base+2], rk[i][base+3])
            };
            rk[i][j*4]   = prev[j*4]   ^ c0;
            rk[i][j*4+1] = prev[j*4+1] ^ c1;
            rk[i][j*4+2] = prev[j*4+2] ^ c2;
            rk[i][j*4+3] = prev[j*4+3] ^ c3;
        }
    }
    rk
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 { state[i] ^= rk[i]; }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = SBOX[*b as usize]; }
}

fn shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift left 1
    let tmp = state[1];
    state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    // Row 2: shift left 2
    state.swap(2, 10); state.swap(6, 14);
    // Row 3: shift left 3 (= shift right 1)
    let tmp = state[15];
    state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
}

fn xtime(b: u8) -> u8 {
    if b & 0x80 != 0 { (b << 1) ^ 0x1b } else { b << 1 }
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i]; let s1 = state[i+1];
        let s2 = state[i+2]; let s3 = state[i+3];
        state[i]   = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
        state[i+1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
        state[i+2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
        state[i+3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
    }
}

// ─── Base64 decoder ────────────────────────────────────────────
//
// RFC 4648 base64. No external dependency — base64 crates vary in API
// across versions and we want no new dependency for Phase 3.

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r')
        .map(base64_char_to_val)
        .collect::<Option<Vec<_>>>()?;

    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    for chunk in bytes.chunks(4) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let b3 = chunk.get(3).copied().unwrap_or(0);
        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() >= 3 { out.push((b1 << 4) | (b2 >> 2)); }
        if chunk.len() >= 4 { out.push((b2 << 6) | b3); }
    }
    Some(out)
}

fn base64_char_to_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}
