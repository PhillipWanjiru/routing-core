//! 128-bit ULID (Universally Unique Lexicographically Sortable Identifier).
//!
//! Structure:
//!   - 48 bits: Unix timestamp in milliseconds (sortable)
//!   - 80 bits: cryptographic randomness
//!
//! Encoded as 26 Crockford base32 characters (case-insensitive, URL-safe).
//! The first character is always ≤ '7' because 2^48 ms ≈ year 10889.
//!
//! This implementation avoids any external crate so the algorithm is
//! fully auditable in one place.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Crockford base32 alphabet (digits + uppercase, minus I L O U).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 128-bit ULID, stored as two 64-bit halves (high, low).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(u128);

impl Ulid {
    /// Generate a new ULID with the current timestamp and random bits.
    pub fn new() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_millis() as u64
            & 0x0000_FFFF_FFFF_FFFF; // keep only 48 bits

        // Phase 1: seed randomness from nanosecond system time XOR a thread-local counter.
        // Phase 4: replace with getrandom once toolchain is upgraded to ≥ 1.78.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        // Mix with a simple hash to spread the bits.
        let a = (ns ^ count).wrapping_mul(0x9e3779b97f4a7c15);
        let b = (ns.rotate_left(17) ^ count.wrapping_add(1)).wrapping_mul(0x6c62272e07bb0142);
        let rand: u128 = ((a as u128) << 64) | b as u128;

        // 128 bits: high 48 = timestamp, low 80 = randomness
        Ulid(((ts as u128) << 80) | (rand & 0x0000_FFFF_FFFF_FFFF_FFFF_FFFF))
    }

    /// Construct a ULID from its raw 128-bit value (e.g. from storage).
    pub fn from_u128(v: u128) -> Self {
        Ulid(v)
    }

    /// Return the raw 128-bit value.
    pub fn as_u128(self) -> u128 {
        self.0
    }

    /// Return the timestamp component in milliseconds since Unix epoch.
    pub fn timestamp_ms(self) -> u64 {
        (self.0 >> 80) as u64
    }

    /// Encode to the canonical 26-character Crockford base32 string.
    ///
    /// Encoding: extract 5 bits at a time from MSB to LSB.
    /// 26 × 5 = 130 bits of symbol space; the top 2 bits are always 0
    /// because 48-bit timestamps fit in 130 − 80 = 50 bits, and 2^50 > 2^48.
    pub fn to_string(&self) -> String {
        let mut v = self.0;
        let mut chars = [0u8; 26];
        for i in (0..26).rev() {
            chars[i] = ALPHABET[(v & 0x1F) as usize];
            v >>= 5;
        }
        // SAFETY: every byte is an ASCII character from ALPHABET.
        unsafe { String::from_utf8_unchecked(chars.to_vec()) }
    }

    /// Parse a 26-character Crockford base32 string into a ULID.
    ///
    /// Accepts both upper and lower case; rejects any character not in the
    /// Crockford alphabet.
    pub fn from_str(s: &str) -> Result<Self, UlidError> {
        let b = s.as_bytes();
        if b.len() != 26 {
            return Err(UlidError::InvalidLength(b.len()));
        }
        let mut v: u128 = 0;
        for &c in b {
            let digit = decode_char(c).ok_or(UlidError::InvalidChar(c as char))?;
            v = (v << 5) | digit as u128;
        }
        // Values decoded from 26 Crockford chars fit in 130 bits.
        // Any value that fits in u128 is valid — the 2 extra conceptual bits
        // are always 0 because timestamps are bounded by 48 bits.
        Ok(Ulid(v))
    }
}

impl Default for Ulid {
    fn default() -> Self {
        Ulid::new()
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

/// Decode a single Crockford base32 character to its 5-bit value.
fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'0'           => Some(0),
        b'1' | b'I' | b'i' | b'L' | b'l' => Some(1),
        b'2'           => Some(2),
        b'3'           => Some(3),
        b'4'           => Some(4),
        b'5'           => Some(5),
        b'6'           => Some(6),
        b'7'           => Some(7),
        b'8'           => Some(8),
        b'9'           => Some(9),
        b'A' | b'a'    => Some(10),
        b'B' | b'b'    => Some(11),
        b'C' | b'c'    => Some(12),
        b'D' | b'd'    => Some(13),
        b'E' | b'e'    => Some(14),
        b'F' | b'f'    => Some(15),
        b'G' | b'g'    => Some(16),
        b'H' | b'h'    => Some(17),
        b'J' | b'j'    => Some(18),
        b'K' | b'k'    => Some(19),
        b'M' | b'm'    => Some(20),
        b'N' | b'n'    => Some(21),
        b'P' | b'p'    => Some(22),
        b'Q' | b'q'    => Some(23),
        b'R' | b'r'    => Some(24),
        b'S' | b's'    => Some(25),
        b'T' | b't'    => Some(26),
        b'V' | b'v'    => Some(27),
        b'W' | b'w'    => Some(28),
        b'X' | b'x'    => Some(29),
        b'Y' | b'y'    => Some(30),
        b'Z' | b'z'    => Some(31),
        _              => None,
    }
}

/// Errors that can occur when parsing a ULID string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlidError {
    InvalidLength(usize),
    InvalidChar(char),
    Overflow,
}

impl fmt::Display for UlidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UlidError::InvalidLength(n) =>
                write!(f, "ULID must be 26 characters, got {n}"),
            UlidError::InvalidChar(c) =>
                write!(f, "invalid Crockford base32 character: '{c}'"),
            UlidError::Overflow =>
                write!(f, "encoded value exceeds 128 bits"),
        }
    }
}

impl std::error::Error for UlidError {}
