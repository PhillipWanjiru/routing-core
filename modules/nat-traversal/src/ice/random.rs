//! Randomness for ICE: transaction IDs and tie-breakers.
//!
//! This matters more than it looks. A check *response* is protected by
//! MESSAGE-INTEGRITY, but an *error* response to a rejected check cannot be
//! (the rejecting side has nothing to sign with), so the transaction ID is
//! the only thing standing between an off-path attacker and a forged error
//! that fails a working pair. RFC 5389 §6 therefore requires transaction IDs
//! to be uniformly random — a predictable counter would not do.
//!
//! The source is the kernel's CSPRNG via `/dev/urandom`, which this project
//! already targets (Ubuntu/Linux). If that read fails — non-Linux, or a
//! sandbox without it — [`weak_fallback_bytes`] takes over. That fallback is
//! time-and-counter mixing: unique within a process, **not** unpredictable,
//! and exposed publicly only so its behaviour can be tested. A deployment
//! that reaches it should be treated as degraded.

use std::io::Read;

/// `N` random bytes from the OS CSPRNG, falling back to
/// [`weak_fallback_bytes`] if `/dev/urandom` cannot be read.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    weak_fallback_bytes::<N>()
}

/// A uniformly random `u64`, e.g. an ICE tie-breaker (RFC 8445 §5.2).
pub fn random_u64() -> u64 {
    u64::from_be_bytes(random_bytes::<8>())
}

/// Time-and-counter mixing. Distinct across calls within a process; **not
/// cryptographically secure** — see the module comment.
pub fn weak_fallback_bytes<const N: usize>() -> [u8; N] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0x1234_5678);
    let mut buf = [0u8; N];
    for chunk in buf.chunks_mut(8) {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let c = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        let mixed = (ns ^ c).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ c;
        let bytes = mixed.to_be_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    buf
}
