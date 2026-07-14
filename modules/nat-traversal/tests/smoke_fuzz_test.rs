//! Crash-safety smoke test for the STUN parser and attribute decoder.
//!
//! # Why this exists instead of a real cargo-fuzz run
//!
//! `cargo-fuzz` requires a nightly Rust toolchain with sanitizer coverage
//! instrumentation. This project's build environment is deliberately
//! pinned to stable 1.75 with no `rustup` available (the same constraint
//! that forced the JSON-over-protobuf substitution in Phase 1's IPC
//! layer). Rather than claim a fuzz run happened when it didn't, this
//! test does the closest honest thing achievable right now: it feeds
//! thousands of random and mutated byte sequences to both `parse_message`
//! and `decode_attributes` inside `catch_unwind`, and fails loudly with
//! the exact offending bytes if either one ever panics.
//!
//! This is NOT equivalent to coverage-guided fuzzing — there is no
//! instrumentation feedback, no corpus evolution, no crash minimisation.
//! It is a fixed-seed, deterministic, reproducible crash-safety check.
//! The real `cargo fuzz run fuzz_stun_parser -- -max_total_time=3600`
//! (see `fuzz/fuzz_targets/`) is still required before this parser goes
//! anywhere near an open internet-facing port — this test is the interim
//! signal available in an environment that cannot run that command.

use nat_traversal::stun::{attributes::decode_attributes, parser::parse_message};
use std::panic;

/// A small, dependency-free xorshift PRNG. Deterministic given a fixed
/// seed, so a failing run is exactly reproducible by re-running this test
/// — unlike a truly random source, which would give a different failing
/// input every time and make the bug reported here impossible to pin down.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        XorShift64 { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    fn next_len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }
}

/// Install a silent panic hook for the duration of `f`, capturing the
/// panic message instead of letting it spam stderr across thousands of
/// iterations. Restores the previous hook afterward regardless of outcome.
fn run_silently<F: FnOnce() -> R + panic::UnwindSafe, R>(f: F) -> std::thread::Result<R> {
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| { /* swallow — we report failures explicitly below */ }));
    let result = panic::catch_unwind(f);
    panic::set_hook(prev_hook);
    result
}

// ─── Pure random buffers ───────────────────────────────────────

#[test]
fn smoke_fuzz_parse_message_random_buffers() {
    const ITERATIONS: u32 = 50_000;
    const MAX_LEN: usize  = 300;

    let mut rng = XorShift64::new(0xC0FFEE_D15EA5E);
    let mut failures: Vec<Vec<u8>> = Vec::new();

    for _ in 0..ITERATIONS {
        let len = rng.next_len(MAX_LEN);
        let buf: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();

        let outcome = run_silently(|| {
            let _ = parse_message(&buf);
        });

        if outcome.is_err() {
            failures.push(buf);
            if failures.len() >= 5 {
                break; // Enough evidence — stop early, report what we have.
            }
        }
    }

    assert!(
        failures.is_empty(),
        "parse_message panicked on {} random input(s) out of {} tried. \
         First offending buffer ({} bytes): {:?}",
        failures.len(), ITERATIONS,
        failures[0].len(), failures.first().map(|b| hex(b))
    );
}

#[test]
fn smoke_fuzz_decode_attributes_random_buffers() {
    const ITERATIONS: u32 = 50_000;
    const MAX_LEN: usize  = 300;

    let mut rng = XorShift64::new(0xDEAD_BEEF_CAFE_1234);
    let txn_id = [0u8; 12];
    let mut failures: Vec<Vec<u8>> = Vec::new();

    for _ in 0..ITERATIONS {
        let len = rng.next_len(MAX_LEN);
        let buf: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();

        let outcome = run_silently(|| {
            let _ = decode_attributes(&buf, &txn_id);
        });

        if outcome.is_err() {
            failures.push(buf);
            if failures.len() >= 5 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "decode_attributes panicked on {} random input(s) out of {} tried. \
         First offending buffer ({} bytes): {:?}",
        failures.len(), ITERATIONS,
        failures[0].len(), failures.first().map(|b| hex(b))
    );
}

// ─── Mutated known-good vectors ─────────────────────────────────
//
// Random buffers rarely pass the magic-cookie check, so most random-fuzz
// iterations above exit the parser in the first few bytes. Mutating a
// known-good message (flipping 1-3 random bits) is far more likely to
// reach deeper code paths — attribute iteration, XOR address decoding,
// padding arithmetic — while still being "attacker-plausible" input:
// a real attacker who has seen valid traffic and is probing for parser
// bugs would do exactly this, not send pure noise.

fn known_good_vectors() -> Vec<Vec<u8>> {
    vec![
        // Same Vector 1 from stun_test.rs: Binding Request, no attributes.
        vec![
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ],
        // Same Vector 2: Success Response with IPv4 XOR-MAPPED-ADDRESS.
        vec![
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x20, 0x00, 0x08,
            0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        ],
        // Same Vector 6: IPv6 XOR-MAPPED-ADDRESS.
        vec![
            0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x20, 0x00, 0x14,
            0x00, 0x02, 0x3e, 0x82, 0x01, 0x13, 0xa9, 0xfa, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x67,
        ],
        // Same Vector 8: two attributes, tests iteration + padding.
        vec![
            0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0x88, 0x88, 0x88, 0x88,
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x00, 0x06, 0x00, 0x03,
            0x61, 0x62, 0x63, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x11, 0x2b,
            0xea, 0x12, 0xd5, 0x47,
        ],
    ]
}

#[test]
fn smoke_fuzz_mutated_known_good_vectors() {
    const MUTATIONS_PER_VECTOR: u32 = 5_000;
    const MAX_BIT_FLIPS: u32 = 3;

    let mut rng = XorShift64::new(0x1337_5EED_FEED_FACE);
    let vectors = known_good_vectors();
    let txn_id = [0u8; 12];
    let mut failures: Vec<(usize, Vec<u8>)> = Vec::new();

    for (vec_idx, base) in vectors.iter().enumerate() {
        for _ in 0..MUTATIONS_PER_VECTOR {
            let mut mutated = base.clone();
            let n_flips = 1 + (rng.next_u64() % MAX_BIT_FLIPS as u64) as u32;

            for _ in 0..n_flips {
                if mutated.is_empty() { break; }
                let byte_idx = (rng.next_u64() as usize) % mutated.len();
                let bit_idx  = (rng.next_u64() % 8) as u8;
                mutated[byte_idx] ^= 1 << bit_idx;
            }

            let m1 = mutated.clone();
            let outcome1 = run_silently(|| { let _ = parse_message(&m1); });
            if outcome1.is_err() {
                failures.push((vec_idx, mutated.clone()));
                continue;
            }

            // Also fuzz decode_attributes directly on the mutated buffer,
            // independent of whether parse_message accepted it — attribute
            // decoding should be equally crash-safe on arbitrary bytes,
            // not just on bytes a valid header happened to frame.
            let outcome2 = run_silently(|| { let _ = decode_attributes(&mutated, &txn_id); });
            if outcome2.is_err() {
                failures.push((vec_idx, mutated));
            }

            if failures.len() >= 5 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "found {} panic(s) from bit-flip mutations of known-good vectors. \
         First: base vector #{}, mutated bytes: {}",
        failures.len(),
        failures.first().map(|(i, _)| *i).unwrap_or(usize::MAX),
        failures.first().map(|(_, b)| hex(b)).unwrap_or_default()
    );
}

// ─── Structured edge cases a pure random walk rarely hits ───────

#[test]
fn smoke_fuzz_structured_edge_cases() {
    let txn_id = [0u8; 12];
    let cases: Vec<Vec<u8>> = vec![
        vec![],                                   // empty
        vec![0x00],                               // 1 byte
        vec![0x00, 0x00],                          // 2 bytes
        vec![0xFF; 20],                             // all-0xFF header
        vec![0x00; 20],                             // all-zero header
        vec![0x00, 0x01, 0xFF, 0xFF, 0x21, 0x12, 0xa4, 0x42, 0,0,0,0,0,0,0,0,0,0,0,0], // max declared length
        {
            // Valid header, message_length claims usize::MAX-adjacent value
            // when reinterpreted — this specifically probes for integer
            // overflow in the `value_start + attr_len` arithmetic inside
            // decode_attributes.
            let mut v = vec![0x00, 0x06, 0xFF, 0xFF];
            v.extend_from_slice(&[0xAB; 4]);
            v
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let o1 = run_silently(|| { let _ = parse_message(case); });
        if o1.is_err() { failures.push(("parse_message", case.clone())); }
        let o2 = run_silently(|| { let _ = decode_attributes(case, &txn_id); });
        if o2.is_err() { failures.push(("decode_attributes", case.clone())); }
    }

    assert!(
        failures.is_empty(),
        "structured edge case(s) panicked: {:?}",
        failures.iter().map(|(f, b)| format!("{f}({})", hex(b))).collect::<Vec<_>>()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}
