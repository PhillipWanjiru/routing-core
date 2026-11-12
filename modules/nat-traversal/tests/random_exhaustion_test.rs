//! Randomness must survive the process running out of file descriptors.
//!
//! This is the failure the old design handled worst: it opened `/dev/urandom` on every
//! call, so exhausting descriptors (which is what a flooded server does) made it silently
//! fall back to predictable values. It lives in its own test binary, with one test, because
//! exhausting descriptors would break any other test running in the same process.

use nat_traversal::ice::random::{random_bytes, random_u64, try_random_bytes};
use std::collections::HashSet;
use std::fs::File;

#[test]
fn randomness_is_still_available_when_the_process_has_no_file_descriptors_left() {
    // The handle is opened on first use and kept.
    let first: [u8; 16] = random_bytes();

    let mut hogs = Vec::new();
    while let Ok(f) = File::open("/dev/null") {
        hogs.push(f);
        if hogs.len() > 3_000_000 {
            eprintln!("could not exhaust file descriptors (limit too high); nothing to verify here");
            return;
        }
    }
    assert!(File::open("/dev/urandom").is_err(), "setup: descriptors really are exhausted");

    let draws: HashSet<[u8; 16]> = (0..2000).map(|_| try_random_bytes::<16>().expect("a held handle needs no new descriptor")).collect();
    assert_eq!(draws.len(), 2000, "and the values are still all different");
    assert!(!draws.contains(&first));
    let tie_breakers: HashSet<u64> = (0..200).map(|_| random_u64()).collect();
    assert_eq!(tie_breakers.len(), 200);
    drop(hogs);
}
