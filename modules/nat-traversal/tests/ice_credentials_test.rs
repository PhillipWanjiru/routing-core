//! ICE credentials generated from the operating system's CSPRNG.
//!
//! The password keys every connectivity check, so these tests are about the properties that
//! make it unguessable: enough bits, a uniform alphabet, nothing shared between values.

use nat_traversal::ice::sdp::{format_ice_attributes, is_ice_char, parse_ice_attributes, EncodeOptions, IceDescription};
use nat_traversal::ice::IceCredentials;
use std::collections::{HashMap, HashSet};

fn many(n: usize) -> Vec<IceCredentials> {
    (0..n).map(|_| IceCredentials::generate().expect("OS randomness")).collect()
}

#[test]
fn lengths_give_at_least_the_entropy_rfc_8839_asks_for() {
    // 6 bits per character: 8 characters = 48 bits (RFC: at least 24), 24 characters = 144 bits (RFC: at least 128).
    for c in many(200) {
        assert_eq!((c.ufrag.len(), c.password.len()), (8, 24));
    }
}

#[test]
fn every_character_is_an_ice_character() {
    for c in many(2000) {
        assert!(c.ufrag.chars().chain(c.password.chars()).all(is_ice_char), "{c:?}");
    }
}

#[test]
fn they_pass_the_sdp_codec_in_both_directions() {
    for c in many(200) {
        let d = IceDescription { ufrag: Some(c.ufrag.clone()), pwd: Some(c.password.clone()), ..Default::default() };
        let text = format_ice_attributes(&d, EncodeOptions::default()).expect("valid by construction");
        assert_eq!(parse_ice_attributes(&text).unwrap().credentials(), Some(c));
    }
}

#[test]
fn ten_thousand_credentials_are_all_different() {
    let all = many(10_000);
    assert_eq!(all.iter().map(|c| c.password.clone()).collect::<HashSet<_>>().len(), 10_000);
    assert_eq!(all.iter().map(|c| c.ufrag.clone()).collect::<HashSet<_>>().len(), 10_000, "48 bits: a collision in 10,000 would be a roughly 1-in-6-million event");
}

#[test]
fn all_sixty_four_characters_are_equally_likely() {
    // A wrong mask, a truncated alphabet or modulo bias shows up here. 20,000 credentials give
    // 640,000 characters, 10,000 expected per symbol with a standard deviation near 100, so
    // +-10% is about ten standard deviations: it cannot fail by chance.
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in many(20_000) {
        for ch in c.ufrag.chars().chain(c.password.chars()) {
            *counts.entry(ch).or_default() += 1;
        }
    }
    assert_eq!(counts.len(), 64, "every one of the 64 symbols must be reachable");
    for (ch, n) in &counts {
        assert!((9_000..=11_000).contains(n), "{ch:?} appeared {n} times, expected about 10,000");
    }
}

#[test]
fn the_ufrag_and_the_password_are_drawn_from_different_bytes() {
    for c in many(5_000) {
        assert_ne!(c.ufrag, c.password[..8], "an overlap would make the ufrag, which is public, reveal part of the secret");
        assert_ne!(c.ufrag, c.password[16..], "likewise the end");
    }
}
