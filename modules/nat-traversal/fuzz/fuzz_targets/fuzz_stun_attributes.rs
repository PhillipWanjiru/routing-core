//! libFuzzer harness for STUN attribute decoding.
//!
//! Separate from fuzz_stun_parser.rs because decode_attributes operates
//! on an already length-framed byte slice (the parser's job is done by
//! the time this runs) but still processes fully attacker-controlled
//! bytes — attribute type, length, and value are all under the sender's
//! control. Mirrors the fuzz_sip_parser / fuzz_sdp_parser split from
//! Phase 1, where the message parser and the body parser got independent
//! fuzz targets rather than one harness covering both.

#![no_main]
use libfuzzer_sys::fuzz_target;
use nat_traversal::stun::attributes::decode_attributes;

fuzz_target!(|data: &[u8]| {
    // Transaction ID content is irrelevant to crash-safety (it only affects
    // the XOR mask value, not control flow), so a fixed value is fine here.
    let txn_id = [0u8; 12];
    let _ = decode_attributes(data, &txn_id);
});
