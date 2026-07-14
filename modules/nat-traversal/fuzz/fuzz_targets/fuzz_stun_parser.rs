//! libFuzzer harness for the STUN message parser.
//!
//! Run with:
//!   cargo fuzz run fuzz_stun_parser -- -max_total_time=3600
//!
//! Pass criteria (matching fuzz_sip_parser's standard exactly):
//! - Zero crashes
//! - Zero panics
//! - Zero AddressSanitizer findings
//!
//! This parser will eventually process datagrams from arbitrary internet
//! hosts on an open UDP port. That is the entire justification for this
//! harness existing before any server logic is built on top of the parser
//! — the same ordering used for modules/voip-sip's SIP parser in Phase 1.

#![no_main]
use libfuzzer_sys::fuzz_target;
use nat_traversal::stun::parser::parse_message;

fuzz_target!(|data: &[u8]| {
    // parse_message must never panic regardless of input, only ever
    // return Ok or a typed Err.
    let _ = parse_message(data);
});
