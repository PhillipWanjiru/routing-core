//! libFuzzer harness for the SIP message parser.
//!
//! Run with:
//!   cargo fuzz run fuzz_sip_parser -- -max_total_time=1800
//!
//! Pass criteria:
//! - Zero crashes
//! - Zero panics
//! - Zero AddressSanitizer findings
//!
//! The fuzzer will generate corpus entries that cover every branch
//! of the nom combinators.  Save the corpus; it feeds regression
//! runs in every subsequent phase.

#![no_main]
use libfuzzer_sys::fuzz_target;
use voip_sip::sip::parser::parse_message;

fuzz_target!(|data: &[u8]| {
    // parse_message must never panic regardless of input.
    // It may return Ok or Err, but must not crash.
    let _ = parse_message(data);
});
