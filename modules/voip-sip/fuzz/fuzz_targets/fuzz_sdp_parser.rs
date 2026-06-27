//! libFuzzer harness for the SDP parser.

#![no_main]
use libfuzzer_sys::fuzz_target;
use voip_sip::sip::sdp::parse_sdp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_sdp(data);
});
