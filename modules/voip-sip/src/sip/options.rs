//! SIP OPTIONS handling.
//!
//! OPTIONS serves two purposes:
//! 1. Capability query: a peer asks what methods, codecs, and extensions
//!    we support.
//! 2. Keepalive / NAT binding refresh: we send periodic OPTIONS to
//!    registered endpoints to detect liveness and refresh NAT pinholes.

use crate::sip::parser::SipMessage;

/// Build a 200 OK response to an incoming OPTIONS request.
///
/// Advertises supported methods and codecs.  The response is built as
/// a string; the caller is responsible for sending it.
pub fn build_options_response(request: &SipMessage, local_uri: &str) -> String {
    let call_id = request.call_id().unwrap_or("-");
    let from    = request.header("From").unwrap_or("-");
    let to      = request.header("To").unwrap_or("-");
    let cseq    = request.header("CSeq").unwrap_or("1 OPTIONS");
    let via     = request.header("Via").unwrap_or("-");

    format!(
        "SIP/2.0 200 OK
         Via: {via}
         From: {from}
         To: {to}
         Call-ID: {call_id}
         CSeq: {cseq}
         Contact: <{local_uri}>
         Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, NOTIFY, SUBSCRIBE
         Accept: application/sdp
         Accept-Encoding: identity
         Accept-Language: en
         Supported: timer
         Content-Length: 0
         
"
    )
}

/// Build an OPTIONS request for use as a keepalive probe.
pub fn build_options_request(
    target_uri: &str,
    local_uri:  &str,
    call_id:    &str,
    cseq:       u32,
) -> String {
    format!(
        "OPTIONS {target_uri} SIP/2.0
         Via: SIP/2.0/UDP {local_uri};branch=z9hG4bKnka.{cseq}
         Max-Forwards: 70
         From: <{local_uri}>;tag=routing-core
         To: <{target_uri}>
         Call-ID: {call_id}
         CSeq: {cseq} OPTIONS
         Content-Length: 0
         
"
    )
}
