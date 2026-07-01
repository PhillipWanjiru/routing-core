//! SIP message construction.
//!
//! The parser (`sip::parser`) turns bytes into structured messages.
//! This module does the reverse: turns structured intent into valid,
//! RFC 3261-compliant SIP message bytes.
//!
//! Kept as plain `format!` string assembly — consistent with the existing
//! `sip::options` module — rather than a generic serializer, since SIP's
//! header ordering and exact CRLF discipline matter and are easiest to
//! get right by writing each message shape explicitly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Random-ish identifier generation ──────────────────────────
//
// Same approach as tracing::ulid: nanosecond time mixed with an atomic
// counter. Not cryptographically secure — fine for tags and branch
// parameters, which only need to be unique per-process, not unguessable.
// Phase 4's auth-pki service owns anything that needs real CSPRNG output.

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn mix() -> u64 {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    (ns ^ c).wrapping_mul(0x9e3779b97f4a7c15)
}

fn hex_id(nibbles: usize) -> String {
    let mut out = String::with_capacity(nibbles);
    let mut v = mix();
    for _ in 0..nibbles {
        out.push(std::char::from_digit((v & 0xF) as u32, 16).unwrap());
        v >>= 4;
        if v == 0 {
            v = mix();
        }
    }
    out
}

/// Generate a SIP tag parameter value (RFC 3261 §19.3 — opaque token).
pub fn gen_tag() -> String {
    hex_id(8)
}

/// Generate a Via branch parameter.
///
/// RFC 3261 §8.1.1.7 requires the "z9hG4bK" magic cookie prefix so that
/// RFC 3261-compliant elements can recognise this as a compliant branch ID
/// (and use it directly as a transaction key) rather than falling back to
/// the older RFC 2543 branch-matching heuristics.
pub fn gen_branch() -> String {
    format!("z9hG4bK{}", hex_id(16))
}

/// Generate a Call-ID (RFC 3261 §8.1.1.4 — must be globally unique
/// per call, conventionally random-string@host).
pub fn gen_call_id(host: &str) -> String {
    format!("{}@{}", hex_id(16), host)
}

// ─── Request builders ───────────────────────────────────────────

/// Parameters shared by every request this builder constructs.
pub struct RequestParts<'a> {
    pub from_uri:    &'a str,
    pub from_tag:    &'a str,
    pub to_uri:      &'a str,
    /// `None` for the initial INVITE; `Some(tag)` for in-dialog requests
    /// (ACK, BYE) once the remote party's To-tag is known.
    pub to_tag:      Option<&'a str>,
    pub call_id:     &'a str,
    pub cseq:        u32,
    pub local_contact: &'a str,
    pub via_branch:  &'a str,
    pub via_host:    &'a str,
}

fn to_header(to_uri: &str, to_tag: Option<&str>) -> String {
    match to_tag {
        Some(tag) => format!("<{to_uri}>;tag={tag}"),
        None      => format!("<{to_uri}>"),
    }
}

/// Build an INVITE request with a minimal audio SDP offer.
///
/// `sdp_port` is the RTP port this side is offering to receive audio on —
/// this exercises the real `sip::sdp` parser on the receiving end in the
/// same live exchange that exercises the SIP parser, rather than testing
/// signaling and SDP in isolation.
pub fn build_invite(p: &RequestParts, request_uri: &str, sdp_port: u16) -> String {
    let sdp = build_offer_sdp(sdp_port);
    format!(
        "INVITE {request_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {via_host};branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <{from_uri}>;tag={from_tag}\r\n\
         To: {to_header}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} INVITE\r\n\
         Contact: <{contact}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {sdp_len}\r\n\
         \r\n\
         {sdp}",
        request_uri = request_uri,
        via_host    = p.via_host,
        branch      = p.via_branch,
        from_uri    = p.from_uri,
        from_tag    = p.from_tag,
        to_header   = to_header(p.to_uri, p.to_tag),
        call_id     = p.call_id,
        cseq        = p.cseq,
        contact     = p.local_contact,
        sdp_len     = sdp.len(),
        sdp         = sdp,
    )
}

/// Build an in-dialog ACK. Must carry the *original* INVITE's branch and
/// CSeq number (RFC 3261 §17.1.1.3 — ACK for a 2xx is a new transaction
/// with its own branch, but reuses the INVITE's CSeq number).
pub fn build_ack(p: &RequestParts, request_uri: &str) -> String {
    format!(
        "ACK {request_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {via_host};branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <{from_uri}>;tag={from_tag}\r\n\
         To: {to_header}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} ACK\r\n\
         Content-Length: 0\r\n\
         \r\n",
        via_host  = p.via_host,
        branch    = p.via_branch,
        from_uri  = p.from_uri,
        from_tag  = p.from_tag,
        to_header = to_header(p.to_uri, p.to_tag),
        call_id   = p.call_id,
        cseq      = p.cseq,
        request_uri = request_uri,
    )
}

/// Build an in-dialog BYE. Uses a fresh branch (new transaction) and an
/// incremented CSeq number relative to the request that established the dialog.
pub fn build_bye(p: &RequestParts, request_uri: &str) -> String {
    format!(
        "BYE {request_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {via_host};branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <{from_uri}>;tag={from_tag}\r\n\
         To: {to_header}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        via_host  = p.via_host,
        branch    = p.via_branch,
        from_uri  = p.from_uri,
        from_tag  = p.from_tag,
        to_header = to_header(p.to_uri, p.to_tag),
        call_id   = p.call_id,
        cseq      = p.cseq,
        request_uri = request_uri,
    )
}

// ─── Response builders ───────────────────────────────────────────
//
// RFC 3261 §8.2.6.2: a UAS response copies Via, From, Call-ID, CSeq, and
// the request's To header verbatim from the request, adding a tag to To
// only if one is not already present (i.e. on the first response in a
// transaction). From/To are NOT swapped — the UAS's own identity stays
// in To, the caller's identity stays in From, exactly as the request had it.

/// Parameters needed to build any response: everything copied from the
/// inbound request, plus what the response itself contributes.
pub struct ResponseParts<'a> {
    pub via:      &'a str,
    pub from:     &'a str,
    pub to_uri:   &'a str,
    /// Tag this UAS assigns to the To header. Generated once per dialog
    /// and reused for every response in that dialog (RFC 3261 §12.1.1).
    pub to_tag:   &'a str,
    pub call_id:  &'a str,
    pub cseq:     &'a str,
    pub local_contact: &'a str,
}

fn response_skeleton(p: &ResponseParts, status_line: &str, body: &str, content_type: &str) -> String {
    let content_length_line = if body.is_empty() {
        "Content-Length: 0\r\n".to_string()
    } else {
        format!("Content-Type: {content_type}\r\nContent-Length: {}\r\n", body.len())
    };
    format!(
        "{status_line}\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: <{to_uri}>;tag={to_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Contact: <{contact}>\r\n\
         {content_length_line}\
         \r\n\
         {body}",
        via      = p.via,
        from     = p.from,
        to_uri   = p.to_uri,
        to_tag   = p.to_tag,
        call_id  = p.call_id,
        cseq     = p.cseq,
        contact  = p.local_contact,
    )
}

/// 100 Trying — provisional, hop-by-hop, never includes a body.
pub fn build_100_trying(p: &ResponseParts) -> String {
    response_skeleton(p, "SIP/2.0 100 Trying", "", "")
}

/// 180 Ringing — provisional, establishes the early dialog (carries To-tag).
pub fn build_180_ringing(p: &ResponseParts) -> String {
    response_skeleton(p, "SIP/2.0 180 Ringing", "", "")
}

/// 200 OK for INVITE — final success response, carries the SDP answer.
pub fn build_200_ok_invite(p: &ResponseParts, sdp_port: u16) -> String {
    let sdp = build_offer_sdp(sdp_port);
    response_skeleton(p, "SIP/2.0 200 OK", &sdp, "application/sdp")
}

/// 200 OK for BYE — final response, no body.
pub fn build_200_ok_bye(p: &ResponseParts) -> String {
    response_skeleton(p, "SIP/2.0 200 OK", "", "")
}

/// 486 Busy Here — final rejection response, no body.
pub fn build_486_busy(p: &ResponseParts) -> String {
    response_skeleton(p, "SIP/2.0 486 Busy Here", "", "")
}

// ─── Minimal SDP body ─────────────────────────────────────────────

/// A minimal, valid single-audio-stream SDP body offering G.711 u-law.
/// Real enough to exercise `sip::sdp::parse_sdp` on the receiving end.
fn build_offer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n"
    )
}
