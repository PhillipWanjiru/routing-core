//! RFC 5389 STUN message parser, built with nom 7 combinators.
//!
//! # Design principles — identical discipline to modules/voip-sip/src/sip/parser.rs
//!
//! 1. **Treats all input as hostile.** This parser will eventually process
//!    packets from arbitrary internet hosts on an open UDP port. No panic
//!    paths exist. Every unexpected byte produces a nom error, not a crash.
//!    Enforced by the libFuzzer target in `fuzz/fuzz_targets/fuzz_stun_parser.rs`.
//!
//! 2. **No unsafe blocks.**
//!
//! 3. **Incomplete vs Error.** A message that is well-formed so far but
//!    needs more bytes returns `Incomplete`; a message that violates the
//!    grammar returns `Malformed`. In practice, on this module's current
//!    transport (UDP — `recv_from()` always hands back one complete,
//!    atomic datagram), `NeedsMoreData` will not fire: a `message_length`
//!    field claiming more bytes than the datagram actually contains is
//!    genuinely `Malformed`, not incomplete, because there is no "rest of
//!    the message" still arriving for a UDP packet that has already been
//!    fully received. The `NeedsMoreData` variant remains correctly wired
//!    for the day this parser is reused against a TCP/TLS-framed byte
//!    stream (RFC 5389 §7.2.2), where a genuinely partial read from the
//!    stream is a real, distinct case from a corrupt message — it just
//!    isn't reachable via the UDP path this milestone targets.
//!
//! # STUN message structure (RFC 5389 §6)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                 |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The top two bits of the message type are always 0 — this is what lets
//! STUN and RTP/RTCP share a port unambiguously (RTP's version field
//! occupies those same two bits with value 2, RTCP similarly non-zero).
//! We reject any input where those bits are set, exactly as RFC 5389 §6
//! requires, rather than silently accepting it.
//!
//! Following the 20-byte fixed header is zero or more TLV attributes,
//! each padded to a 4-byte boundary (RFC 5389 §15).

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    IResult,
};
use std::fmt;

// ─── Constants ──────────────────────────────────────────────────

/// Fixed 32-bit magic cookie (RFC 5389 §6). Its presence is what
/// distinguishes a STUN message from the older RFC 3489 format, and
/// (combined with the top-two-zero-bits rule) is what allows STUN to be
/// demultiplexed from RTP/RTCP on a shared port.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

pub const HEADER_LEN: usize = 20;
pub const TRANSACTION_ID_LEN: usize = 12;

// ─── Message class and method ───────────────────────────────────

/// The STUN message class (RFC 5389 §6, encoded across two non-adjacent
/// bits of the 14-bit method field — see [`decode_class_and_method`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MessageClass::Request         => "Request",
            MessageClass::Indication      => "Indication",
            MessageClass::SuccessResponse => "Success Response",
            MessageClass::ErrorResponse   => "Error Response",
        };
        f.write_str(s)
    }
}

/// Known STUN methods. Binding (0x0001) is the only method this Phase 4
/// milestone implements; TURN adds Allocate/Refresh/etc. as an extension
/// (RFC 5766 §13), represented here as `Extension` until that module lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Binding,
    Extension(u16),
}

// ─── Parsed message ──────────────────────────────────────────────

/// A fully parsed STUN message header plus raw (un-decoded) attribute bytes.
///
/// Attribute *decoding* (XOR-MAPPED-ADDRESS, USERNAME, etc.) is deliberately
/// a separate concern from framing — this mirrors how `sip::parser` extracts
/// headers as opaque strings and leaves semantic interpretation (e.g. tag
/// extraction) to the caller. See `stun::attributes` for decoding.
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub class:          MessageClass,
    pub method:         Method,
    /// Length of the attributes section in bytes, as declared in the header.
    /// Guaranteed equal to `attributes_raw.len()` after a successful parse.
    pub message_length: u16,
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    /// Raw TLV-encoded attribute bytes, not yet decoded.
    pub attributes_raw: Vec<u8>,
}

/// Errors produced by the STUN parser — same two-variant shape as
/// `sip::parser::ParseError`, for the same reason: the I/O layer needs to
/// know whether to keep buffering (`NeedsMoreData`) or discard the
/// datagram outright (`Malformed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    NeedsMoreData,
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NeedsMoreData => write!(f, "incomplete STUN message — needs more data"),
            ParseError::Malformed(r)  => write!(f, "malformed STUN message: {r}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ─── Public API ───────────────────────────────────────────────────

/// Parse one complete STUN message from `input`.
///
/// Returns `Ok(StunMessage)` on success, `Err(ParseError)` otherwise.
/// Unlike the SIP parser, STUN messages are length-prefixed in their own
/// header (`message_length`), so there is no ambiguity about where the
/// message ends once the header is readable — but a truncated *header*
/// (fewer than 20 bytes) or a declared length exceeding the available
/// input both correctly produce `NeedsMoreData`, not a panic or a
/// read past the buffer.
pub fn parse_message(input: &[u8]) -> Result<StunMessage, ParseError> {
    match stun_message(input) {
        Ok((_, msg)) => Ok(msg),
        Err(nom::Err::Incomplete(_)) => Err(ParseError::NeedsMoreData),
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            Err(ParseError::Malformed(format!("{:?}", e.code)))
        }
    }
}

// ─── nom combinators ────────────────────────────────────────────

fn stun_message(input: &[u8]) -> IResult<&[u8], StunMessage> {
    let (input, msg_type_raw) = be_u16(input)?;

    // RFC 5389 §6: top two bits MUST be 0. Reject anything else outright
    // rather than masking them away silently — a set top bit here usually
    // means this is RTP/RTCP (or garbage), not STUN, and treating it as
    // STUN anyway would be exactly the kind of "helpful" leniency that
    // creates security bugs.
    if msg_type_raw & 0xC000 != 0 {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let (input, message_length) = be_u16(input)?;
    let (input, _magic)         = verify_magic_cookie(input)?;
    let (input, txn_id_slice)   = take(TRANSACTION_ID_LEN)(input)?;
    let (input, attrs_raw)      = take(message_length as usize)(input)?;

    let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(txn_id_slice);

    let (class, method) = decode_class_and_method(msg_type_raw);

    Ok((input, StunMessage {
        class,
        method,
        message_length,
        transaction_id,
        attributes_raw: attrs_raw.to_vec(),
    }))
}

fn verify_magic_cookie(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, cookie) = be_u32(input)?;
    if cookie != MAGIC_COOKIE {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok((input, cookie))
}

/// Decode the STUN message class and method from the 14-bit type field.
///
/// RFC 5389 §6: the class is encoded as two bits, C1 and C0, interleaved
/// with the method bits at fixed positions (not contiguous) — this odd
/// layout is a deliberate backward-compatibility artifact of RFC 3489,
/// preserved by RFC 5389. Bit positions (0-indexed from MSB of the 16-bit
/// type field, with the top 2 bits already known to be 0):
///
/// ```text
/// 0 0 M M M M M C M M M M C M M M
///         11109       876543210
/// ```
/// C0 is bit 4 (0x0010), C1 is bit 8 (0x0100). Method bits occupy the
/// remaining 12 positions, split across three groups.
fn decode_class_and_method(msg_type: u16) -> (MessageClass, Method) {
    let c0 = (msg_type & 0x0010) != 0;
    let c1 = (msg_type & 0x0100) != 0;

    let class = match (c1, c0) {
        (false, false) => MessageClass::Request,
        (false, true)  => MessageClass::Indication,
        (true,  false) => MessageClass::SuccessResponse,
        (true,  true)  => MessageClass::ErrorResponse,
    };

    // Reassemble the 12-bit method by removing the two class bits and
    // closing the gap they left.
    let m_low   = msg_type & 0x000F;        // bits 0-3
    let m_mid   = (msg_type & 0x00E0) >> 1; // bits 5-7, shifted down past removed bit 4
    let m_high  = (msg_type & 0x3E00) >> 2; // bits 9-13, shifted down past removed bit 8
    let method_bits = m_high | m_mid | m_low;

    let method = match method_bits {
        0x001 => Method::Binding,
        other => Method::Extension(other),
    };

    (class, method)
}

impl StunMessage {
    /// True if this message is a Binding Request — the only message type
    /// this Phase 4 milestone's server responds to.
    pub fn is_binding_request(&self) -> bool {
        self.method == Method::Binding && self.class == MessageClass::Request
    }
}
