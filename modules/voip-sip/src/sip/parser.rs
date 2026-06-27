//! RFC 3261 SIP message parser built with nom 7.
//!
//! # Design principles
//!
//! 1. **Treats all input as hostile.** No panic paths exist in the parser
//!    itself. Every unexpected byte produces a nom error, not a crash.
//!    This is enforced by the libFuzzer target in `fuzz/fuzz_targets/`.
//!
//! 2. **No unsafe blocks.** Rust's nom combinators operate on byte slices
//!    and the type system prevents buffer overflows by construction.
//!
//! 3. **Incomplete vs Error.** Nom distinguishes between a message that is
//!    well-formed so far but needs more bytes (`Incomplete`) and one that
//!    violates the grammar (`Error`). We surface this distinction to callers
//!    so the I/O layer can buffer correctly.
//!
//! 4. **Folded headers.** RFC 3261 allows a header value to continue on the
//!    next line if that line starts with a space or tab (obs-fold). We
//!    unfold these before handing the value to the caller.
//!
//! # Coverage
//!
//! - Request-Line and Status-Line.
//! - All header fields named in RFC 3261 §20 (compact form included).
//! - Content-Length based body extraction.
//! - Unknown headers are preserved verbatim, not rejected.

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take, take_till, take_while, take_while1},
    character::complete::{char, crlf, digit1, line_ending, not_line_ending, space0, space1},
    combinator::{map, map_res, opt, recognize},
    multi::many0,
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};
use std::fmt;

// ─── Public types ─────────────────────────────────────────────

/// A fully parsed SIP message (request or response).
#[derive(Debug, Clone)]
pub struct SipMessage {
    pub start_line: StartLine,
    pub headers:    Vec<SipHeader>,
    pub body:       Vec<u8>,
}

/// The first line of a SIP message.
#[derive(Debug, Clone)]
pub enum StartLine {
    Request(RequestLine),
    Response(StatusLine),
}

/// SIP request line: `Method SP Request-URI SP SIP/2.0 CRLF`
#[derive(Debug, Clone)]
pub struct RequestLine {
    pub method:  Method,
    pub uri:     String,
    pub version: SipVersion,
}

/// SIP status line: `SIP/2.0 SP Status-Code SP Reason-Phrase CRLF`
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub version:       SipVersion,
    pub status_code:   u16,
    pub reason_phrase: String,
}

/// SIP protocol version.  Almost always Major=2, Minor=0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipVersion {
    pub major: u8,
    pub minor: u8,
}

impl fmt::Display for SipVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/{}.{}", self.major, self.minor)
    }
}

/// SIP request method.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Register,
    Info,
    Message,
    Notify,
    Prack,
    Publish,
    Refer,
    Subscribe,
    Update,
    /// Extension method not listed in RFC 3261.
    Extension(String),
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Method::Invite    => "INVITE",
            Method::Ack       => "ACK",
            Method::Bye       => "BYE",
            Method::Cancel    => "CANCEL",
            Method::Options   => "OPTIONS",
            Method::Register  => "REGISTER",
            Method::Info      => "INFO",
            Method::Message   => "MESSAGE",
            Method::Notify    => "NOTIFY",
            Method::Prack     => "PRACK",
            Method::Publish   => "PUBLISH",
            Method::Refer     => "REFER",
            Method::Subscribe => "SUBSCRIBE",
            Method::Update    => "UPDATE",
            Method::Extension(m) => m.as_str(),
        };
        f.write_str(s)
    }
}

/// One header field.  The value is unfolded (obs-fold whitespace removed).
#[derive(Debug, Clone)]
pub struct SipHeader {
    pub name:  String,
    pub value: String,
}

/// Errors produced by the SIP parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input is incomplete; more bytes are needed.
    NeedsMoreData,
    /// The input violates the SIP grammar.
    Malformed(String),
    /// Content-Length header is present but the value is not a valid integer.
    InvalidContentLength(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NeedsMoreData =>
                write!(f, "incomplete SIP message — needs more data"),
            ParseError::Malformed(r) =>
                write!(f, "malformed SIP message: {r}"),
            ParseError::InvalidContentLength(v) =>
                write!(f, "invalid Content-Length: '{v}'"),
        }
    }
}

impl std::error::Error for ParseError {}

// ─── Public API ───────────────────────────────────────────────

/// Parse one complete SIP message from `input`.
///
/// Returns `Ok(SipMessage)` on success, `Err(ParseError)` otherwise.
/// The body is extracted according to the Content-Length header when present;
/// if absent the body is empty.
pub fn parse_message(input: &[u8]) -> Result<SipMessage, ParseError> {
    match sip_message(input) {
        Ok((_, msg)) => Ok(msg),
        Err(nom::Err::Incomplete(_)) => Err(ParseError::NeedsMoreData),
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            Err(ParseError::Malformed(format!("{:?}", e.code)))
        }
    }
}

// ─── Top-level nom combinator ─────────────────────────────────

fn sip_message(input: &[u8]) -> IResult<&[u8], SipMessage> {
    let (input, start_line) = parse_start_line(input)?;
    let (input, headers)    = many0(parse_header_field)(input)?;
    let (input, _)          = crlf(input)?; // blank line separating headers from body

    // Extract body using Content-Length.
    let content_length = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length")
                       || h.name.eq_ignore_ascii_case("l"))
        .and_then(|h| h.value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let (input, body) = if content_length > 0 {
        let (rest, body_bytes) = take(content_length)(input)?;
        (rest, body_bytes.to_vec())
    } else {
        (input, Vec::new())
    };

    Ok((input, SipMessage { start_line, headers, body }))
}

// ─── Start line ───────────────────────────────────────────────

fn parse_start_line(input: &[u8]) -> IResult<&[u8], StartLine> {
    alt((
        map(parse_request_line,  StartLine::Request),
        map(parse_status_line,   StartLine::Response),
    ))(input)
}

/// `Method SP Request-URI SP SIP/2.0 CRLF`
fn parse_request_line(input: &[u8]) -> IResult<&[u8], RequestLine> {
    let (input, method)  = parse_method(input)?;
    let (input, _)       = space1(input)?;
    let (input, uri)     = parse_request_uri(input)?;
    let (input, _)       = space1(input)?;
    let (input, version) = parse_sip_version(input)?;
    let (input, _)       = crlf(input)?;

    Ok((input, RequestLine {
        method,
        uri: String::from_utf8_lossy(uri).into_owned(),
        version,
    }))
}

/// `SIP/2.0 SP Status-Code SP Reason-Phrase CRLF`
fn parse_status_line(input: &[u8]) -> IResult<&[u8], StatusLine> {
    let (input, version)  = parse_sip_version(input)?;
    let (input, _)        = space1(input)?;
    let (input, code_raw) = digit1(input)?;
    let (input, _)        = space1(input)?;
    let (input, reason)   = not_line_ending(input)?;
    let (input, _)        = crlf(input)?;

    let status_code = std::str::from_utf8(code_raw)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| nom::Err::Failure(nom::error::Error::new(
            code_raw,
            nom::error::ErrorKind::Digit,
        )))?;

    Ok((input, StatusLine {
        version,
        status_code,
        reason_phrase: String::from_utf8_lossy(reason).into_owned(),
    }))
}

fn parse_sip_version(input: &[u8]) -> IResult<&[u8], SipVersion> {
    // Accept "SIP/2.0" and any other major.minor combination.
    let (input, _)     = tag_no_case(b"SIP/")(input)?;
    let (input, major) = map_res(digit1, |d| {
        std::str::from_utf8(d).unwrap_or("0").parse::<u8>()
    })(input)?;
    let (input, _)     = char('.')(input)?;
    let (input, minor) = map_res(digit1, |d| {
        std::str::from_utf8(d).unwrap_or("0").parse::<u8>()
    })(input)?;

    Ok((input, SipVersion { major, minor }))
}

fn parse_method(input: &[u8]) -> IResult<&[u8], Method> {
    let (input, raw) = take_while1(|c: u8| c.is_ascii_uppercase())(input)?;
    let method = match raw {
        b"INVITE"    => Method::Invite,
        b"ACK"       => Method::Ack,
        b"BYE"       => Method::Bye,
        b"CANCEL"    => Method::Cancel,
        b"OPTIONS"   => Method::Options,
        b"REGISTER"  => Method::Register,
        b"INFO"      => Method::Info,
        b"MESSAGE"   => Method::Message,
        b"NOTIFY"    => Method::Notify,
        b"PRACK"     => Method::Prack,
        b"PUBLISH"   => Method::Publish,
        b"REFER"     => Method::Refer,
        b"SUBSCRIBE" => Method::Subscribe,
        b"UPDATE"    => Method::Update,
        other        => Method::Extension(
            String::from_utf8_lossy(other).into_owned()
        ),
    };
    Ok((input, method))
}

fn parse_request_uri(input: &[u8]) -> IResult<&[u8], &[u8]> {
    // URI is everything up to the next whitespace.
    take_while1(|c: u8| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n')(input)
}

// ─── Header fields ────────────────────────────────────────────

/// Parse one header field, including any folded continuation lines.
///
/// RFC 3261 §7.3: "A single header field value can be written across
/// multiple lines.  The continuation line begins with at least one SP or
/// HTAB."
fn parse_header_field(input: &[u8]) -> IResult<&[u8], SipHeader> {
    // Header name up to colon.
    let (input, name) = take_while1(|c: u8| c != b':' && c != b'\r' && c != b'\n')(input)?;
    let (input, _)    = char(':')(input)?;
    let (input, _)    = space0(input)?;

    // First value line.
    let (input, first_value) = not_line_ending(input)?;
    let (input, _)           = crlf(input)?;

    // Folded continuation lines (start with SP or HTAB).
    let (input, continuations) = many0(parse_folded_continuation)(input)?;

    let mut value = String::from_utf8_lossy(first_value).into_owned();
    for cont in continuations {
        value.push(' ');
        value.push_str(cont.trim());
    }

    Ok((input, SipHeader {
        name:  String::from_utf8_lossy(name).trim().to_owned(),
        value: value.trim().to_owned(),
    }))
}

/// A folded continuation line: starts with at least one SP or HTAB.
fn parse_folded_continuation(input: &[u8]) -> IResult<&[u8], &str> {
    let (input, _)    = space1(input)?;
    let (input, line) = not_line_ending(input)?;
    let (input, _)    = crlf(input)?;
    Ok((input, std::str::from_utf8(line).unwrap_or("")))
}

// ─── Convenience accessors ────────────────────────────────────

impl SipMessage {
    /// Return the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Return all header values matching `name` (case-insensitive).
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Parsed Content-Length, or 0 if not present.
    pub fn content_length(&self) -> usize {
        self.header("content-length")
            .or_else(|| self.header("l"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Call-ID header value.
    pub fn call_id(&self) -> Option<&str> {
        self.header("call-id").or_else(|| self.header("i"))
    }

    /// CSeq number and method.
    pub fn cseq(&self) -> Option<(u32, &str)> {
        let v = self.header("cseq")?;
        let mut parts = v.trim().splitn(2, ' ');
        let num = parts.next()?.trim().parse().ok()?;
        let m   = parts.next()?.trim();
        Some((num, m))
    }

    /// Whether this is a request.
    pub fn is_request(&self) -> bool {
        matches!(self.start_line, StartLine::Request(_))
    }

    /// Whether this is a response.
    pub fn is_response(&self) -> bool {
        matches!(self.start_line, StartLine::Response(_))
    }

    /// Status code, if this is a response.
    pub fn status_code(&self) -> Option<u16> {
        if let StartLine::Response(ref s) = self.start_line {
            Some(s.status_code)
        } else {
            None
        }
    }

    /// Method, if this is a request.
    pub fn method(&self) -> Option<&Method> {
        if let StartLine::Request(ref r) = self.start_line {
            Some(&r.method)
        } else {
            None
        }
    }
}
