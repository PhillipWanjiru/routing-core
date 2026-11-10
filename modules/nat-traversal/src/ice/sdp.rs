//! SDP attributes for ICE (RFC 8839 §5): the text form of candidates and
//! credentials, as exchanged in an offer and an answer.
//!
//! ```text
//! a=ice-ufrag:8hhy
//! a=ice-pwd:asd88fgpdd777uzjYhagZg
//! a=candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host
//! a=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.1.1 rport 8998
//! ```
//!
//! # The input is hostile
//!
//! An SDP description comes from the other end of a call. The decoder is strict
//! about what it accepts: a malformed candidate is an error, never a guess, and
//! every field is range-checked. A candidate that is well-formed but that this
//! implementation cannot use (TCP, an unknown candidate type, a hostname) is
//! *skipped and counted*, which is what RFC 8839 requires of a receiver, so that
//! one exotic candidate does not fail a whole negotiation. Lines, candidate
//! counts and total input are all capped.
//!
//! **Hostnames are never resolved.** Browsers send mDNS names (`....local`) in
//! place of host addresses. Resolving an attacker-supplied name inside a parser
//! would make the parser a network client for the attacker (SSRF, and a leak of
//! when and where the call is handled), so a hostname candidate is skipped with
//! [`Skip::Hostname`] and a higher layer may resolve it deliberately, or not.
//!
//! # The output must not be injectable
//!
//! Every field written into SDP is validated first: a foundation, ufrag or
//! password containing a space or a line break would let whoever controls it add
//! arbitrary lines to the description. Encoding therefore returns an error rather
//! than emit them.
//!
//! # Related addresses are hidden by default
//!
//! `raddr`/`rport` say where a reflexive candidate came from, which for a
//! server-reflexive candidate is the host's own (often private) address. ICE
//! does not use them, and RFC 8839 allows `0.0.0.0`/`0` in their place, which is
//! what browsers send. This encoder does the same unless asked to expose the
//! base ([`EncodeOptions::expose_base`]).
//!
//! # Foundations
//!
//! The foundations this crate computes are readable (`Host-192.168.1.10`) and are
//! not valid SDP: `-`, `.` and `:` are not ICE characters, and an IPv6 one
//! exceeds 32. They are kept readable for logs, and written to SDP through
//! [`wire_foundation`]: the foundation itself if it is already valid, otherwise a
//! stable hash of it. A peer only ever compares foundations for equality, so the
//! hash preserves what matters.
//!
//! # Not covered
//!
//! TCP candidates, and the m-line and c-line "default candidate" of RFC 5245.

use super::candidate::{Candidate, CandidateType};
use super::agent::IceCredentials;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Longest line the decoder will look at.
pub const MAX_LINE: usize = 4096;
/// Most candidates one description may carry.
pub const MAX_CANDIDATES: usize = 256;
/// Largest description the attribute parser accepts.
pub const MAX_INPUT: usize = 256 * 1024;
/// RFC 8839: a priority is between 1 and 2^31 - 1.
const MAX_PRIORITY: u64 = (1 << 31) - 1;

/// An ICE character (RFC 8839 §5.1): letters, digits, `+` and `/`.
pub fn is_ice_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/'
}

fn ice_chars_between(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.chars().all(is_ice_char)
}

/// An RFC 3550/4566 "token": what a transport or extension name may be made of.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ─── Decoding ──────────────────────────────────────────────────────

/// A well-formed candidate this implementation cannot use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Not UDP.
    Transport(String),
    /// Not host, srflx, prflx or relay.
    CandidateType(String),
    /// An address that is a name, not an IP. Never resolved here.
    Hostname(String),
    /// Component 256, valid in SDP but not representable here.
    Component(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The line breaks the grammar. Never a guess: the caller gets an error.
    Malformed(&'static str),
    /// The line is well-formed and unusable here; skip it.
    Unsupported(Skip),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Malformed(why) => write!(f, "malformed candidate: {why}"),
            DecodeError::Unsupported(skip) => write!(f, "unsupported candidate: {skip:?}"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn malformed<T>(why: &'static str) -> Result<T, DecodeError> {
    Err(DecodeError::Malformed(why))
}

enum Addr {
    Ip(IpAddr),
    Host(String),
}

fn parse_connection_address(tok: &str) -> Result<Addr, DecodeError> {
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return Ok(Addr::Ip(ip));
    }
    if tok.contains(':') {
        return malformed("IPv6 address");
    }
    if tok.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return malformed("IPv4 address");
    }
    let name_ok = tok.len() <= 253
        && tok.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && tok.split('.').all(|l| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-'));
    if name_ok { Ok(Addr::Host(tok.to_string())) } else { malformed("address") }
}

fn parse_port(tok: &str, allow_zero: bool) -> Result<u16, DecodeError> {
    if tok.len() > 5 || !is_digits(tok) {
        return malformed("port");
    }
    match tok.parse::<u32>() {
        Ok(n) if n <= 65535 && (allow_zero || n != 0) => Ok(n as u16),
        _ => malformed("port range"),
    }
}

/// Decode one candidate attribute: `candidate:...`, with or without a leading
/// `a=` and surrounding whitespace.
pub fn decode_candidate(line: &str) -> Result<Candidate, DecodeError> {
    // Only ASCII padding is tolerated. Unicode whitespace such as U+2028 or U+0085
    // is a line break to some parsers, and treating it as padding here would be a
    // parser differential, so it falls through to the non-ASCII refusal below.
    let s = line.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if s.is_empty() {
        return malformed("empty");
    }
    if s.len() > MAX_LINE {
        return malformed("line too long");
    }
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return malformed("non-printable or non-ASCII character");
    }
    let s = s.strip_prefix("a=").unwrap_or(s);
    let Some(rest) = s.strip_prefix("candidate:") else {
        return malformed("not a candidate attribute");
    };
    let t: Vec<&str> = rest.split(' ').filter(|x| !x.is_empty()).collect();
    if t.len() < 8 {
        return malformed("too few fields");
    }

    // Everything is validated before anything is reported as unsupported, so
    // "unsupported" always means "otherwise well-formed".
    let mut unsupported: Option<Skip> = None;

    let foundation = t[0];
    if !ice_chars_between(foundation, 1, 32) {
        return malformed("foundation");
    }

    if t[1].len() > 3 || !is_digits(t[1]) {
        return malformed("component");
    }
    let component: u16 = t[1].parse().expect("at most three digits");
    if !(1..=256).contains(&component) {
        return malformed("component range");
    }
    if component > 255 {
        unsupported.get_or_insert(Skip::Component(component));
    }

    if !is_token(t[2]) {
        return malformed("transport");
    }
    if !t[2].eq_ignore_ascii_case("udp") {
        unsupported.get_or_insert(Skip::Transport(t[2].to_string()));
    }

    if t[3].len() > 10 || !is_digits(t[3]) {
        return malformed("priority");
    }
    let priority: u64 = t[3].parse().expect("at most ten digits");
    if !(1..=MAX_PRIORITY).contains(&priority) {
        return malformed("priority range");
    }

    let address = parse_connection_address(t[4])?;
    let port = parse_port(t[5], false)?;

    if t[6] != "typ" {
        return malformed("expected typ");
    }
    let candidate_type = match t[7] {
        "host" => Some(CandidateType::Host),
        "srflx" => Some(CandidateType::ServerReflexive),
        "prflx" => Some(CandidateType::PeerReflexive),
        "relay" => Some(CandidateType::Relayed),
        other if is_token(other) => {
            unsupported.get_or_insert(Skip::CandidateType(other.to_string()));
            None
        }
        _ => return malformed("candidate type"),
    };

    let extensions = &t[8..];
    if extensions.len() % 2 != 0 {
        return malformed("extension without a value");
    }
    let (mut raddr, mut rport): (Option<Addr>, Option<u16>) = (None, None);
    for pair in extensions.chunks(2) {
        let (name, value) = (pair[0], pair[1]);
        if !is_token(name) {
            return malformed("extension name");
        }
        match name {
            "raddr" => {
                if raddr.is_some() {
                    return malformed("duplicate raddr");
                }
                raddr = Some(parse_connection_address(value)?);
            }
            "rport" => {
                if rport.is_some() {
                    return malformed("duplicate rport");
                }
                rport = Some(parse_port(value, true)?);
            }
            _ => {} // generation, network-id, ufrag, network-cost, ...: not needed here
        }
    }

    let ip = match address {
        Addr::Ip(ip) => ip,
        Addr::Host(name) => {
            unsupported.get_or_insert(Skip::Hostname(name));
            IpAddr::from([0, 0, 0, 0])
        }
    };
    if let Some(skip) = unsupported {
        return Err(DecodeError::Unsupported(skip));
    }
    let candidate_type = candidate_type.expect("an unknown type was reported as unsupported above");

    let transport_addr = SocketAddr::new(ip, port);
    // A reflexive candidate's base is its related address, when one was given and
    // it is not the "hidden" 0.0.0.0:0. Nothing else about a remote candidate's
    // base is ever used, so it is otherwise the transport address itself.
    let base_addr = match (candidate_type, raddr, rport) {
        (CandidateType::ServerReflexive | CandidateType::PeerReflexive, Some(Addr::Ip(r)), Some(p))
            if !r.is_unspecified() && p != 0 =>
        {
            SocketAddr::new(r, p)
        }
        _ => transport_addr,
    };
    let priority = priority as u32;

    Ok(Candidate {
        candidate_type,
        transport_addr,
        base_addr,
        foundation: foundation.to_string(),
        local_preference: ((priority >> 8) & 0xFFFF) as u16,
        component_id: component as u8,
        priority_override: Some(priority),
    })
}

// ─── Encoding ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Write a reflexive candidate's base as its related address. Off by
    /// default: it discloses the host's own address.
    pub expose_base: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    Component(u8),
    Port,
    /// A priority outside 1..=2^31-1, such as an arbitrary one a peer advertised.
    Priority(u32),
    /// A credential that is not 4..=256 (ufrag) or 22..=256 (password) ICE characters.
    Credential(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::Component(c) => write!(f, "component id {c} cannot be written to SDP"),
            EncodeError::Port => write!(f, "a candidate with port 0 cannot be written to SDP"),
            EncodeError::Priority(p) => write!(f, "priority {p} is outside 1..=2^31-1"),
            EncodeError::Credential(which) => write!(f, "invalid {which}"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// The foundation as written to SDP: itself if it is already 1..=32 ICE
/// characters, otherwise a stable 64-bit FNV-1a hash of it in hex. A peer only
/// compares foundations for equality, which a hash preserves.
pub fn wire_foundation(foundation: &str) -> String {
    if ice_chars_between(foundation, 1, 32) {
        return foundation.to_string();
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in foundation.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn type_name(t: CandidateType) -> &'static str {
    match t {
        CandidateType::Host => "host",
        CandidateType::ServerReflexive => "srflx",
        CandidateType::PeerReflexive => "prflx",
        CandidateType::Relayed => "relay",
    }
}

/// Encode a candidate as `candidate:...`, without the `a=` and without a line
/// ending.
pub fn encode_candidate(c: &Candidate, opts: EncodeOptions) -> Result<String, EncodeError> {
    if c.component_id == 0 {
        return Err(EncodeError::Component(0));
    }
    if c.transport_addr.port() == 0 {
        return Err(EncodeError::Port);
    }
    let priority = c.priority();
    if !(1..=MAX_PRIORITY).contains(&u64::from(priority)) {
        return Err(EncodeError::Priority(priority));
    }

    let mut out = format!(
        "candidate:{} {} UDP {} {} {} typ {}",
        wire_foundation(&c.foundation),
        c.component_id,
        priority,
        c.transport_addr.ip(),
        c.transport_addr.port(),
        type_name(c.candidate_type),
    );
    let related = match c.candidate_type {
        CandidateType::Host => None,
        CandidateType::ServerReflexive | CandidateType::PeerReflexive if opts.expose_base => Some(c.base_addr),
        _ => {
            let hidden: IpAddr = if c.transport_addr.is_ipv4() { [0, 0, 0, 0].into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
            Some(SocketAddr::new(hidden, 0))
        }
    };
    if let Some(r) = related {
        out.push_str(&format!(" raddr {} rport {}", r.ip(), r.port()));
    }
    Ok(out)
}

// ─── The attributes of one description ─────────────────────────────

/// The ICE attributes of one SDP media section (or of the session level).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IceDescription {
    pub ufrag: Option<String>,
    pub pwd: Option<String>,
    /// `a=ice-lite`.
    pub lite: bool,
    /// `a=ice-options:trickle`.
    pub trickle: bool,
    /// `a=end-of-candidates`.
    pub end_of_candidates: bool,
    pub candidates: Vec<Candidate>,
    /// Candidates that were well-formed but unusable here, and so were skipped.
    pub skipped: Vec<Skip>,
}

impl IceDescription {
    /// The credentials, if both halves were present.
    pub fn credentials(&self) -> Option<IceCredentials> {
        Some(IceCredentials { ufrag: self.ufrag.clone()?, password: self.pwd.clone()? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpError {
    InputTooLarge,
    /// An ICE attribute line longer than [`MAX_LINE`] (the 1-based line number).
    LineTooLong(usize),
    TooManyCandidates,
    /// A malformed candidate, with its 1-based line number.
    Candidate { line: usize, why: &'static str },
    /// An ice-ufrag or ice-pwd outside the length or character rules.
    Credential(&'static str),
    /// A second ice-ufrag or ice-pwd.
    Duplicate(&'static str),
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::InputTooLarge => write!(f, "SDP too large"),
            SdpError::LineTooLong(n) => write!(f, "line {n} is too long"),
            SdpError::TooManyCandidates => write!(f, "too many candidates"),
            SdpError::Candidate { line, why } => write!(f, "line {line}: malformed candidate: {why}"),
            SdpError::Credential(which) => write!(f, "invalid {which}"),
            SdpError::Duplicate(which) => write!(f, "duplicate {which}"),
        }
    }
}

impl std::error::Error for SdpError {}

fn valid_ufrag(s: &str) -> bool {
    ice_chars_between(s, 4, 256)
}
fn valid_pwd(s: &str) -> bool {
    ice_chars_between(s, 22, 256)
}

/// Pull the ICE attributes out of SDP text. Lines that are not ICE attributes
/// are ignored, so a whole media section can be passed in. `\n` and `\r\n` both work.
pub fn parse_ice_attributes(sdp: &str) -> Result<IceDescription, SdpError> {
    if sdp.len() > MAX_INPUT {
        return Err(SdpError::InputTooLarge);
    }
    let mut d = IceDescription::default();
    for (i, raw) in sdp.split('\n').enumerate() {
        let n = i + 1;
        let line = raw.trim_end_matches('\r');
        let Some(attr) = line.strip_prefix("a=") else {
            continue;
        };
        let (name, value) = attr.split_once(':').map_or((attr, ""), |(a, b)| (a, b));
        let ours = matches!(name, "ice-ufrag" | "ice-pwd" | "ice-options" | "ice-lite" | "end-of-candidates" | "candidate");
        if !ours {
            continue;
        }
        if line.len() > MAX_LINE {
            return Err(SdpError::LineTooLong(n));
        }
        match name {
            "ice-ufrag" => {
                if d.ufrag.is_some() {
                    return Err(SdpError::Duplicate("ice-ufrag"));
                }
                if !valid_ufrag(value) {
                    return Err(SdpError::Credential("ice-ufrag"));
                }
                d.ufrag = Some(value.to_string());
            }
            "ice-pwd" => {
                if d.pwd.is_some() {
                    return Err(SdpError::Duplicate("ice-pwd"));
                }
                if !valid_pwd(value) {
                    return Err(SdpError::Credential("ice-pwd"));
                }
                d.pwd = Some(value.to_string());
            }
            "ice-options" => d.trickle |= value.split(' ').any(|o| o == "trickle"),
            "ice-lite" => d.lite = true,
            "end-of-candidates" => d.end_of_candidates = true,
            _ => match decode_candidate(line) {
                Ok(c) => {
                    if d.candidates.len() >= MAX_CANDIDATES {
                        return Err(SdpError::TooManyCandidates);
                    }
                    d.candidates.push(c);
                }
                Err(DecodeError::Unsupported(skip)) => d.skipped.push(skip),
                Err(DecodeError::Malformed(why)) => return Err(SdpError::Candidate { line: n, why }),
            },
        }
    }
    Ok(d)
}

/// Write the ICE attributes, one `a=` line each, ending in CRLF.
pub fn format_ice_attributes(d: &IceDescription, opts: EncodeOptions) -> Result<String, EncodeError> {
    let mut out = String::new();
    if let Some(u) = &d.ufrag {
        if !valid_ufrag(u) {
            return Err(EncodeError::Credential("ice-ufrag"));
        }
        out.push_str(&format!("a=ice-ufrag:{u}\r\n"));
    }
    if let Some(p) = &d.pwd {
        if !valid_pwd(p) {
            return Err(EncodeError::Credential("ice-pwd"));
        }
        out.push_str(&format!("a=ice-pwd:{p}\r\n"));
    }
    if d.lite {
        out.push_str("a=ice-lite\r\n");
    }
    if d.trickle {
        out.push_str("a=ice-options:trickle\r\n");
    }
    for c in &d.candidates {
        out.push_str(&format!("a={}\r\n", encode_candidate(c, opts)?));
    }
    if d.end_of_candidates {
        out.push_str("a=end-of-candidates\r\n");
    }
    Ok(out)
}
